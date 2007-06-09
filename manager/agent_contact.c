#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "agent_contact.h"
#include "utils.h"
#include "hash.h"
#include "errors.h"
#include "job.h"
#include "alert.h"


extern  SensorList sensorlist;

static int udp_socket; /* The UDP Socket */
static int tcp_socket; /* The TCP Socket listening for incoming connections */

/*
 * Function: get_new_client_pos(u_int8_t *, size_t)
 *
 * Purpose: Find the first unused entry in the Agents table 
 *
 * Arguments:  map=> pointer to the map array
 *             map_size=> Size of the map array in 8 bit (1 byte) units;
 *
 * Returns: the index of the first unused size on success
 *          map_size * 8  on error
 */
static unsigned short get_new_client_pos(u_int8_t *map, size_t map_size)
{
	int i;
	unsigned short offset;

	DPRINTF("\n");
	for (i = 0; i < map_size; i++) {
		offset = find_first_zero(map[i]);
		if (offset < 8)
			return i*8 + offset;
	}
	return map_size*8;
}

/*
 * Function: cleanup_map(Agents *)
 *
 * Purpose: Removes the agents that haven't communicated for a long time  
 *
 * Arguments:  agents=> The agents struct 
 *
 * Returns: 1=> Some agents have been removed
 *          0=> No agent has beed removed
 */
static int cleanup_map(Agents *agents)
{
	int i;
	int cleared = 0;
	time_t current_time;
	AgentInfo *this_agent;

	/* Press PageDown, you'll find the body of this function ;-) */ 
	static void remove_agent(Agents *, unsigned int);

	current_time = time(NULL);

	for(i = 0; i < agents->max; i++) {
		this_agent = agents->table + i;
		if(this_agent->id) /* agent exists */
			if(current_time - this_agent->timestamp > MAX_WAIT) {
				cleared = 1;
				remove_agent(agents, this_agent->id);
			}
	}

	return cleared;
}

/* just check the password and return TRUE if it matches */
static inline int check_password(char *pwd)
{
	return (strncmp(pwd, pv.password, MAX_PWD_SIZE))?0:1;
}


/*
 * Function: add_agent(Agents *, struct sockaddr_in *)
 *
 * Purpose:  Adds a new agent in the Agent table
 *
 * Arguments:  agents=> struct with info about all the agents
 *             addr=> The IP address of the agent we want to add;
 *
 * Returns: Pointer to the newly added agent on success, NULL on error
 */
static AgentInfo *add_agent(Agents *agents, struct sockaddr_in *addr)
{
	AgentInfo *this_agent;
	unsigned short index;
	u_int8_t mask=0;
	unsigned int id;
	int i;

	DPRINTF("\n");
	index = get_new_client_pos(agents->map, agents->map_size);
	if (index >= agents->max) {
		/* 
		 * the client map is full, let's try to
		 * remove obsolete agents
		 */
		if(cleanup_map(agents))
			index = get_new_client_pos(agents->map,
							agents->map_size);
		else return NULL;
	}

	/* Create a unique ID */
	do {
		id = (u_int32_t)get_rand();
		if(id == 0)
			continue;
	} while(hash_agent_lookup(agents->hash, id));

	/* I have an index and an id, let's add them in the hash table */ 
	if(hash_agent_insert(agents->hash, id, index) == 0) {
		fprintf(stderr,"Error in hash_agent_insert\n");
		return NULL;
	}

	/* We have an index in the agents table,
	 * now set it to 1 in the map array */
	mask = 1 << (index % 8);
	i = index / 8; 
	agents->map[i] = agents->map[i] | mask;

	DPRINTF("New agent ID: %u, Index: %u\n",id, index);

	this_agent = agents->table + index;
	this_agent->id = id;
	this_agent->addr = *addr;
	this_agent->seq = 1;
	this_agent->timestamp = time(NULL);

	return this_agent;
}

/*
 * Function: remove_agent(Agents *, unsigned int *)
 *
 * Purpose:  Remove an agent from the Agent table
 *
 * Arguments:  agents=> struct with info about all the agents
 *             id => Agent's ID;
 */
static void remove_agent(Agents *agents, unsigned int id)
{
	AgentInfo *this_agent;
	u_int8_t mask;
	int i;
	int ret;
	unsigned short *index;

	DPRINTF("\n");
	index = hash_agent_lookup(agents->hash, id);

	if (index == NULL) {
		fprintf(stderr, "Can't find id in hash\n");
		return;
	}

	DPRINTF("Remove agent ID:%u Index:%u\n",id,*index);

	this_agent = agents->table + *index;

	/* if we have data in the history left, destroy the group */
	if(this_agent->history.data.tcp) {

		mutex_lock(&this_agent->history.sensor->mutex);
		ret = destroy_datagroup(&this_agent->history);
		mutex_unlock(&this_agent->history.sensor->mutex);

		if(ret == 2) {
			mutex_lock(&sensorlist.mutex);
			destroy_sensor(this_agent->history.sensor);
			mutex_unlock(&sensorlist.mutex);
		}

	}

	memset(this_agent, '\0', sizeof(AgentInfo));

	/* Update the bit map */
	mask = ~(1 << (*index % 8));
	i = *index / 8;
	agents->map[i] = agents->map[i] & mask;
}

/*
 * Function: send_msg(AgentInfo *, int *)
 *
 * Purpose: send a UDP message to an agent
 *
 * Arguments:  agent=> struct with info about an agent
 *             type=> The type of the message we want to send;
 *
 * Returns: 1=> exit on success, 0=> exit on failure
 */
static int send_msg(AgentInfo *agent, int type)
{
	char buf[UDP_PCK_SIZE];
	size_t length;
	socklen_t addr_len;
	int numbytes;

	DPRINTF("\n");
	length = UDP_PCK_SIZE;
	addr_len =  sizeof(struct sockaddr);

	*(u_int32_t *)(buf +  0) = htonl(length);
	*(u_int32_t *)(buf +  4) = htonl(agent->seq);
	*(u_int32_t *)(buf +  8) = htonl(type);
	*(u_int32_t *)(buf + 12) = htonl(agent->id);

	numbytes = sendto(udp_socket, buf, length, 0,
			(struct sockaddr *) &agent->addr, addr_len);

	DPRINTF("Send: %u,%u,%u,%u\n",length,agent->seq,ntohl(type),agent->id);
	if (numbytes == -1)
		errno_cont("sendto");
	else if (numbytes != length)
		fprintf(stderr, "Couldn't send the data\n");
	else 
		return 1;

	return 0;
}


/*
 * Function: send_work(AgentInfo *, DataInfo *)
 *
 * Purpose: Send work to process to an agent
 *
 * Arguments:  agent=> struct with info about an agent
 *             work=> struct with info about the work we want to send
 *
 * Returns: 1=> exit on success, 0=> exit on failure
 */
static int send_work(AgentInfo *agent, DataInfo *work)
{
	char *buf;
	socklen_t addr_len = sizeof(struct sockaddr);
	size_t length = 2*UDP_PCK_SIZE; /* main_msg + addr */
	char * payload;
	size_t payload_length;
	unsigned int type;

	DPRINTF("\n");
	if (work->session->proto == IPPROTO_TCP) {
		payload =        work->data.tcp->payload;
		payload_length = work->data.tcp->length;
	} else {
		payload =        work->data.udp->payload;
		payload_length = work->data.udp->length;
	}
	type = UDP_DATA;

	length += payload_length;
	buf = malloc(length);
	if(buf == NULL) {
		errno_cont("malloc");
		return 0;
	}

	*(u_int32_t *)(buf +  0) = htonl(length);
	*(u_int32_t *)(buf +  4) = htonl(agent->seq);
	*(u_int32_t *)(buf +  8) = htonl(type);
	*(u_int32_t *)(buf + 12) = htonl(agent->id);
	*(u_int32_t *)(buf + 16) = htonl(work->session->proto);
	*(u_int16_t *)(buf + 20) = work->session->addr.s_port;
	*(u_int16_t *)(buf + 22) = work->session->addr.d_port;
	*(u_int32_t *)(buf + 24) = work->session->addr.s_addr;
	*(u_int32_t *)(buf + 28) = work->session->addr.d_addr;
	memcpy(buf + 2*UDP_PCK_SIZE, payload, payload_length);
	addr_len =  sizeof(struct sockaddr);
	if(sendto(udp_socket, buf, length, 0,
			(struct sockaddr *) &agent->addr, addr_len) == -1) {
		errno_cont("sendto");
		free(buf);
		return 0;
	}

	DPRINTF("Send: %u,%u,%u,%u\n",length,agent->seq,ntohl(type),agent->id);

	/* update history */
	agent->history = *work;

	free(buf);
	return 1;
}


/*
 * Function: send_new_work(AgentInfo *)
 *
 * Purpose: send new work to an agent, by removing it from the joblist
 *
 * Arguments:  agent=> struct with info about an agent
 *
 * Returns: 1=> exit on success, 0=> exit on failure		
 */
static int send_new_work(AgentInfo *agent)
{
	int ret;

	DPRINTF("\n");
	if(agent->history.data.tcp) { /* doesn't matter, could be udp too */

		/* 
		 * Destroy the old data group,
		 * we are about to start with a new one...
		 */
		mutex_lock(&agent->history.sensor->mutex);

		ret = destroy_datagroup(&agent->history);

		mutex_unlock(&agent->history.sensor->mutex);


		/* If safe, destroy the sensor too */
		if(ret == 2) {

			mutex_lock(&sensorlist.mutex);

			destroy_sensor(agent->history.sensor);

			mutex_unlock(&sensorlist.mutex);
		}
	}

	ret = execute_job(send_work, agent);
	if (ret != -1)  /* a job was executed */
		return ret;

	/* Clear the history */
	agent->history.data.tcp = NULL;
	ret = send_msg(agent, UDP_NOT_FOUND);
	return ret;
}


/*
 * Function: send_next_work(AgentInfo *)
 *
 * Purpose: Send next data from a continuous group of data to an agent
 *          by checking the last sent data
 *
 * Arguments:  agent=> struct with info about an agent
 *
 * Returns: 1=> exit on success, 0=> exit on failure
 */
static int send_next_work(AgentInfo *agent)
{
	int ret = -1;
	DataInfo work;

	DPRINTF("\n");
	if(agent->history.data.tcp) { /* doesn't matter, could be udp too */

		work = agent->history;

		mutex_lock(&work.sensor->mutex);

		if(work.session->proto == IPPROTO_TCP)
			work.data.tcp = get_next_data(work.data.tcp);
		else 	
			work.data.udp = NULL;

		/* 
		 * Now we know what we want to send,
		 * so it's safe to destroy the old data
		 */
		destroy_data(&agent->history);

		if(work.data.tcp)
			ret = send_work(agent, &work);

		mutex_unlock(&work.sensor->mutex);
	}

	if (ret == -1) { /* nothing sent */
		agent->history.data.tcp = NULL;
		ret = send_msg(agent, UDP_NOT_FOUND);
	}

	return ret;
}

/*
 * Function: send_current_work(AgentInfo *)
 *
 * Purpose: Send to an agent the last sent data again
 *
 * Arguments: agent=> struct with info about an agent
 *
 * Returns: 1=> exit on success, 0=> exit on failure
 */
static int send_current_work(AgentInfo *agent)
{
	int ret = 0;
	
	DPRINTF("\n");
	if(agent->history.data.tcp) { /* tcp doesn't matter, could be udp too */

		mutex_lock(&agent->history.sensor->mutex); /* Do I need this? */
		
		ret = send_work(agent, &agent->history);

		mutex_unlock(&agent->history.sensor->mutex);

	} else
		ret = send_msg(agent, UDP_NOT_FOUND);

	return ret;
}


/*
 * Function: recv_udp_packet(UDPPacket *)
 *
 * Purpose: Receive a UDP Packet sent by an agent
 *
 * Arguments: pck=> Pointer to the struct we fill with the packet data
 *
 * Returns: 1=> exit on success, 0=> exit on failure
 */
static int recv_udp_packet(UDPPacket *pck)
{
	char buf[2*UDP_PCK_SIZE +1];
	ssize_t numbytes;
	socklen_t addr_len;

	DPRINTF("\n");
	addr_len = sizeof(struct sockaddr);
	numbytes = recvfrom(udp_socket, buf, 2*UDP_PCK_SIZE+1, MSG_DONTWAIT,
		      (struct sockaddr *) &pck->addr, &addr_len);
	if (numbytes == -1) {
		if(errno == EAGAIN)
			return 0; /* no data available */
		errno_abort("recvfrom");
	}


	DPRINTF("I got %d bytes\n", numbytes);
	if((numbytes != UDP_PCK_SIZE) && (numbytes != 2*UDP_PCK_SIZE))
		return -1;

	pck->size = ntohl(*(u_int32_t *) (buf +  0));
	if(pck->size != numbytes)
		return -1;
	pck->seq  = ntohl(*(u_int32_t *) (buf +  4));
	pck->type = ntohl(*(u_int32_t *) (buf +  8));
	pck->id   = ntohl(*(u_int32_t *) (buf + 12));

	if(numbytes == 2*UDP_PCK_SIZE)
		strncpy(pck->pwd,buf + UDP_PCK_SIZE, UDP_PCK_SIZE - 1);

	DPRINTF("Received: %u,%u,%u,%u\n",pck->size, pck->seq,
				ntohl(pck->type), pck->id);

	return 1;
}

/*
 * Function: process_udp_packet(Agents *, UDPPacket *)
 *
 * Purpose: Analyze and process a received UDP Packet
 *
 * Arguments: agents=> Struct with info about the agent table 
 *            pck=> Pointer to the UDP packet struct
 */
static void process_udp_packet(Agents *agents, UDPPacket *pck)
{
	AgentInfo *this_agent;
	unsigned short *index;

	DPRINTF("\n");
	if (pck->type == UDP_NEW_AGENT) {
		if(!check_password(pck->pwd)) { /* Check the Password */
			DPRINTF("Wrong Password\n");
			return;
		}
		this_agent = add_agent(agents, &pck->addr);
		if(this_agent)
			send_msg(this_agent, UDP_CONNECTED);
		return;
	}

	index = hash_agent_lookup(agents->hash, pck->id);
	if(!index)
		return;
	this_agent = agents->table + *index;

	/* check if the address is the same as the one stored*/
	if(memcmp(&this_agent->addr,&pck->addr, sizeof(struct sockaddr)) != 0)
		return;

	if(pck->seq == this_agent->seq) { 
		/* Send the last data sent again, if still there... */
		switch(pck->type) {
			case UDP_NEW_WORK:
			case UDP_GET_NEXT:
				send_current_work(this_agent);
		}
	}
	else if(pck->seq == (this_agent->seq + 1)) { /* new_request */

		switch(pck->type) {
			case UDP_NEW_WORK:
				this_agent->seq = pck->seq;
				send_new_work(this_agent);
				break;
			case UDP_GET_NEXT:
				this_agent->seq = pck->seq;
				send_next_work(this_agent);
				break;
			case UDP_QUIT:
				if(check_password(pck->pwd)) {
					this_agent->seq = pck->seq;
					remove_agent(agents,pck->id);
				}
					/* we don't use break. this agent */
				return; /* does not exist any more */
					 
			default:
				DPRINTF("Unknown Packet type\n");
				return;
		}
		/* Update timestamp */
		this_agent->timestamp = time(NULL);
	}
	return;
}

/*
 * Serves a UDP requests
 */
static void udp_request(Agents *agents)
{
	UDPPacket pck;
	int ret;

	DPRINTF("\n");
	ret = recv_udp_packet(&pck);
	if(ret == 1)
		process_udp_packet(agents, &pck);

	return;
}


/*
 * Function: recv_alert_data(int, unsigned int *)
 *
 * Purpose: Receive the alert data from a TCP Connection
 *
 * Arguments: socket=> The TCP connection Socket
 *            data_size=> A parameter we fill with the size of the alert data
 *
 * Returns: Pointer to a buffer filled with the collected alert data
 */
static char *recv_alert_data(int socket, unsigned int *data_size)
{
	u_int32_t size;
	char *alert_data;
	ssize_t numbytes;
	int flags = 0;

	DPRINTF("\n");
	flags = MSG_PEEK | MSG_WAITALL;
	numbytes = recv(socket, &size, sizeof(u_int32_t), flags);
	if (numbytes == -1) {
		errno_cont("recv");
		return NULL;
	}
	if (numbytes != sizeof(u_int32_t)) {
		DPRINTF("Error in receiving the size\n");
		return NULL;
	}

	size = ntohl(size);
	DPRINTF("size is %u\n",size);

	/* we allow zero payload */
	if (size < UDP_PCK_SIZE + sizeof(u_int32_t)) { 
		DPRINTF("The alert message size is not sane\n");
		return NULL;
	}
	/* TODO: Check about the MAX UDP packet size */

	alert_data = malloc(size);
	if (alert_data == NULL) {
		errno_cont("malloc");
		return NULL;
	}

	flags = MSG_WAITALL;
	numbytes = recv(socket, alert_data, size, flags);
	if (numbytes == -1)
		errno_cont("recv");
	else if(numbytes != size)
		DPRINTF("Error in receiving the alert_data\n");
	else { 
		*data_size = size;
		return alert_data;
	}

	/* On error */
	free(alert_data);
	return NULL;
}

/*
 * Function: process_alert_data(char *, int)
 *
 * Purpose: Process the alert data from a buffer, and push the alert to the
 *          alert list
 *
 * Arguments: data=> buffer that contains the alert data
 *            data_len=> size of the alert data buffer
 */
static void process_alert_data(char *data, int data_len)
{
	struct tuple4 connection;
	int proto;
	char *payload;
	int payload_len;
	unsigned int size;

	DPRINTF("\n");
	size = ntohl(*(u_int32_t *)data);

	payload_len = size - TCP_PCK_SIZE;

	DPRINTF("size is %u, payload is %u\n",size, payload_len);
	proto = ntohl(*(u_int32_t *)(data + 4));
	connection.s_port = ntohs(*(u_int16_t *)(data + 8));
	connection.d_port = ntohs(*(u_int16_t *)(data + 10));
	connection.s_addr = ntohl(*(u_int32_t *)(data + 12));
	connection.d_addr = ntohl(*(u_int32_t *)(data + 16));
	payload = (payload_len)? (data + 20) : NULL;

	/* send the alert */
	DPRINTF("push alert\n");
	push_alert(&connection, proto, payload, payload_len);

	return;
}

typedef struct {
	int socket;
	unsigned long addr;
	unsigned short port;
} TCPConData;

/*
 * Function: tcp_connection(TCPConData *)
 *
 * Purpose: Main thread function that handles a TCP connection to receive
 *          an alert
 *
 * Arguments: data=> Pointer to a TCP Connection info struct
 */
static void *tcp_connection(TCPConData *data)
{
	struct timeval wait;
	int ret;
	fd_set readset;
	char pwd[MAX_PWD_SIZE + 1];
	char *buf = NULL;
	int buf_len;
	ssize_t numbytes;
	size_t bytesleft = MAX_PWD_SIZE;

	DPRINTF("\n");
	FD_ZERO(&readset);
	FD_SET(data->socket, &readset);

select_again:
	wait.tv_sec = 5;
	wait.tv_usec = 0;
	ret = select(data->socket + 1, &readset, NULL, NULL, &wait);
	if (ret == -1) {
		if (errno == EBADF) {
			goto select_again;
		}
		else goto end;
	}
	else if (ret == 0) {
		DPRINTF("Select timed out\n");
		goto end;
	}

	numbytes = recv(data->socket, pwd + MAX_PWD_SIZE - bytesleft, bytesleft, 0);
	if (numbytes == -1) {
		errno_cont("recv");
		goto end;
	} else if (numbytes != bytesleft) {
		bytesleft -= numbytes;
		goto select_again;
	}

	pwd[MAX_PWD_SIZE] = '\0';
	if(!check_password(pwd)) {
		DPRINTF("Wrong Password\n");
		goto end;
	}
	/* password is OK, now receive the alert */
	buf = recv_alert_data(data->socket, &buf_len);
	if (buf) {
		DPRINTF("buf_len %u\n",buf_len);
		process_alert_data(buf,buf_len);
		free(buf);
	}

end:
	close (data->socket);
	free(data);
	return NULL;
}



/*
 * Initialize an Agents struct
 */
static void init_agents(Agents *agents)
{
	agents->max = pv.max_agents;
	agents->table = calloc(agents->max, sizeof(AgentInfo));
	if (agents->table == NULL)
		errno_abort("calloc");
	agents->map_size = (size_t) ((agents->max + 7) & ~7) / 8;
	agents->map = calloc(agents->map_size, 1); /* Clear the memory */
	if (agents->map == NULL)
		errno_abort("calloc");
	agents->hash = new_hash_table();
}


/*
 * Function: agents_contact(AgentsContactData *)
 *
 * Purpose: Main agents_thread thread function. This function creates a UDP
 *          and a TCP server to communicate with the agents
 *
 * Arguments: data=> Connection parameters
 */
void *agents_contact(void)
{
	int newfd,maxfd;
	fd_set readset, allset;
	int nready;
	struct sockaddr_in my_addr, his_addr;;
	socklen_t addrlen;
	Agents agents;
	TCPConData *t_data;

	init_agents(&agents);

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(pv.agent_port);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	memset(&(my_addr.sin_zero), '\0', 8);

	udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_socket == -1)
		errno_abort("socket");

	if(bind(udp_socket, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
		errno_abort("bind");

	tcp_socket = socket(PF_INET, SOCK_STREAM, 0);
	if (tcp_socket == -1)
		errno_abort("socket");

	if(bind(tcp_socket, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
		errno_abort("bind");

	if(listen(tcp_socket, 10) == -1)
		errno_abort("listen");

	maxfd = MAX(udp_socket, tcp_socket);

	FD_ZERO(&allset);
	FD_SET(udp_socket, &allset);
	FD_SET(tcp_socket, &allset);

	for(;;) {
		readset = allset;
select_restart:
		nready = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if (nready == -1) {
			if (errno == EINTR)
				goto select_restart;
			else errno_abort("select");
		}
		if (FD_ISSET(udp_socket, &readset)) {
			udp_request(&agents);

			if(--nready <= 0)
				continue;
		}

		if (FD_ISSET(tcp_socket, &readset)) {
			addrlen = sizeof(his_addr);
			newfd = accept(tcp_socket, (struct sockaddr *)&his_addr,
								&addrlen);
			if(newfd == -1)
				errno_cont("accept");
			else {
				t_data = malloc(sizeof(TCPConData));
				if(t_data == NULL) {
					errno_cont("malloc");
					close(newfd);
				} else {
					t_data->socket = newfd;
					t_data->addr = his_addr.sin_addr.s_addr;
					t_data->port = his_addr.sin_port;

					/* 
					 * Create a new thread to handle the
					 * TCP connection.
					 */
					create_thread((void *)tcp_connection,
								t_data);
				}
			}
			if(--nready <= 0)
				continue;
		}
	}
}
