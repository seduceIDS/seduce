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
#include "errors.h"
#include "hash.h"
#include "job.h"
#include "alert.h"


extern  SensorList sensorlist;

static int udp_socket; /* The UDP Socket */
static int tcp_socket; /* The TCP Socket listening for incoming connections */


/*
 * This function finds the first unused entry in the Agents table
 */
static unsigned short get_new_client_pos(u_int8_t *map, size_t map_size)
{
	int i;
	unsigned short tmp;

	DPRINTF("\n");
	for (i = 0; i < map_size; i++) {
		tmp = find_first_zero(map[i]);
		if (tmp < 8)
			return i*8 + tmp;
	}
	return map_size*8;
}

int cleanup_map(Agents *agents)
{
	int i;
	int cleared = 0;
	time_t current_time;
	AgentInfo *this_agent;

	current_time = time(NULL);
	for(i = 0; i < agents->max; i++) {
		this_agent = agents->table + i;
		if(this_agent->id) /* agent exists */
			if(current_time - this_agent->timestamp > MAX_WAIT) {
				cleared = 1;
				/*remove agent*/
			}
	}
	return 0;
}

inline int check_password(char *pwd)
{
	return (strncmp(pwd, PASSWORD, UDP_PCK_SIZE -1))?0:1;
}


/*
 * Adds a new agent in the Agent table
 * Returns the AgentInfo pointer on success, NULL on failure
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
		/* the client map is full,
		 * let's try to remove absolute agents */
		if(cleanup_map(agents))
			index = get_new_client_pos(agents->map,
							agents->map_size);
		else return NULL;
	}

	/* Create an ID */
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
	this_agent->tcp_socket = -1;
	this_agent->sec = 1;
	this_agent->timestamp = time(NULL);

	return this_agent;
}

/*
 * Removes an agent from the Agent table
 */
static void remove_agent(Agents *agents, unsigned int id)
{
	AgentInfo *this_agent;
	u_int8_t mask;
	int i;
	unsigned short *index;

	DPRINTF("\n");
	index = hash_agent_lookup(agents->hash, id);

	if (index == NULL) {
		fprintf(stderr, "Can't find id in hash\n");
		return;
	}

	DPRINTF("Remove agent ID:%u Index:%u\n",id,*index);

	this_agent = agents->table + *index;
	memset(this_agent, '\0', sizeof(AgentInfo));

	/* Update the bit map */
	mask = ~(1 << (*index % 8));
	i = *index / 8;
	agents->map[i] = agents->map[i] & mask;
}


/*
 * Sends a UDP message of type "type" to an agent.
 * Returns 1 on success, 0 on failure
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
	*(u_int32_t *)(buf +  4) = htonl(agent->sec);
	*(u_int32_t *)(buf +  8) = htonl(type);
	*(u_int32_t *)(buf + 12) = htonl(agent->id);

	numbytes = sendto(udp_socket, buf, length, 0,
			(struct sockaddr *) &agent->addr, addr_len);

	DPRINTF("Send: %u,%u,%u,%u\n",length,agent->sec,ntohl(type),agent->id);
	if (numbytes == -1)
		errno_cont("sendto");
	else if (numbytes != length)
		fprintf(stderr, "Couldn't send the data\n");
	else 
		return 1;

	return 0;
}

/*
 * Receives a UDP packet and fills the pck struct
 * Returns 1 on success, 0 if no packets are available
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
	pck->sec  = ntohl(*(u_int32_t *) (buf +  4));
	pck->type = ntohl(*(u_int32_t *) (buf +  8));
	pck->id   = ntohl(*(u_int32_t *) (buf + 12));

	if(numbytes == 2*UDP_PCK_SIZE)
		strncpy(pck->pwd,buf + UDP_PCK_SIZE, UDP_PCK_SIZE - 1);

	DPRINTF("Received: %u,%u,%u,%u\n",pck->size, pck->sec,
				ntohl(pck->type), pck->id);

	return 1;
}


/*
 * Send work to an agent.
 */
int send_work(AgentInfo *agent, DataInfo *work)
{
	char *buf;
	socklen_t addr_len = sizeof(struct sockaddr);
	size_t length = 2*UDP_PCK_SIZE; /* main_msg + addr */
	char * payload;
	size_t payload_length;
	unsigned int type;

	DPRINTF("\n");
	if (work->session->proto == TCP) {
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
	*(u_int32_t *)(buf +  4) = htonl(agent->sec);
	*(u_int32_t *)(buf +  8) = htonl(type);
	*(u_int32_t *)(buf + 12) = htonl(agent->id);
	*(u_int32_t *)(buf + 16) = htonl(work->session->proto);
	*(u_int16_t *)(buf + 20) = work->session->addr.s_port;
	*(u_int16_t *)(buf + 22) = work->session->addr.d_port;
	*(u_int32_t *)(buf + 24) = work->session->addr.s_addr;
	*(u_int32_t *)(buf + 32) = work->session->addr.d_addr;
	memcpy(buf + 2*UDP_PCK_SIZE, payload, payload_length);
	addr_len =  sizeof(struct sockaddr);
	if(sendto(udp_socket, buf, length, 0,
			(struct sockaddr *) &agent->addr, addr_len) == -1) {
		errno_cont("sendto");
		free(buf);
		return 0;
	}

	DPRINTF("Send: %u,%u,%u,%u\n",length,agent->sec,ntohl(type),agent->id);

	/* update the "sent data history" */
	if (work->session->proto == TCP) {
		agent->history.sensor = work->sensor->id;
		agent->history.session = work->session->id;
		agent->history.data = work->data.tcp->id;
	} else {
		agent->history.sensor = 0;
		agent->history.session = 0;
		agent->history.data = 0;
	}

	free(buf);
	return 1;
}

/*
 * Reads the agents history of the data send and sends previous,
 * same or next data according to the data_id_offset
 */
static int send_offset_work(AgentInfo *agent, int data_id_offset)
{
	unsigned int sensor_id;
	unsigned int session_id;
	unsigned int data_id;
	Sensor  *sensor;
	Session *session;
	TCPData *data;
	DataInfo work;
	int status;

	DPRINTF("\n");
	sensor_id = agent->history.sensor;
	session_id = agent->history.session;
	data_id = agent->history.data;

	if (!sensor_id || !session_id || !data_id)
	       return 0;

	data_id += data_id_offset;
	if (data_id <= 0)
		return 0;
	
	/* find the work */
	status = pthread_mutex_lock(&sensorlist.mutex);
	if (status != 0)
		err_abort(status, "Lock mutex");

	sensor = hash_sensor_lookup(sensorlist.hash, sensor_id);
	if (!sensor) {
		status = pthread_mutex_unlock(&sensorlist.mutex);
		if (status != 0)
			err_abort(status, "Unlock mutex");
		return 0;
	}

	status = pthread_mutex_lock(&sensor->mutex);
	if (status != 0)
		err_abort(status, "Lock mutex");

	status = pthread_mutex_unlock(&sensorlist.mutex);
	if (status != 0)
		err_abort(status, "Unlock mutex");

	session = hash_session_lookup(sensor->hash, session_id);
	if (!session) {
		status = pthread_mutex_unlock(&sensor->mutex);
		if (status != 0)
			err_abort(status, "Unlock mutex");
		return 0;
	}

	if ((data = find_data(session, data_id))) {
		work.sensor = sensor;
		work.session = session;
		work.data.tcp = data;
		send_work(agent, &work);
	}

	status = pthread_mutex_unlock(&sensor->mutex);
	if (status != 0)
		err_abort(status, "Unlock mutex");

	return (data)?1:0;
}


/*
 * Send new work to an agent
 */
static inline int send_new_work(AgentInfo *agent)
{
	int ret;

	DPRINTF("\n");
	ret = execute_job(send_work, agent);
	if (ret) 
		return 1;

	send_msg(agent, UDP_NOT_FOUND);
	return 0;
}

/*
 * Send the previous data to the agent
 */
static inline int send_prev_work(AgentInfo *agent)
{
	int ret;

	DPRINTF("\n");
	ret = send_offset_work(agent, -1);
	if (ret)
		return 1;

	send_msg(agent, UDP_NOT_FOUND);
	return 0;
}

/*
 * Send the next data
 */
static inline int send_next_work(AgentInfo *agent)
{
	int ret;

	DPRINTF("\n");
	ret = send_offset_work(agent, +1);
	if (ret)
		return 1;

	send_msg(agent, UDP_NOT_FOUND);
	return 0;
}

/*
 * Send current data
 */
static inline int send_current_work(AgentInfo *agent)
{
	int ret;

	DPRINTF("\n");
	ret = send_offset_work(agent, 0);
	if (ret)
		return 1;

	send_msg(agent, UDP_NOT_FOUND);
	return 0;
}


static void process_udp_packet(Agents *agents, UDPPacket *pck)
{
	AgentInfo *this_agent;
	unsigned short *index;

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

	if(pck->sec == this_agent->sec) { 
		/* Send the last data sent again, if still there... */
		switch(pck->type) {
			case UDP_NEW_WORK:
			case UDP_GET_NEXT:
			case UDP_GET_PREV:		
				send_current_work(this_agent);
		}
	}
	else if(pck->sec > this_agent->sec) { /* new_request */

		/* Update sequence */
		this_agent->sec = pck->sec;
		switch(pck->type) {
			case UDP_NEW_WORK:
				send_new_work(this_agent);
				break;
			case UDP_GET_NEXT:
				send_next_work(this_agent);
				break;
			case UDP_GET_PREV:
				send_prev_work(this_agent);
				break;
			case UDP_QUIT:
				if(check_password(pck->pwd))
					remove_agent(agents,pck->id);
				else return;
				break;
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

	ret = recv_udp_packet(&pck);
	if(ret == 1)
		process_udp_packet(agents, &pck);

	return;
}

/* 
 * Receives the alert data from a TCP connection.
 * Returns the data size received on success, 0 if an error occurs
 */ 
static int recv_alert_data(int socket, char *alert_data)
{
	u_int32_t size;
	ssize_t numbytes;
	int flags = 0;

	flags = MSG_PEEK | MSG_WAITALL;
	numbytes = recv(socket, &size, sizeof(u_int32_t), flags);
	if (numbytes == -1) {
		errno_cont("recv");
		return 0;
	}
	if (numbytes != sizeof(u_int32_t)) {
		DPRINTF("Error in receiving the size\n");
		return 0;
	}

	/* we allow zero payload */
	if (size < UDP_PCK_SIZE + sizeof(u_int32_t)) { 
		DPRINTF("The alert message size is not sane\n");
		return 0;
	}
	/* TODO: Check about the MAX UDP packet size */

	alert_data = malloc(size);
	if (alert_data == NULL) {
		errno_cont("malloc");
		return 0;
	}

	flags = MSG_WAITALL;
	numbytes = recv(socket, alert_data, size, flags);
	if (numbytes == -1)
		errno_cont("recv");
	else if(numbytes != size)
		DPRINTF("Error in receiving the alert_data\n");
	else
		return (int)size;

	/* On error */
	free(alert_data);
	return 0;
}


static void process_alert_data(char *data, int data_len)
{
	struct tuple4 connection;
	IPProtocol proto;
	char *payload;
	int payload_len;

	unsigned int size = *(u_int32_t *)data;

	/* payload_len = SIZE - CONNECTION_SIZE - SIZE_FIELD_SIZE */
	payload_len = size - UDP_PCK_SIZE -sizeof(u_int32_t);

	proto = ntohl(*(u_int32_t *)(data + 4));
	connection.s_port = *(u_int16_t *)(data + 8);
	connection.d_port = *(u_int16_t *)(data + 10);
	connection.s_addr = *(u_int32_t *)(data + 12);
	connection.d_addr = *(u_int32_t *)(data + 16);
	payload = (payload_len)? data + UDP_PCK_SIZE + sizeof(u_int32_t) : NULL;

	/* send the alert */
	push_alert(&connection, proto, payload, payload_len);

	return;
}

typedef struct {
	int socket;
	unsigned long addr;
	unsigned short port;
} TCPConData;

/* 
 * Serve a TCP connection.
 */
static void *tcp_connection(TCPConData *data)
{
	struct timeval wait;
	int ret;
	fd_set readset;
	char pwd[UDP_PCK_SIZE];
	char *buf = NULL;
	int buf_len;
	ssize_t numbytes;

	FD_ZERO(&readset);
	FD_SET(data->socket, &readset);
	wait.tv_sec = 5;
	wait.tv_usec = 0;

select_again:
	ret = select(data->socket, &readset, NULL, NULL, &wait);
	if (ret == -1) {
		if (errno == EBADF) {
			wait.tv_sec = 5;
			wait.tv_usec = 0;
			goto select_again;
		}
		else goto end;
	}
	else if (ret == 0) {
		DPRINTF("Select timed out\n");
		goto end;
	}

	numbytes = recv(data->socket, pwd, UDP_PCK_SIZE, 0);
	if (numbytes == -1) {
		errno_cont("recv");
		goto end;
	} else if (numbytes != UDP_PCK_SIZE)
		goto end;

	pwd[UDP_PCK_SIZE - 1] = '\0';
	if(!check_password(pwd)) {
		DPRINTF("Wrong Password\n");
		goto end;
	}
	/* password is OK, now receive the alert */
	buf_len = recv_alert_data(data->socket, buf);
	if (buf_len > 0) {
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
static void init_agents(Agents *agents, int max_conns)
{
	agents->max = max_conns;
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
 * Main agents_thread function
 */
void *agents_contact(AgentsContactData *data)
{
	int newfd,maxfd;
	fd_set readset, allset;
	int nready;
	struct sockaddr_in my_addr, his_addr;;
	socklen_t addrlen;
	Agents agents;
	TCPConData *t_data;

	init_agents(&agents, data->max_conns);

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(data->port);
	free(data);
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
								&t_data);
				}
			}
			if(--nready <= 0)
				continue;
		}
	}
}
