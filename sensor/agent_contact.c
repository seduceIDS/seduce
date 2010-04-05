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
#include "data.h"
#include "alert_recv.h"
#include "thread.h"


static int udp_sock; /* The UDP Socket */
static int tcp_sock; /* The TCP Socket listening for incoming connections */

/*
 * Function: get_new_client_pos(uint8_t *, size_t)
 *
 * Purpose: Find the first unused entry in the Agents table 
 *
 * Arguments:  map=> pointer to the map array
 *             map_size=> Size of the map array in 8 bit (1 byte) units;
 *
 * Returns: the index of the first unused size on success
 *          map_size * 8  on error
 */
static unsigned short get_new_client_pos(uint8_t *map, size_t map_size)
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

static void remove_agent(Agents *, unsigned);

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
inline int check_password(const char *pwd)
{
	return (strncmp(pwd, pv.password, MAX_PWD_SIZE)) ? 0 : 1;
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
	uint8_t mask=0;
	unsigned id;
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
		id = (uint32_t)get_rand();
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
 * Function: remove_agent(Agents *, unsigned)
 *
 * Purpose:  Remove an agent from the Agent table
 *
 * Arguments:  agents=> struct with info about all the agents
 *             id => Agent's ID;
 */
static void remove_agent(Agents *agents, unsigned id)
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

		mutex_lock(&sensor.mutex);
		ret = destroy_datagroup(&sensor.proto_lost,
					&this_agent->history);
		/* TODO: Do I need to check about ret ? */
		mutex_unlock(&sensor.mutex);
	}

	memset(this_agent, '\0', sizeof(AgentInfo));

	/* Update the bit map */
	mask = ~(1 << (*index % 8));
	i = *index / 8;
	agents->map[i] = agents->map[i] & mask;

	hash_agent_remove(agents->hash, id);
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
	char buf[UDP_HDR_SIZE];
	size_t length;
	socklen_t addr_len = sizeof(struct sockaddr);
	int numbytes;

	DPRINTF("\n");
	length = UDP_HDR_SIZE;
	addr_len =  sizeof(struct sockaddr);

	*(u_int32_t *)(buf +  0) = htonl(length);
	*(u_int32_t *)(buf +  4) = htonl(type);
	*(u_int32_t *)(buf +  8) = htonl(agent->seq);
	*(u_int32_t *)(buf + 12) = htonl(agent->id);

	numbytes = sendto(udp_sock, buf, length, 0,
			(struct sockaddr *) &agent->addr, addr_len);

	DPRINTF("Send: %u,%u,%u,%u\n", length, agent->seq, type, agent->id);
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
	ssize_t numbytes;
	socklen_t addr_len = sizeof(struct sockaddr);
	size_t length = UDP_HDR_SIZE;
	
	unsigned type;
	unsigned char * payload;
	size_t payload_length;

	DPRINTF("\n");
	if (work->session->proto == IPPROTO_TCP) {
		payload =        work->data.tcp->payload;
		payload_length = work->data.tcp->length;
	} else {
		payload =        work->data.udp->payload;
		payload_length = work->data.udp->length;
	}

	/* what kind of package do we send? */
	if(work->is_grouphead) {
		type = UDP_HEAD_DATA;
		length += UDP_INFO_SIZE;
	} else
		type = UDP_DATA;

	length += payload_length;
	buf = malloc(length);
	if(buf == NULL) {
		errno_cont("malloc");
		return 0;
	}

	/* The packet header */
	*(u_int32_t *)(buf +  0) = htonl(length);
	*(u_int32_t *)(buf +  4) = htonl(type);
	*(u_int32_t *)(buf +  8) = htonl(agent->seq);
	*(u_int32_t *)(buf + 12) = htonl(agent->id);

	if(work->is_grouphead) {
		*(u_int32_t *)(buf + 16) = htonl(work->session->proto);
		*(u_int16_t *)(buf + 20) = work->session->addr.source;
		*(u_int16_t *)(buf + 22) = work->session->addr.dest;
		*(u_int32_t *)(buf + 24) = work->session->addr.saddr;
		*(u_int32_t *)(buf + 28) = work->session->addr.daddr;
		memcpy(buf + 32, payload, payload_length); 
	} else
		memcpy(buf + 16, payload, payload_length);

	numbytes = sendto(udp_sock, buf, length, 0, 
		     		(struct sockaddr *) &agent->addr, addr_len);
	if(numbytes == -1) {
		errno_cont("sendto");
		free(buf);
		return 0;
	}

	DPRINTF("Send: %u,%u,%u,%u\n", length, agent->seq, type, agent->id);
	DPRINTF("Bytes sent:%u\n", numbytes);

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
		mutex_lock(&sensor.mutex);
		/*
		 * I'm not sure those data should be logged as being lost
		 * because of the agents protocol, but I'll leave it like this
		 * for now
		 */
		ret = destroy_datagroup(&sensor.proto_lost, &agent->history);

		mutex_unlock(&sensor.mutex);
	}

	ret = consume_group(send_work, agent, 1);
	if (ret != -1)  /* a job was consumed */
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

		mutex_lock(&sensor.mutex);

		if(work.session->proto == IPPROTO_TCP)
			work.data.tcp = get_next_data(work.data.tcp);
		else 	
			work.data.udp = NULL;

		/* 
		 * Now we know what we want to send,
		 * so it's safe to destroy the old data
		 */
		destroy_data(&sensor.out, &agent->history);

		/* those data are not the head of a data group */
		work.is_grouphead = 0;

		if(work.data.tcp)
			ret = send_work(agent, &work);

		mutex_unlock(&sensor.mutex);
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

		mutex_lock(&sensor.mutex); /* Do I need this? */
		
		ret = send_work(agent, &agent->history);

		mutex_unlock(&sensor.mutex);

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
	char buf[UDP_HDR_SIZE + UDP_INFO_SIZE + 1];
	ssize_t numbytes;
	socklen_t addr_len;
	int max_pck_size = UDP_HDR_SIZE + UDP_INFO_SIZE; 

	DPRINTF("\n");
	addr_len = sizeof(struct sockaddr);
	numbytes = recvfrom(udp_sock, buf, max_pck_size + 1, MSG_DONTWAIT,
		      (struct sockaddr *) &pck->addr, &addr_len);
	if (numbytes == -1) {
		if(errno == EAGAIN)
			return 0; /* no data available */
		errno_abort("recvfrom");
	}


	DPRINTF("I got %d bytes\n", numbytes);
	if((numbytes != UDP_HDR_SIZE) && (numbytes != max_pck_size))
		return -1;

	pck->size = ntohl(*(uint32_t *) (buf +  0));
	if(pck->size != numbytes)
		return -1;
	pck->type = ntohl(*(uint32_t *) (buf +  4));
	pck->seq  = ntohl(*(uint32_t *) (buf +  8));
	pck->id   = ntohl(*(uint32_t *) (buf + 12));

	if(numbytes == max_pck_size)
		strncpy(pck->pwd,buf + UDP_HDR_SIZE, UDP_INFO_SIZE - 1);

	DPRINTF("Received: %u,%u,%u,%u\n",pck->size, pck->seq,
							pck->type, pck->id);

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

	} else if(pck->seq == (this_agent->seq + 1)) {
		/* new_request */
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
			/* does not exist any more */
			return; 
				 
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
void *agents_contact(void *thread_params)
{
	int newfd,maxfd, one;
	fd_set readset, allset;
	int nready;
	struct sockaddr_in my_addr, his_addr;
	socklen_t addrlen;
	Agents agents;

	init_agents(&agents);

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(pv.agent_port);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	memset(&(my_addr.sin_zero), '\0', 8);

	udp_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_sock == -1)
		errno_abort("socket");

	if(bind(udp_sock, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
		errno_abort("bind");

	tcp_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (tcp_sock == -1)
		errno_abort("socket");

	if(setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, 
							 sizeof(one)) == -1)
		errno_abort("setsockopt");

	if(bind(tcp_sock, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
		errno_abort("bind");

	if(listen(tcp_sock, 10) == -1)
		errno_abort("listen");

	maxfd = MAX(udp_sock, tcp_sock);

	FD_ZERO(&allset);
	FD_SET(udp_sock, &allset);
	FD_SET(tcp_sock, &allset);

	for(;;) {
		readset = allset;
select_restart:
		nready = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if (nready == -1) {
			if (errno == EINTR)
				goto select_restart;
			else
				errno_abort("select");
		}

		if (FD_ISSET(udp_sock, &readset)) {
			udp_request(&agents);

			if(--nready <= 0)
				continue;
		}
		if (FD_ISSET(tcp_sock, &readset)) {
			addrlen = sizeof(his_addr);
			newfd = accept(tcp_sock, (struct sockaddr *)&his_addr,
					&addrlen);
			if(newfd == -1)
				errno_cont("accept");
			else 
				create_thread((void *)alert_receiver, 
								(void *) newfd);
			
			if(--nready <= 0)
				continue;
		}
	}
}
