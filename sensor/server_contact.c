/* 
 * Functions for communicating with the Scheduler (Server)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <nids.h>
#include "errors.h"


/* The Socket File Descriptor for the communication */
static int sockfd; 


/* This function makes sure all the wanted data are sent.
 * It takes as arguments the socket file descriptor, the
 * buffer and the length. It returns 0 on success, -1 on
 * failure.
 */ 
static int sendall(int s, char *buf, unsigned int *len)
{
	int total = 0;
	int bytesleft = *len;
	int n = -1; /* what if *len == 0 ? */

	while (total < *len) {
		n = send(s, buf+total, bytesleft, 0);
		if (n == -1)
			break;
		total += n;
		bytesleft -= n;
	}

	*len = total;
	return n==-1?-1:0;
}


/* The packet types */
enum {
       PT_CONNECT = 0,
       PT_CLOSE,
       PT_NEW_TCP,
       PT_TCP_CLOSE,
       PT_TCP_DATA,
       PT_UDP_DATA
};


/*
 * Connect to the Sceduler
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0________4________8
 * |  size  | packet |
 * |________|__type__|
 *
 */
int server_connect(in_addr_t s_addr,unsigned short s_port)
{
	struct sockaddr_in server_addr;
	unsigned int packet_size,msglen;
	char packet_buffer[2 * sizeof(unsigned int)];
	char * buffer_pointer;
	int bytenum;
	unsigned int *size,*reply;

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return 0;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(s_port);
	server_addr.sin_addr.s_addr = s_addr;
	memset(&(server_addr.sin_zero), '\0', 8);

	if (connect(sockfd, (struct sockaddr *)&server_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("connect");
		return 0;
	}

	/* fill the packet_buffer with data in Network Byte Order */
	packet_size = 2 * sizeof(unsigned int);

	buffer_pointer = packet_buffer;
	*(unsigned int *)buffer_pointer = htonl(packet_size);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(PT_CONNECT);

	/* send the data */
	if (sendall(sockfd, packet_buffer, &packet_size) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}
	
	/* Wait for the answer......*/
	msglen = 0;
	packet_size = 2*sizeof(unsigned int);
	
	/* Only receive the expected reply length */
	do {
		if ((bytenum = recv(sockfd, packet_buffer+msglen, packet_size-msglen, 0)) == -1) {
			perror("recv");
			return 0;
		}
		msglen += bytenum;

	} while (msglen < packet_size);

	size = (unsigned int *)packet_buffer;
	reply = size + 1;

	if (ntohl(*size) == packet_size) {
		switch (ntohl(*reply)) {
			case 0:
				return 1;
			
			case 1: 
				fprintf(stderr, "Too many connection\n");
				return 0;

			default:
				fprintf(stderr, "Undefined Error\n");
				return 0;
		}
	}

	fprintf(stderr, "Error in the size of the reply\n");
	return 0;
}


/*
 * Disconnect from the Sceduler
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0________4________8
 * |  size  | packet |
 * |________|__type__|
 *
 */
int server_disconnect(void)
{
	unsigned int packet_size;
	char packet_buffer[2 * sizeof(unsigned int)];
	char * buffer_pointer;

	
	/* Fill the packet buffer with data in Network Byte Order */
	packet_size = 2 * sizeof(unsigned int);

	buffer_pointer = packet_buffer;
	*(unsigned int *)buffer_pointer = htonl(packet_size);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(PT_CLOSE);

	/* Send the data */
	if (sendall(sockfd, packet_buffer, &packet_size) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	return 1;
}

/*
 * Submit a new TCP connection to the Sceduler
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0________4________8________12_______________________24
 * |  size  | packet | stream |     struct tuple4      |
 * |________|__type__|___ID___|________________________|
 *
 */
int new_tcp_connection(unsigned int stream_id, struct tuple4 *tcp_addr)
{
	unsigned int packet_size;
	char packet_buffer[3 * sizeof(unsigned int) + sizeof(struct tuple4)];
	char * buffer_pointer;

	
	/* Fill the packet buffer with data in Network Byte Order */
	packet_size = 5 * sizeof(unsigned int) + 2 * sizeof(unsigned short);
	
	buffer_pointer = packet_buffer;
	*(unsigned int *)buffer_pointer = htonl(packet_size);
	
	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(PT_NEW_TCP);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(stream_id);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned short *)buffer_pointer = htons(tcp_addr->source);
	
	buffer_pointer += sizeof(tcp_addr->source);
	*(unsigned short *)buffer_pointer = htons(tcp_addr->dest);

	buffer_pointer += sizeof(tcp_addr->dest);
	*(unsigned int *)buffer_pointer = htonl(tcp_addr->saddr);

	buffer_pointer += sizeof(tcp_addr->saddr);
	*(unsigned int *)buffer_pointer = htonl(tcp_addr->daddr);

	/* Send the Data */
	if (sendall(sockfd, packet_buffer, &packet_size) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	return 1;
}


/*
 * Informs the Sceduler that a TCP connection has closed
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0________4________8________12
 * |  size  | packet | stream |
 * |________|__type__|___ID___|
 *
 */
int close_tcp_connection(unsigned int stream_id)
{
	unsigned int packet_size;
	char packet_buffer[3 * sizeof(unsigned int)];
	char * buffer_pointer;


	/* Fill the packet buffer with data in Network Byte Order */
	packet_size = 3 * sizeof(unsigned int);

	buffer_pointer = packet_buffer;
	*(unsigned int *)buffer_pointer = htonl(packet_size);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(PT_TCP_CLOSE);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(stream_id);

	/* Send the Data */
	if (sendall(sockfd, packet_buffer, &packet_size) == -1) {
		perror("sendall");
		return 0;
	}

	return 1;
}


/*
 * Sends TCP data to the Scheduler
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0________4________8________12_______ _ _ _ _
 * |  size  | packet | stream |   data
 * |________|__type__|___ID___|________ _ _ _ _
 *
 */

int send_tcp_data(unsigned int stream_id, u_char *data, int data_length)
{
	unsigned int packet_size;
	char header_buffer[3 * sizeof(unsigned int)];
	char * buffer_pointer;
	unsigned int header_length = 3 * sizeof(unsigned int);


	if (data_length <= 0) {
		/*this is an error....*/
		fprintf(stderr,"send_tcp_data: No Data to send...\n");
		return 0;
	}

	/* lets send the header first... */
	packet_size = header_length + data_length;

	buffer_pointer = header_buffer;
	*(unsigned int *)buffer_pointer = htonl(packet_size);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(PT_TCP_DATA);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(stream_id);


	if (sendall(sockfd, header_buffer, &header_length) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	/* Now lets send the data... */

	if (sendall(sockfd, data, &data_length) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	return 1;
}


/*
 * Sends UDP data to the Scheduler
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0_______4_______8______12________________24_______ _ _ _ _
 * | packet| packet|  ID   |   struct tuple4 |  data
 * |__size_|__type_|_______|_________________|_______ _ _ _ _
 *
 */

int send_udp_data(struct tuple4 *udp_addr, u_char *data,
		int data_length, unsigned int id)
{
	unsigned int packet_size;
	char header_buffer[3 * sizeof(unsigned int) + sizeof(struct tuple4)];
	unsigned int header_length = 3 * sizeof(unsigned int) + sizeof(struct tuple4);
	char * buffer_pointer;


	if (data_length <= 0) {
		fprintf(stderr, "send_udp_data: No Data to send...\n");
		return 0;
	}

	/* The header first... */
	packet_size = header_length + data_length;

	buffer_pointer = header_buffer;
	*(unsigned int *)buffer_pointer = htonl(packet_size);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(PT_UDP_DATA);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned int *)buffer_pointer = htonl(id);

	buffer_pointer += sizeof(unsigned int);
	*(unsigned short *)buffer_pointer = htons(udp_addr->source);
	
	buffer_pointer += sizeof(udp_addr->source);
	*(unsigned short *)buffer_pointer = htons(udp_addr->dest);

	buffer_pointer += sizeof(udp_addr->dest);
	*(unsigned int *)buffer_pointer = htonl(udp_addr->saddr);

	buffer_pointer += sizeof(udp_addr->saddr);
	*(unsigned int *)buffer_pointer = htonl(udp_addr->daddr);



	if (sendall(sockfd, header_buffer, &header_length) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	/* the data... */
	if (sendall(sockfd, data, &data_length) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	return 1;
}
