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


/* The Socket File Descriptor for the communication */
static int sockfd; 


/* This function makes sure all the wanted data are sent.
 * It takes as arguments the socket file descriptor, the
 * buffer and the length. It returns 0 on success, -1 on
 * failure.
 */ 
static int sendall(int s, char *buf, unsigned int len)
{
	int total = 0;
	size_t bytesleft = len;
	ssize_t n = -1; /* what if len == 0 ? */

	while (total < len) {
		n = send(s, buf+total, bytesleft, 0);
		if (n == -1)
			break;
		total += n;
		bytesleft -= n;
	}

	return (n == -1) ? -1 : total;
}


/* The packet types */
enum {
       PT_CONNECT = 0,
       PT_CLOSE,
       PT_NEW_TCP,
       PT_TCP_CLOSE,
       PT_TCP_DATA,
       PT_TCP_BREAK,
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
int server_connect(in_addr_t addr,unsigned short port)
{
	struct sockaddr_in server_addr;
	unsigned int msglen;
	char buf[8];
	int bytenum;
	unsigned int size,reply;

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return 0;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = addr;
	memset(&(server_addr.sin_zero), '\0', 8);

	if (connect(sockfd, (struct sockaddr *)&server_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("connect");
		return 0;
	}

	/* fill the packet_buffer with data in Network Byte Order */
	msglen = 8;
	*(u_int32_t *)(buf + 0) = htonl(msglen);
	*(u_int32_t *)(buf + 4) = htonl(PT_CONNECT);

	/* send the data */
	if (sendall(sockfd, buf, msglen) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}
	
	/* Wait for the answer......*/
	/* Wait to receive the expected reply length */
	msglen = 8;
	bytenum = recv(sockfd, buf, msglen, MSG_WAITALL);
	if (bytenum == -1) {
		perror("recv");
		return 0;
	}

	if (bytenum != msglen) {
		fprintf(stderr, "Error in receiving data\n");
	       return 0;
	}	       

	size = ntohl(*(u_int32_t *)(buf + 0));
	reply =ntohl(*(u_int32_t *)(buf + 4));

	if(size != bytenum) {
		fprintf(stderr, "Error in the size of the reply\n");
		return 0;
	}

	switch (reply) {
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
	unsigned int msglen;
	char buf[8];

	/* Fill the packet buffer with data in Network Byte Order */
	msglen = 8;
	*(u_int32_t *)(buf + 0) = htonl(msglen);
	*(u_int32_t *)(buf + 4) = htonl(PT_CLOSE);

	/* Send the data */
	if (sendall(sockfd, buf, msglen) == -1) {
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
	unsigned int msglen;
	char buf[24];
	
	/* Fill the packet buffer with data in Network Byte Order */
	msglen = 24;
	*(u_int32_t *)(buf +  0) = htonl(msglen);
	*(u_int32_t *)(buf +  4) = htonl(PT_NEW_TCP);
	*(u_int32_t *)(buf +  8) = htonl(stream_id);
	*(u_int16_t *)(buf + 12) = htons(tcp_addr->source);
	*(u_int16_t *)(buf + 14) = htons(tcp_addr->dest);
	*(u_int32_t *)(buf + 16) = htonl(tcp_addr->saddr);
	*(u_int32_t *)(buf + 20) = htonl(tcp_addr->daddr);

	/* Send the Data */
	if (sendall(sockfd, buf, msglen) == -1) {
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
	unsigned int msglen;
	char buf[12];


	/* Fill the packet buffer with data in Network Byte Order */
	msglen = 12;
	*(u_int32_t *)(buf + 0) = htonl(msglen);
	*(u_int32_t *)(buf + 4) = htonl(PT_TCP_CLOSE);
	*(u_int32_t *)(buf + 8) = htonl(stream_id);

	/* Send the Data */
	if (sendall(sockfd, buf, msglen) == -1) {
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

int send_tcp_data(unsigned int stream_id, u_char *data, int datalen)
{
	unsigned int msglen;
	unsigned int hdrlen;
	char buf[12];

	if (datalen <= 0) {
		/*this is an error....*/
		fprintf(stderr,"send_tcp_data: No Data to send...\n");
		return 0;
	}

	hdrlen = 12;
	msglen = hdrlen + datalen; /* header + data */
	*(u_int32_t *)(buf + 0) = htonl(msglen);
	*(u_int32_t *)(buf + 4) = htonl(PT_TCP_DATA);
	*(u_int32_t *)(buf + 8) = htonl(stream_id);

	/* first send the header */
	if (sendall(sockfd, buf, hdrlen) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	/* then send the data... */
	if (sendall(sockfd, data, datalen) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	return 1;
}

/*
 * Informs the Sceduler that the next data belong to a new group
 * returns 1 on success, 0 on failure
 *
 * packet structure:
 * 0________4________8________12
 * |  size  | packet | stream |
 * |________|__type__|___ID___|
 *
 */

int tcp_data_break(unsigned int stream_id)
{
	unsigned int msglen;
	char buf[12];


	/* Fill the packet buffer with data in Network Byte Order */
	msglen = 12;
	*(u_int32_t *)(buf + 0) = htonl(msglen);
	*(u_int32_t *)(buf + 4) = htonl(PT_TCP_BREAK);
	*(u_int32_t *)(buf + 8) = htonl(stream_id);

	/* Send the Data */
	if (sendall(sockfd, buf, msglen) == -1) {
		perror("sendall");
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
		int datalen, unsigned int id)
{
	unsigned int msglen;
	unsigned int hdrlen;
	char buf[24];

	if (datalen <= 0) {
		fprintf(stderr, "send_udp_data: No Data to send...\n");
		return 0;
	}

	/* The header first... */
	hdrlen = 24;
	msglen = hdrlen + datalen;
	*(u_int32_t *)(buf +  0) = htonl(msglen);
	*(u_int32_t *)(buf +  4) = htonl(PT_UDP_DATA);
	*(u_int32_t *)(buf +  8) = htonl(id);
	*(u_int16_t *)(buf + 12) = htons(udp_addr->source);
	*(u_int16_t *)(buf + 14) = htons(udp_addr->dest);
	*(u_int32_t *)(buf + 16) = htonl(udp_addr->saddr);
	*(u_int32_t *)(buf + 20) = htonl(udp_addr->daddr);



	if (sendall(sockfd, buf, hdrlen) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	/* the data... */
	if (sendall(sockfd, data, datalen) == -1) {
		fprintf(stderr,"Error in sendall\n");
		return 0;
	}

	return 1;
}
