#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#include "agent.h"


/* from detect_engine.c */
extern char *threat_payload;
extern size_t threat_length;

#define MIN_TCP_SIZE	20

static int tcp_connect()
{
	int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr);

	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if(sockfd == -1) {
		perror("socket");
		return 0;
	}

	if(connect(sockfd, (struct sockaddr *)&pv.addr, addrlen) == -1) {
		perror("connect");
		return 0;
	}

	return sockfd;
}

static int send_alert(int socket, Work *work)
{
	char pwd[16];
	char buf[MIN_TCP_SIZE];
	size_t size;
	ssize_t numbytes;
	int iovcnt;
	struct iovec iov[3];

	copy_password(pwd);
	size = MIN_TCP_SIZE + threat_length;
	*(u_int32_t *)(buf +  0) = htonl(size);
	*(u_int32_t *)(buf +  4) = htonl(work->proto);
	*(u_int16_t *)(buf +  8) = work->s_port;
	*(u_int16_t *)(buf + 10) = work->d_port;
	*(u_int32_t *)(buf + 12) = work->s_addr;
	*(u_int32_t *)(buf + 16) = work->d_addr;

	iov[0].iov_base = pwd;
	iov[0].iov_len = MAX_PWD_SIZE;
	iov[1].iov_base = buf;
	iov[1].iov_len = MIN_TCP_SIZE;
	iov[2].iov_base = threat_payload;
	iov[2].iov_len = threat_length;

	iovcnt = 3;

	numbytes = writev(socket,iov,iovcnt);
	if (numbytes == -1) {
		perror("writev");
		return 0;
	}

	if (numbytes != size + 16)
		return 0;

	return 1;
}

int alert_scheduler(Work *work)
{
	int socket;

	printf("Connecting to the Scheduler...");

		socket = tcp_connect();
		if(!socket) {
			fprintf(stderr, "Connecting to the scheduler failed\n");
			return 0;
		} else
			printf("done\n");

	printf("Sending the alert...");
	if(send_alert(socket,work) == 0) {
		fprintf(stderr, "Couldn't send the alert\n");
		close(socket);
	       return 0;
	} else 
		printf("done\n");

	printf("Terminating the connection\n");
	close(socket);
	return 1;
}
