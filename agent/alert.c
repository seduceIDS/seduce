#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>


#include "alert.h"
#include "config.h"

/* from agent.c */
extern Session session;

/* from detect_endine.c */
extern char *threat_payload;
extern size_t threat_length;

static int tcp_connect(struct sockaddr_in *addr)
{
	int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr);

	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if(sockfd == -1) {
		perror("socket");
		return 0;
	}

	if(connect(sockfd, (struct sockaddr *)addr, addrlen) == -1) {
		perror("connect");
		return 0;
	}

	return sockfd;
}

static int send_alert(int socket, Work *work)
{
	char buf[TCP_SIZE];
	size_t size;
	ssize_t numbytes;
	int iovcnt;
	struct iovec iov[2];

	size = TCP_SIZE + threat_length;
	*(u_int32_t *)(buf +  0) = htonl(size);
	*(u_int32_t *)(buf +  4) = htonl(session.id);
	*(u_int32_t *)(buf +  8) = htonl(work->proto);
	*(u_int16_t *)(buf + 10) = htonl(work->s_port);
	*(u_int16_t *)(buf + 12) = htonl(work->d_port);
	*(u_int32_t *)(buf + 16) = htonl(work->s_addr);
	*(u_int32_t *)(buf + 20) = htonl(work->d_addr);

	iov[0].iov_base = buf;
	iov[0].iov_len = TCP_SIZE;
	iov[1].iov_base = threat_payload;
	iov[1].iov_len = threat_length;

	iovcnt = 2;

	numbytes = writev(socket,iov,iovcnt);
	if (numbytes == -1) {
		perror("writev");
		return 0;
	}

	if (numbytes != size)
		return 0;

	return 1;
}

int alert_scheduler(Work *work)
{
	int socket;
	int i;

	printf("Connecting to the Scheduler...");

	for(i = 0; i <  RETRY_TIMES; i++) {
		socket = tcp_connect(session.addr);

		if(!socket) {
			fprintf(stderr, "Can't connect...");
			sleep(RETRY_WAIT);
		} else break;
		fprintf(stderr, "Trying...\n");
	}

	if(i == RETRY_TIMES) {
		fprintf(stderr, "Connecting to the scheduler failed\n");
		return 0;
	}
	printf("done\n");

	printf("Sending the alert...");
	if(send_alert(socket,work) == 0) {
		fprintf(stderr, "Couldn't send the alert\n");
		close(socket);
	       return 0;
	}

	printf("done\n");

	printf("Terminating the connection\n");
	close(socket);
	return 1;
}
