#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <stdlib.h>

#include "alert.h"
#include "agent.h"
#include "utils.h"

#define MIN_TCP_SIZE	20

static int tcp_connect()
{
	int sock;
	socklen_t addrlen = sizeof(struct sockaddr);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1) {
		perror("socket");
		return 0;
	}

	if(connect(sock, (struct sockaddr *)&pv.addr, addrlen) == -1) {
		perror("connect");
		return 0;
	}

	return sock;
}

#if 0
static int send_alert(int socket, const Work *work)
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
	*(u_int32_t *)(buf +  4) = htonl(work->info.proto);
	*(u_int16_t *)(buf +  8) = work->info.s_port;
	*(u_int16_t *)(buf + 10) = work->info.d_port;
	*(u_int32_t *)(buf + 12) = work->info.s_addr;
	*(u_int32_t *)(buf + 16) = work->info.d_addr;

	iov[0].iov_base = pwd;
	iov[0].iov_len = MAX_PWD_SIZE;
	iov[1].iov_base = buf;
	iov[1].iov_len = MIN_TCP_SIZE;
	iov[2].iov_base = threat_payload;
	iov[2].iov_len = threat_length;

	iovcnt = 3;

	numbytes = writev(socket,iov,iovcnt);
    free(threat_payload);
	if (numbytes == -1) {
		perror("writev");
		return 0;
	}

	if (numbytes != size + 16)
		return 0;

	return 1;
}

int alert_scheduler(const Work *work)
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
	if(send_alert(socket, work) == 0) {
		fprintf(stderr, "Couldn't send the alert\n");
		close(socket);
	       return 0;
	} else 
		printf("done\n");

	printf("Terminating the connection\n");
	close(socket);
	return 1;
}
#endif

int alert_submission(ConnectionInfo *c, Threat *t)
{
	printf("Submitting an alert...\n");
	return 1;
}
