#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "agent.h"
#include "config.h"
#include "detect_engine.h"
#include "alert.h"


Session session;

void sigalrm_handler(int s)
{
	return;
}

static inline void copy_password(char *buf)
{
	strncpy(buf, PASSWORD, UDP_SIZE);
}

static int send_msg(int type)
{
	char buf[2*UDP_SIZE];
	socklen_t addr_len;
	size_t len;
	ssize_t numbytes;

	if((type == UDP_NEW_AGENT) || (type == UDP_QUIT)) {
		len = 2*UDP_SIZE;
		copy_password(buf + UDP_SIZE);
	} else	len = UDP_SIZE;

	
	*(u_int32_t *)(buf +  0) = htonl(len);
	*(u_int32_t *)(buf +  4) = htonl(session.sec);
	*(u_int32_t *)(buf +  8) = type;
	*(u_int32_t *)(buf + 12) = htonl(session.id);

	addr_len = sizeof(struct sockaddr);
	numbytes = sendto(session.fd, buf, len, 0,
			(struct sockaddr *)session.addr, addr_len);
	if(numbytes == -1) {
		perror("sendto");
		return 0;
	}

	return 1;
}


int recv_packet(Packet *pck)
{
	char main_buf[UDP_SIZE];
	char addr_buf[UDP_SIZE];
	char *payload = NULL;
	ssize_t payload_len = 0;
	unsigned int size;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(struct sockaddr);
	ssize_t numbytes;
	struct msghdr msg;
	struct iovec iov[3];


	alarm(TIMEOUT_WAIT);
	/* Just "Peek" the first 32 bits... this should be the packet size */
	numbytes = recvfrom(session.fd, &size, sizeof(u_int32_t),
			MSG_PEEK, (struct sockaddr *)&addr, &addr_len);
	alarm(0);

	if(numbytes == -1) {
		if (errno == EINTR)
			printf("timed out\n");
		else
			perror("\nrecvfrom");
		return 0;
	}

	if(numbytes != sizeof(size))
		return 0;

	size = ntohl(size);
	if((size < UDP_SIZE) || ((size > UDP_SIZE) && (size <= 2*UDP_SIZE))) {
		/* Size is not sane... I'll just clear the receiv buffer */
		if(recvfrom(session.fd, main_buf, UDP_SIZE, 0,NULL,0) == -1)
			perror("recvfrom");
		return 0;
	}

	/* size seems OK, I'll receive the packet */
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(struct sockaddr);
	msg.msg_iov = iov;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	/* 
	 * Don't know about this MSG_TRUNK flag. Stevens  says something,
	 * linux man page something else....but I'll use it anyway.
	 */
	msg.msg_flags = MSG_TRUNC; 

	iov[0].iov_base = main_buf;
	iov[0].iov_len = UDP_SIZE;
	iov[1].iov_base = addr_buf;
	iov[1].iov_len = UDP_SIZE;

	if(size == UDP_SIZE) /* Simple message packet */
		msg.msg_iovlen = 2;
	else { /* Packet has addr and payload too */
		payload_len = size - 2*UDP_SIZE;
		payload = malloc(payload_len + 1);
		iov[2].iov_base = payload;
		iov[2].iov_len = payload_len + 1;
		msg.msg_iovlen = 3;
	}

	/* Now let's get the packet "for real" */
	numbytes = recvmsg(session.fd, &msg, 0);
	if(numbytes == -1) {
		perror("recvmsg");
		return 0;
	}

	if((size != numbytes) || (msg.msg_flags & MSG_TRUNC)) {
		/* The packet is fucked up */
		fprintf(stderr,"Protocol violation\n");
		if(payload)
		       free(payload);
		return 0;
	}

	pck->sec   = ntohl(*(u_int32_t *)(main_buf +  4));
	pck->type  =       *(u_int32_t *)(main_buf +  8);
	pck->id    = ntohl(*(u_int32_t *)(main_buf + 12));

	if(pck->work != NULL)
		pck->work->payload_len = 0;

	if(size != UDP_SIZE) { /* we have a long packet */
		if(pck->work == NULL) {
			free(payload);
			return 0;
		}
		pck->work->proto = ntohl(*(u_int32_t *)addr_buf);
		pck->work->s_port = *(u_int16_t *)(addr_buf + 4);
		pck->work->d_port = *(u_int16_t *)(addr_buf + 6);
		pck->work->s_addr = *(u_int32_t *)(addr_buf + 8);
		pck->work->d_addr = *(u_int32_t *)(addr_buf + 12);
		pck->work->payload = payload;
		pck->work->payload_len = payload_len;
	}

	return 1;
}

void quit_handler(int s)
{
	session.sec++;
	fprintf(stderr,"Sending QUIT Message...\n");
	send_msg(UDP_QUIT);
	exit(0);
}

static int request_connection()
{
	Packet pck;

	if(send_msg(UDP_NEW_AGENT) == 0) {
		fprintf(stderr,"Can't send connection request\n");
		return -1;
	}

	printf("Connecting to the Scheduler...");
	fflush(stdout);

	pck.work = NULL;
	if(recv_packet(&pck) == 0)
		return -1;

	if(pck.type == UDP_CONNECTED) {
		printf("Connected to the Scheduler.\n");
		printf("My ID is %u\n", pck.id);
		
		/*write the new id */
		session.id = pck.id;
		return 1;
	} else if(pck.type == UDP_NOT_CONN) {
		return 0;
	} else
		return -1;
}

static int request_work(Work *work, int type)
{
	Packet pck;

	if(send_msg(type) == 0) {
		fprintf(stderr,"Can't send work request\n");
		return -1;
	}

	pck.work = work;
	do {
		if(recv_packet(&pck) == 0)
			return -1;

	} while(pck.sec != session.sec);

	if(pck.type == UDP_NOT_FOUND)
		return 0;
	if(pck.type == UDP_DATA)
		return 1;
	else
		return 0;
}

static inline int get_work(Work *work, int type)
{
	int i;
	int ret;

	printf("get_work\n");

	/* New Work == New sequence number */
	session.sec++;

	for(i = 0; i < RETRY_TIMES; i++) {
		ret = request_work(work, type);
		if(ret != -1)
			return ret;
		fprintf(stderr,"Retying...\n");
	}

	/* The communication is bad, I'll quit */
	exit(1);
}

static int scheduler_connect()
{
	int i;
	int ret;

	session.sec++;

	for(i = 0; i < RETRY_TIMES; i++) {
		ret = request_connection();
		if(ret == 1) {
			return 1;
		} else if(ret == 0) {
			printf("Scheduler refused to connect me\n");
#if 0
			printf("I'll sleep for 1 minute...\n");
			sleep(60);
			connection.sec++;
#endif
			return 0;
		} else {
			fprintf(stderr,"Retying...\n");
		}
	}
	return 0;
}


static void main_loop(void)
{
	int result;
	int ret;
	Work work;

	result = WORK_DONE;
	for(;;) {
		switch(result) {
			case WORK_DONE:
				ret = get_work(&work, UDP_NEW_WORK);
				break;

			case NEED_NEXT:
				ret = get_work(&work, UDP_GET_NEXT);
				break;

			case NEED_PREV:
				ret = get_work(&work, UDP_GET_PREV);
				break;

			case THREAT_DETECTED:
				alert_scheduler(&work);
				ret = get_work(&work, UDP_NEW_WORK);

			default:
				ret = 0;
		}
		if(ret)
			result = execute_work(work.payload, work.payload_len);
		else {
			result = execute_work(NULL, 0);
			fprintf(stderr,"No work is available,"
					"I'll sleep for 5 secs\n");
			sleep(5);
		}

	}
}

static inline void init_session(int socket, struct sockaddr_in *addr)
{
	session.fd = socket;
	session.addr = addr;
	session.sec = 0;
	session.id  = 0;
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_in their_addr;
	struct hostent *he;
	unsigned int port;
	struct sigaction sa;

	sa.sa_handler = sigalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	if (argc != 3) {
		fprintf(stderr,"usage: agent IP PORT\n");
		exit (1);
	}

	if ((he = gethostbyname(argv[1])) == NULL) {
		herror("gethostbyname");
		exit(1);
	}

	if ((port = atoi(argv[2])) == 0) {
		fprintf(stderr, "This is not a valid port\n");
		fprintf(stderr,"usage: agent IP PORT\n");
		exit (1);
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(port);
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(their_addr.sin_zero, '\0', 8);

	/* Now initialize the session */
	init_session(sockfd, &their_addr);

	/* Check the password */
	if (strlen(PASSWORD) >= UDP_SIZE) {
		fprintf(stderr, "Password too long\n");
		exit(1);
	}

	/* Try to connect to the sceduler */
	if(!scheduler_connect()) {
		fprintf(stderr, "Can't connect to the scheduler\n");
		exit(1);
	}

	/* if connected, initialize handlers for quiting... */
	sa.sa_handler = quit_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	/* Everything is initialized, go to the main loop */
	main_loop();

	return 0;
}
