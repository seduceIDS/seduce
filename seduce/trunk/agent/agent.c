#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "agent.h"
#include "detect_engine.h"


extern void fill_progvars(int, char **);
extern int alert_scheduler(Work *);

/* Globals */
PV pv;
QemuVars qv;

void sigalrm_handler(int s)
{
	return;
}

inline void copy_password(char *buf)
{
	strncpy(buf, pv.password, MAX_PWD_SIZE);
}

static int send_msg(int type)
{
	char buf[MIN_UDP_SIZE + MAX_PWD_SIZE];
	socklen_t addr_len;
	size_t len;
	ssize_t numbytes;


	if((type == SEND_NEW_AGENT) || (type == SEND_QUIT)) {
		len = MIN_UDP_SIZE + MAX_PWD_SIZE;
		copy_password(buf + MIN_UDP_SIZE);
	} else	len = MIN_UDP_SIZE;

	
	*(u_int32_t *)(buf +  0) = htonl(len);
	*(u_int32_t *)(buf +  4) = htonl(pv.seq);
	*(u_int32_t *)(buf +  8) = htonl(type);
	*(u_int32_t *)(buf + 12) = htonl(pv.id);

	addr_len = sizeof(struct sockaddr);
	numbytes = sendto(pv.socket, buf, len, 0,
					(struct sockaddr *)&pv.addr, addr_len);
	if(numbytes == -1) {
		perror("sendto");
		return 0;
	}

	return 1;
}


int recv_packet(Packet *pck)
{
	char main_buf[MIN_UDP_SIZE];
	char addr_buf[MIN_UDP_SIZE];
	char *payload = NULL;
	ssize_t payload_len = 0;
	unsigned int size;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(struct sockaddr);
	ssize_t numbytes;
	struct msghdr msg;
	struct iovec iov[3];


	fflush(stdout);
	alarm(pv.timeout);
	/* Just "Peek" the first 32 bits... this should be the packet size */
	numbytes = recvfrom(pv.socket, &size, sizeof(u_int32_t),
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
	if((size < MIN_UDP_SIZE) || 
	  ((size > MIN_UDP_SIZE) && (size <= 2*MIN_UDP_SIZE))) {

		/* 
		 * Size is not sane...I'll just clear the receive buffer by
		 * receiving 1 byte and leaving it to the kernel to remove
		 * the packet from the buffer
		 */
		if(recvfrom(pv.socket, main_buf, 1, 0,NULL,0) == -1)
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
	 * Don't know about this MSG_TRUNK flag. Stevens says something,
	 * linux man page something else....but I'll use it anyway.
	 */
	msg.msg_flags = MSG_TRUNC; 

	iov[0].iov_base = main_buf;
	iov[0].iov_len = MIN_UDP_SIZE;
	iov[1].iov_base = addr_buf;
	iov[1].iov_len = MIN_UDP_SIZE;

	if(size == MIN_UDP_SIZE) /* Simple message packet */
		msg.msg_iovlen = 2;
	else { /* Packet has addr and payload too */
		payload_len = size - 2*MIN_UDP_SIZE;
		payload = malloc(payload_len + 1);
		iov[2].iov_base = payload;
		iov[2].iov_len = payload_len + 1;
		msg.msg_iovlen = 3;
	}

	/* Now let's get the packet for real this time */
	numbytes = recvmsg(pv.socket, &msg, 0);
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

	pck->seq   = ntohl(*(u_int32_t *)(main_buf +  4));
	pck->type  = ntohl(*(u_int32_t *)(main_buf +  8));
	pck->id    = ntohl(*(u_int32_t *)(main_buf + 12));

	if(pck->work != NULL)
		pck->work->payload_len = 0;

	if(size != MIN_UDP_SIZE) { /* we have a long packet */
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
    detect_engine_stop(&qv);
	pv.seq++;
	printf("Sending QUIT Message...\n");
	send_msg(SEND_QUIT);
	exit(0);
}

static int request_connection()
{
	Packet pck;

	if(send_msg(SEND_NEW_AGENT) == 0) {
		fprintf(stderr,"Can't send connection request\n");
		return -2;
	}

	printf("Connecting to the Scheduler...");

	pck.work = NULL;
	if(recv_packet(&pck) == 0)
		return -1;

	if(pck.type == RECV_CONNECTED) {
		printf("Connected to the Scheduler.\n");
		printf("My ID is %u\n", pck.id);

		/*write the new id */
		pv.id = pck.id;
		return 1;

	} else if(pck.type == RECV_NOT_CONN) {
		return 0;
	} else
		return -1;
}

static int request_work(Work *work, int type)
{
	Packet pck;

	if(send_msg(type) == 0) {
		fprintf(stderr,"Can't send work request\n");
		return -2;
	}

	pck.work = work;

	/* receive packets until we get receive the right sec */
	do {
		if(recv_packet(&pck) == 0)
			return -1;

	} while(pck.seq != pv.seq);

	if(pck.type == RECV_NOT_FOUND)
		return 0;

	else if(pck.type == RECV_DATA)
		return 1;

	else {
		fprintf(stderr, "Unknown packet type\n");
		return 0;
	}
}

static int need_work(Work *work, int type)
{
	int i;
	int ret;

	printf("get_work\n");

	/* for new work we need new sequence number */
	pv.seq++;

	i = 0;
	do {
		ret = request_work(work, type);
		if(ret == -2)
			goto err;
		else if(ret != -1)
			return ret;

		i++;
		printf("Retying...\n");
	} while(i <= pv.retries);

err:
	fprintf(stderr, "The communication is bad, quiting..\n");
	exit(1);
}

static int scheduler_connect()
{
	int i;
	int ret;

	pv.seq++;

	i = 0;
	do {
		ret = request_connection();
		if(ret == 1)
			return 1;

		else if(ret == 0) {
			fprintf(stderr, "Scheduler refused to connect me\n");
			return 0;
		}

		else if(ret == -2)
			/* No need to retry, we have a problem in sending */
			return 0;

		i++;
		printf("Retying...\n");
	} while(i <= pv.retries);

	return 0;
}


static void main_loop(void)
{
	int result;
	int ret;
	int new_work_asked = 0;
	Work work;

    detect_engine_init(&qv);
	result = WORK_DONE;
	for(;;) {
		switch(result) {
			case WORK_DONE:
				ret = need_work(&work, SEND_NEW_WORK);
				new_work_asked = 1;
				break;

			case NEED_NEXT:
				ret = need_work(&work, SEND_GET_NEXT);
				new_work_asked = 0;
				break;

			case THREAT_DETECTED:
				alert_scheduler(&work);
				ret = need_work(&work, SEND_NEW_WORK);
				new_work_asked = 1;
				break;

			default:
				ret = 0;
				break;
		}
		if(ret)
			result = execute_work(work.payload, work.payload_len, &qv);
		else {
			result = execute_work(NULL, 0, &qv);

			if(new_work_asked) {
				/* 
				 * If I requested new work (not next work!!)
				 * and the scheduler hasn't any, I could use
				 * some sleep :-)
				 */
				printf("No work is available, I'll sleep\n");
				fflush(stdout);
				sleep(pv.no_work_wait);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa;

	sa.sa_handler = sigalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		perror("sigaction sigalrm");
		exit(1);
	}
    sa.sa_handler = sigvtalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
	if (sigaction(SIGVTALRM, &sa, NULL) == -1) {
		perror("sigaction sigvtalrm");
		exit(1);
	}

	/* initialize the programe variables */
	fill_progvars(argc, argv);

	/* initialize the socket */
	pv.socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (pv.socket == -1) {
		perror("socket");
		exit(1);
	}

	/* Try to connect to the sceduler */
	if(!scheduler_connect()) {
		fprintf(stderr, "Can't connect to the scheduler\n");
		exit(1);
	}

	/* if connected, initialize handlers for quiting */
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
