#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include <signal.h>
#include <string.h>

#include "utils.h"
#include "error.h"

#include "server_contact.h"
#include "agent.h"

/* 
 * conn_info should only be visible in this file. To make
 * other functions see part of it we need to declare getters.
 */
static ConnectionInfo  *conn_info = NULL;

static void sigalrm_handler(int s)
{
	return;
}

/*
 * Function: send_pck(int)
 *
 * Purpose: send a UDP package to the manager
 *
 * Arguments: type => The type of the package
 *
 * Returns: 1 => success
 *          0 => An error occured
 */
static int send_pck(int type)
{
	char pck[PROTO_HDR_SIZE + PROTO_PWD_SIZE];
	size_t length;
	ssize_t numbytes;

	switch(type) {
	case SEND_NEW_AGENT:
	case SEND_QUIT:
		/* those packets contain the hdr and a password*/
		length = PROTO_HDR_SIZE + PROTO_PWD_SIZE;
		copy_password(pck + PROTO_HDR_SIZE);
		break;

	case SEND_NEW_WORK:
	case SEND_GET_NEXT:
		length = PROTO_HDR_SIZE;
		break;
	
	default:
		fprintf(stderr, "send_pck: Unknown packet type");
		return 0;
	}

	/*
	 * Packet Header:
	 * 0________4________8________12_______16
	 * |  size  |  type  |  seq   |   ID   |
	 * |________|________|________|________|
	 *
	 */

	*(u_int32_t *)(pck +  0) = htonl(length);
	*(u_int32_t *)(pck +  4) = htonl(type);
	*(u_int32_t *)(pck +  8) = htonl(conn_info->seq);
	*(u_int32_t *)(pck + 12) = htonl(conn_info->id);

	numbytes = sendto(conn_info->sock, pck, length, 0,
		 (struct sockaddr *)&conn_info->addr, sizeof(struct sockaddr));
	if(numbytes == -1) {
		perror("sendto");
		return 0;
	}

	return 1;
}

static inline void fill_hdr_info(Packet *dst, const char *src)
{
	dst->size = ntohl(*(u_int32_t *)(src +  0));
	dst->type = ntohl(*(u_int32_t *)(src +  4));
	dst->seq  = ntohl(*(u_int32_t *)(src +  8));
	dst->id   = ntohl(*(u_int32_t *)(src + 12));
}

static inline void fill_session_info(Work *dst, const char *src)
{
	dst->proto = ntohl(*(u_int32_t *)(src +  0));
	dst->s_port =      *(u_int16_t *)(src +  4);
	dst->d_port =      *(u_int16_t *)(src +  6);
	dst->s_addr =      *(u_int32_t *)(src +  8);
	dst->d_addr =      *(u_int32_t *)(src + 12);
}

/*
 * Function: rcv_pck(Packet *)
 *
 * Purpose: receive a UDP packet from the manager
 *
 * Arguments: pck => The Packet struct to fill
 *
 * Returns:  1 => Success
 *           0 => Critical Error (recvfrom)
 *          -1 => Timed Out
 *          -2 => Package Sanity (wrong package fields)
 */
static int recv_pck(Packet *pck)
{
	char hdr[PROTO_HDR_SIZE]; /* for the packet header */
	char info[PROTO_INFO_SIZE]; /* for the session info (RECV_DATA_HEAD) */
	char *payload = NULL;
	socklen_t addr_len;
	ssize_t payload_len = 0;

	u_int32_t peek[2];
	unsigned int size, type;

	struct sockaddr_in addr;
	ssize_t numbytes;

	struct msghdr msg;
	struct iovec iov[3];

	int ret;

	alarm(pv.timeout);
	/* Just "Peek" the first 64 bits... this should be the size & type */
	numbytes = recvfrom(conn_info->sock, peek, 2*sizeof(u_int32_t),
				  MSG_PEEK,(struct sockaddr *)&addr, &addr_len);
	alarm(0);

	if(numbytes == -1) {
		if (errno == EINTR) {
			/* recvfrom timed out */
			DPRINTF("recvfrom timeout\n");
			return -1;
		} else {
			perror("recvfrom");
			return 0;
		}
	} else if (numbytes != 2 * sizeof(u_int32_t)) {
		/* 
		 * for some strange reason recvfrom returned without error but
		 * it did not do what we asked! I consider this a critical error
		 */
		return 0;
	}

	size = ntohl(peek[0]);
	type = ntohl(peek[1]);


	/* size sanity check and iov_len determination*/
	switch(type) {
	case RECV_CONNECTED:
	case RECV_NOT_CONN:
	case RECV_NOT_FOUND:
		/* those packages only contain a header */
		if(size != PROTO_HDR_SIZE) {
			proto_violation("size != hdr");
			/* sanity check error */
			ret = -2;
			goto drop_pck;
		}

		msg.msg_iovlen = 1;
		payload_len = 0;
		break;

	case RECV_DATA:
		/* this packet contains header and payload */
		if(size < (PROTO_HDR_SIZE + 1)) {
			proto_violation("size < hdr + 1");
		
			/* sanity check error */
			ret = -2;
			goto drop_pck;
		}

		msg.msg_iovlen = 2;
		payload_len = size - PROTO_HDR_SIZE;
		break;

	case RECV_HEAD_DATA:
		/* this packet contains header, info and payload */
		if(size < (PROTO_HDR_SIZE + PROTO_INFO_SIZE + 1)) {
			proto_violation("size < hdr + info + 1");

			/* sanity check error */
			ret = -2;
			goto drop_pck;
		}

		msg.msg_iovlen = 3;
		payload_len = size - PROTO_HDR_SIZE - PROTO_INFO_SIZE;

		/* add the info buffer to the iov struct */
		iov[1].iov_base = info;
		iov[1].iov_len = PROTO_INFO_SIZE;
		break;

	default:
		/* Unknown Reply */
		proto_violation("Unknown Reply type\n");
		
		/* sanity check error */
		ret = -2;
		goto drop_pck;
	}

	/* the header buffer should be in the iov struct for all packages */
	iov[0].iov_base = hdr;
	iov[0].iov_len = PROTO_HDR_SIZE;

	/* payload is always the entry of the iov struct */
	if(payload_len) {
		payload = malloc(payload_len);
		if(payload == NULL){
			perror("malloc");

			/* a malloc failure is critical... */
			ret = 0;
			goto drop_pck;
		}

		/* Payload is always in the last place */
		iov[msg.msg_iovlen - 1].iov_base = payload;
		iov[msg.msg_iovlen - 1].iov_len  = payload_len;
	} else 
		payload = NULL;

	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(struct sockaddr);
	msg.msg_iov = iov;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/*
	 * Flags we supply:
	 *
	 * MSG_TRUNC: Return the real length of the packet, even when it was
	 * longer than the passed buffer. Only valid for packet sockets.
	 *
	 * This can be used to check the real packet size
	 */
	msg.msg_flags = MSG_TRUNC;

	/* Now let's get the packet for real this time */
	numbytes = recvmsg(conn_info->sock, &msg, 0);
	if(numbytes == -1) {
		perror("recvmsg");
		ret = 0;
		goto after_rcv_err;
	}

	/*
	 * Flags upon return:
	 *
	 * MSG_TRUNC: indicates that the trailing portion of a datagram was
	 * discarded because the datagram was larger than the buffer supplied.
	 *
	 * we will double check
	 */
	if((size != numbytes) || (msg.msg_flags & MSG_TRUNC)) {
		/* the package is fucked up... */
		fprintf(stderr, "Size = %d, numbytes = %d\n", size, numbytes);
		proto_violation("The actual packet size"
				"and the packet size field don't match");
		ret = -2;
		goto after_rcv_err;
	}

	/* Copy the header info */
	fill_hdr_info(pck, hdr);

	/* Copy payload's session info if needed*/
	if(type == RECV_HEAD_DATA)
		fill_session_info(&pck->work, info);

	/* Copy the payload info (may be NULL)*/
	pck->work.payload = payload;
	pck->work.length = payload_len;

	return 1;

drop_pck:
	/* 
 	 * clear the receive buffer by receiving 1 byte and leaving it to the
	 * kernel to remove the packet from the buffer
 	 */
	if(recvfrom(conn_info->sock, hdr, 1, 0,NULL,0) == -1)
			perror("recvfrom");
	
	return ret;

after_rcv_err:

	if(payload_len)
		free(payload);

	return ret;
}

void destroy_payload(Work *w)
{
	if(w->length) {
		w->length = 0;
		free(w->payload);
	}
}

/*
 * Function: do_request(unsigned int, Packet *)
 *
 * Purpose: Send a message to the manager and then receive a valid reply. A 
 *          reply is valid if it has the same sequence number with the request
 *
 * Arguments: type => The type of the request to send
 *            pck  => the packet struct to fill
 *
 * Returns:  1 => Success
 *           0 => Critical Error
 *          -1 => Timed Out
 */
static int do_request(unsigned int type, Packet *pck)
{
	int ret;

	ret = send_pck(type);
	if(ret == 0) {
		fprintf(stderr, "server_request: Can't send request\n");
		return 0;
	}

	if((pck == NULL) || (type == SEND_QUIT)) {
		/* 
		 * If no Packet supplied or type is SEND_QUIT, then we don't
		 * expect an answer by the server (manager).
		 */
		return 1;
	}

	do {
		ret = recv_pck(pck);
		if(ret == -2) {
			/* I received garbage, I'll retry */
			proto_violation("Collected garbage. Retrying to receive"
					" the answer to the request...\n");
			continue;
		} else if(ret == 0) {
			/* 
			 * I don't think there is a point in trying.
			 * The agent itself should probably quit...
			 */
			return 0;
		} else if(ret == -1) {
			/*
			 * It timed out. I won't take the responsibility to
			 * do a retry. Let the higher level to choose.
			 */
			return -1;
		}
		
		/* 
		 * if we sent a connection package, 
		 * then there is no seq to check
		 */
		if(type == SEND_NEW_AGENT)
			return 1;
		/* 
		 * if we reached here, check the sequence number and do a retry
		 * if needed.
		 */
	} while(pck->seq != conn_info->seq);

	return 1;
}

static int handle_connect_reply(Packet *pck)
{
	switch(pck->type) {
	case RECV_CONNECTED:
		printf("Connected with ID %d\n", pck->id);
		/* save the new id and seq*/
		conn_info->id = pck->id;
		conn_info->seq = pck->seq;
		return 1;

	case RECV_NOT_CONN:
		/* the server does not connect us... */
		printf("Server rejected me.\n");
		return 0;

	default:
		proto_violation("Received unexpected packet type");
		destroy_payload(&pck->work);
		return -1;
	}
}

static int handle_newwork_reply(Packet *pck)
{
	destroy_payload(&conn_info->current);

	switch(pck->type) {
	case RECV_HEAD_DATA:
		/* Update current work info */
		memcpy(&conn_info->current, &pck->work, sizeof(Work));
		pck->work.length = 0;
		return 1;

	case RECV_NOT_FOUND:
		return 0;
	default:
		proto_violation("Received unexpected packet type");
		destroy_payload(&pck->work);
		return -1;
	}
}

static int handle_getnext_reply(Packet *pck)
{

	destroy_payload(&conn_info->current);

	switch(pck->type) {
	case RECV_DATA:
		/* Update current work info */
		conn_info->current.length = pck->work.length;
		conn_info->current.payload = pck->work.payload;

		return 1;
	case RECV_NOT_FOUND:
		return 0;
	default:
		proto_violation("Received unexpected packet type");
		destroy_payload(&pck->work);
		return -1;
	}
}

int server_request(int req_type)
{
	Packet pck;
	int ret;
	int retries_left = pv.retries;

	if((req_type > MAX_SEND_TYPE) || (req_type < 1)) {
		proto_violation("Unknown request type");
		return -1;
	}

	/* For a new request we need a new Sequence number */
	conn_info->seq++;

retry:
	ret = do_request(req_type, &pck);
	if(ret == 0)
		critical_error(1, "Unable to communicate with the manager");
	else if(ret == -1) {
		printf("timed out.\n");

		if(--retries_left) {
			printf("Retrying...\n");
			goto retry;
		}

		printf("No more retries left...\n");
		return -1;
	}

	printf("Request submitted\n");

	printf("Examining the reply...");

	switch(req_type) {
	case SEND_NEW_AGENT:
		ret = handle_connect_reply(&pck);
		break;
	case SEND_QUIT:
		printf("nothing to examin. We are quitting\n");
		ret = 1;
		break;
	case SEND_NEW_WORK:
		ret =  handle_newwork_reply(&pck);
		break;
	case SEND_GET_NEXT:
		ret = handle_getnext_reply(&pck);
		break;
	}

	if(ret >= 0)
		return ret;
	else {
		/* 
		 * I've got a protocol violation. Either someone is
		 * messing up with the packets or the manager went crazy.
		 * I'll retry. If this was a real server reply, then the
		 * server will send the same reply back or will ignore me.
		 */
		if(--retries_left) {
			printf("Retrying...\n");
			goto retry;
		}

		printf("No more retries left...\n");
		return -1;
	}
}

int init_conn_info(void)
{
	struct sigaction sa;

	conn_info = malloc(sizeof(ConnectionInfo));
	if(conn_info == NULL) {
		perror("malloc");
		return 0;
	}

	/* initialize the socket */
	conn_info->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (conn_info->sock == -1) {
		perror("socket");
		goto err;
	}

	conn_info->addr.sin_family = AF_INET;
	conn_info->addr.sin_port = pv.port;
	conn_info->addr.sin_addr = pv.addr;
	memset(&(conn_info->addr.sin_zero), '\0', 8);

	/* 
	 * They will be overwritten when we connect to the
	 * server, but I'll initialize them anyway.
	 */
	conn_info->seq = 0;
	conn_info->id = 0;

	memset(&conn_info->current, '\0', sizeof(Work));

	sa.sa_handler = sigalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGALRM, &sa, NULL) == -1) {
		perror("sigaction sigalarm");
		goto err;
	}

	return 1;

err:
	free(conn_info);
	return 0;
}

void destroy_conn_info(void)
{
	if(conn_info) {
		conn_info = NULL;
		free(conn_info);
	}
}

Work * fetch_current_work(void)
{
	return &conn_info->current;
}
