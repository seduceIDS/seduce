#ifndef _SERVER_CONTACT_H
#define _SERVER_CONTACT_H

#define PROTO_HDR_SIZE	16
#define PROTO_PWD_SIZE	16
#define PROTO_INFO_SIZE 16

/* send */
#define SEND_NEW_AGENT 1
#define SEND_NEW_WORK  2
#define SEND_GET_NEXT  3
#define SEND_QUIT      4

#define MAX_SEND_TYPE  4

/* receive */
#define RECV_CONNECTED 1
#define RECV_NOT_CONN  2
#define RECV_HEAD_DATA 3
#define RECV_DATA      4
#define RECV_NOT_FOUND 5

#define MAX_RECV_TYPE  5

#include <netinet/in.h> /* for struct in_addr */


typedef struct _Work {
	unsigned int proto;
	unsigned short s_port,d_port; /* In network byte order */
	unsigned int   s_addr,d_addr; /* In network byte order */
	char *payload;
	size_t length; /* payload length */
} Work;

typedef struct _Packet {
	unsigned int size;
	unsigned int type;
	unsigned int seq;
	unsigned int id;
	Work work;
} Packet;

typedef struct _ConnectionInfo {
	struct sockaddr_in addr;/* udp connection info */
	int sock; 		/* UDP Socket */
	unsigned int seq; 	/* Sequence Number */
	unsigned int id;	/* Agents ID */
	Work current;		/* Current Work */
} ConnectionInfo;

/* function Declarations */

Work *fetch_current_work(void);
int init_conn_info(void);
void destroy_conn_info(void);
int server_request(int req_type);

#endif /* _SERVER_CONTACT_H */
