#ifndef _MANAGER_PROTOCOL_H
#define _MANAGER_PROTOCOL_H

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

typedef struct _ConnectionInfo {
	unsigned int proto;
	unsigned short s_port,d_port;
	unsigned long  s_addr,d_addr;
} ConnectionInfo;

typedef struct _Work {
	ConnectionInfo info;
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

typedef struct _ManagerSession {
	struct sockaddr_in addr;/* udp connection info */
	int sock; 		/* UDP Socket */
	char * password;
	int retries;		/* number of allowed retries */
	int timeout;		/* Seconds to wait before timeout */
	unsigned int seq; 	/* Sequence Number */
	unsigned int id;	/* Agent ID */
	Work current;		/* Current Work */
} ManagerSession;

/* function Declarations */

ManagerSession *init_session(struct in_addr addr, unsigned short port,
			    const char *pwd, int timeout, int retries);

void destroy_session(ManagerSession **);

int manager_request(ManagerSession *, int req_type);
const Work *fetch_current_work(const ManagerSession *);
inline char *pwdcpy(const ManagerSession *, char *buf);

#endif /* _MANAGER_PROTOCOL_H */
