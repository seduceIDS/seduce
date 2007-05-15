#ifndef _AGENT_H
#define _AGENT_H

#define MIN_UDP_SIZE	16
#define MAX_PWD_SIZE	16

/* send */
#define SEND_NEW_AGENT 1
#define SEND_NEW_WORK  2
#define SEND_GET_NEXT  3
#define SEND_QUIT      4

/* receive */
#define RECV_CONNECTED 1
#define RECV_NOT_CONN  2
#define RECV_DATA      3
#define RECV_NOT_FOUND 4

#include <netinet/in.h> /* for struct in_addr */


typedef struct _Work {
	unsigned int proto;
	unsigned short s_port,d_port;
	unsigned int   s_addr,d_addr;
	char *payload;
	size_t payload_len;
} Work;

typedef struct _Packet {
	unsigned int size;
	unsigned int seq;
	unsigned int type;
	unsigned int id;
	Work *work;
} Packet;

typedef struct _ProgVars {
	char *prog_name;		/* program name */
	int socket;			/* udp socket */
	struct sockaddr_in addr;	/* udp connection info */
	unsigned int seq;		/* sequence number */
	unsigned int id;		/* agents ID */
	char *password;			/* Connection password */
	int timeout;			/* timeout value */
	int retries;			/* Number of allowed retries */
	int no_work_wait;		/* Time to wait when there is
					   no work available */
} PV;

extern PV pv;

/* definitions */
void copy_password(char *);

#endif /* _AGENT_H */
