#ifndef _AGENT_H
#define _AGENT_H

#define UDP_SIZE	16

/* send */
#define UDP_NEW_AGENT htonl(1)
#define UDP_NEW_WORK  htonl(2)
#define UDP_GET_NEXT  htonl(3)
#define UDP_GET_PREV  htonl(4)
#define UDP_QUIT      htonl(5)

/* receive */
#define UDP_CONNECTED htonl(1)
#define UDP_NOT_CONN  htonl(2)
#define UDP_DATA      htonl(3)
#define UDP_NOT_FOUND htonl(4)

#include <stdlib.h>


typedef struct _Work {
	unsigned int proto;
	unsigned short s_port,d_port;
	unsigned int   s_addr,d_addr;
	char *payload;
	size_t payload_len;
} Work;

typedef struct _Packet {
	unsigned int size;
	unsigned int sec;
	unsigned int type;
	unsigned int id;
	Work *work;
} Packet;

typedef struct _Session {
	int fd;
	struct sockaddr_in *addr;
	unsigned int sec;
	unsigned int id;
} Session;


#endif /* _AGENT_H */
