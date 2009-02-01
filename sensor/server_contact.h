#ifndef _SERVER_CONTACT_H
#define _SERVER_CONTACT_H

#include <sys/types.h>  /* for size_t, u_short and u_int */
#include <netinet/in.h> /* for in_addr_t */

#ifndef _NIDS_NIDS_H
struct tuple4 /* for new_stream_connection and send_dgram_data */
{
	u_short source;
	u_short dest;
	u_int saddr;
	u_int daddr;
};
#endif


int manager_connect(int *sockfd, in_addr_t addr, unsigned short port);
int manager_disconnect(int sockfd);

int new_stream_connection(int sockfd, const struct tuple4 *conn, 
			  unsigned **id);
int close_stream_connection(int sockfd, unsigned *id);

int send_stream_data(int sockfd, unsigned id, const void *data, size_t len);
int stream_data_break(int sockfd, unsigned id);

int send_dgram_data(int sockfd, const struct tuple4 *conn, const void *data,
		    size_t len);

#endif /* _SERVER_CONTACT_H */
