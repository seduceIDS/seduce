#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <nids.h>

#include "sensor.h"
#include "sniffer.h"
#include "server_contact.h"
#include "debug.h"

#define YES (1 == 1)
#define NO  (!YES)

extern int all_local_ipaddrs_chksum_disable(void);
extern void fill_progvars(int, char **);


/* our socket to the manager */
static int sockfd;

/*************Only for Debug purpose**********************/
# define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
char *adres (struct tuple4 addr)
{
	static char buf[256];

	strcpy (buf, int_ntoa (addr.saddr));
	sprintf (buf + strlen (buf), ",%i,", addr.source);
	strcat (buf, int_ntoa (addr.daddr));
	sprintf (buf + strlen (buf), ",%i", addr.dest);

	return buf;
}
/*********************************************************/

/*
 * TCP callback function for nids
 */
void tcp_sniff (struct tcp_stream *a_tcp, unsigned int **stream_id)
{
	struct half_stream *hlf;

	switch (a_tcp->nids_state) {
	case NIDS_JUST_EST:
		if (pv.port_table[a_tcp->addr.dest] & TCP_PORT) {
			if (new_stream_connection(sockfd, &a_tcp->addr,
						  stream_id, STREAM_DATA)) 
			{
				a_tcp->server.collect = YES;

				DPRINTF("Established a Connection:%s\n",
					adres(a_tcp->addr));
				DPRINTF("Sequence Number:%u\n", **stream_id);
			}
		}
		return;

	case NIDS_DATA:
		/* 
		 * I play with the client.collect value, so I can get
		 * informed by libnids when the server data I collect
		 * are not continuous any more. I don't want to collect
		 * client data but I want to know when client data start
		 * comming. When this happens, I stop collecting client
		 * data.
		 */
		if(a_tcp->client.count_new) {

			DPRINTF("Sending Break for Stream:%u\n", **stream_id);
			
			break_stream_data(sockfd, **stream_id);
			a_tcp->client.collect = NO;
			return;
		}
		/* data sent to the server */
		a_tcp->client.collect = YES;
		hlf = &a_tcp->server;
		send_stream_data(sockfd, **stream_id, hlf->data, 
				 hlf->count - hlf->offset);

		DPRINTF("New TCP DATA: %s\n",adres(a_tcp->addr));
		DPRINTF("Sequence Number:%u\n",**stream_id);
		DPRINTF("Data Pointer: %p\n", hlf->data);
		DPRINTF("Data Length: %d\n", hlf->count - hlf->offset);

		return;

	case NIDS_CLOSE:
	case NIDS_RESET:
	case NIDS_TIMED_OUT:
		DPRINTF("Connection %d is dying...\n",**stream_id);
		close_stream_connection(sockfd, *stream_id);
		return;
	}
}

/*
 * UDP callback function for libnids
 */
void udp_sniff (struct tuple4 *addr, u_char *data, int len, struct ip *pkt)
{
	if (pv.port_table[addr->dest] & UDP_PORT) {
		send_dgram_data(sockfd, addr, data, len, DGRAM_DATA);
		DPRINTF("New UDP DATA: %s\n",adres(*addr));
	}
}

int init_sniffer(void)
{
	/* disable libnids portscan detection feature */
	nids_params.scan_num_hosts = 0;

	/* I'm done with setting up the enviroment, now run libnids */
	if (!nids_init ()) {
		fprintf(stderr,"%s\n", nids_errbuf);
		return 0;
	}

	if ( all_local_ipaddrs_chksum_disable() == -1) {
		fprintf(stderr,"Error in all_local_ipaddrs_chksum_disable\n");
		return 0;
	}

	/* connect to the manager */
	if (manager_connect(&sockfd, pv.server_addr, pv.server_port) == 0) {
		fprintf(stderr,"Can't Connect to the Server\n");
		return 0;
	}

	return 1;
}

void start_sniffer(void)
{
	nids_register_tcp(tcp_sniff);
	nids_register_udp(udp_sniff);

	nids_run();
}

#if 0
int main(int argc, char *argv[])
{

	fill_progvars(argc, argv);


	/* This one is never executed */
	manager_disconnect(sockfd);
	return 0;
}
#endif
