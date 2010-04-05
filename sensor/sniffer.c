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

#include "sniffer.h"
#include "sensor.h"
#include "sensor_contact.h"
#include "utils.h"

extern int all_local_ipaddrs_chksum_disable(void);

/* 
 * Returns the next available ID
 */
static unsigned int get_new_id(void)
{
	static unsigned int next_id = 1;

	if (next_id == 0)
		next_id = 1;

	return next_id++;
}


/*
 * Initialize a new stream
 */
static unsigned *init_stream(void)
{
	unsigned int *stream_id;
	
	stream_id = malloc(sizeof(unsigned));
	if (stream_id == NULL)
		return NULL;

	*stream_id = get_new_id();
	return stream_id;
}

/*
 * TCP callback function for nids
 */
static void tcp_sniff (struct tcp_stream *a_tcp, unsigned **stream_id)
{
	struct half_stream *hlf;
	
	switch (a_tcp->nids_state) {
	case NIDS_JUST_EST:
		if ((pv.port_table[a_tcp->addr.dest] & TCP_PORT)) {

			*stream_id = init_stream();
			if (*stream_id == NULL) {
				fprintf(stderr, "Memory allocation failed\n");
				/* Let's not exit and see what happens... */
				return;
			}

			a_tcp->server.collect = YES;

			DPRINTF("New Connection: (%u)\n", **stream_id);
			DPRINT_TUPLE4(&a_tcp->addr);
			new_tcp(**stream_id, &a_tcp->addr);
		}
		return;

	case NIDS_DATA:
		/* 
		 * I play with the client.collect value, so I can get
		 * informed by libnids when the server data I collect
		 * are not continuous any more. I don't want to collect
		 * client data but I want to know when client data start
		 * comming. When this happens, I stop collecting them.
		 */
		if (a_tcp->client.count_new) {
			a_tcp->client.collect = NO;
			
			tcp_break(**stream_id);

			DPRINTF("Sending Break for Stream:%u\n", **stream_id);
		} else {
			a_tcp->client.collect = YES;
			
			hlf = &a_tcp->server;
			size_t len =  hlf->count - hlf->offset; 
			tcp_data(**stream_id, hlf->data, len);

			DPRINTF("New TCP DATA (%u):\n",**stream_id);
			DPRINT_TUPLE4(&a_tcp->addr);
			DPRINTF("Data Pointer: %p\n", hlf->data);
			DPRINTF("Data Length: %d\n", len);
		}
		return;

	case NIDS_CLOSE:
	case NIDS_RESET:
	case NIDS_TIMED_OUT:
		close_tcp(**stream_id);
		
		DPRINTF("Connection %d is dying...\n",**stream_id);
		
		free(*stream_id);
		return;
	}
}

/*
 * UDP callback function for libnids
 */
static void udp_sniff(struct tuple4 *addr, u_char *data, int len,struct ip *pkt)
{
	if (pv.port_table[addr->dest] & UDP_PORT) {

		udp_data(addr, data, len, get_new_id());
		
		DPRINTF("New UDP DATA:\n");
		DPRINT_TUPLE4(addr);
	}
}

int init_sniffer(void)
{
	/* disable libnids portscan detection feature */
	nids_params.scan_num_hosts = 0;

	/* initialize libnids */
	if (!nids_init ()) {
		fprintf(stderr,"libnids: %s\n", nids_errbuf);
		return 0;
	}
	
	if (all_local_ipaddrs_chksum_disable() == -1) {
		fprintf(stderr, "Error in all_local_ipaddrs_chksum_disable\n");
		return 0;
	}

	nids_register_tcp(tcp_sniff);
	nids_register_udp(udp_sniff);

	return 1;
}

void start_sniffer(void)
{
	nids_run();
}

