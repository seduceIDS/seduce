#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <nids.h>

#include "sensor.h"
#include "server_contact.h"
#include "debug.h"

#define YES (1 == 1)
#define NO  (!YES)

extern int all_local_ipaddrs_chksum_disable(void);
extern int parse_options(CommandLineOptions *);

/* GLOBALS */
PV pv;

static void printusage(int rc)
{
	fprintf(stderr, 
		"usage: %s [-c <config_file>] [-h] [-i<interface>] "
		"[-n<home_network>] [-p<portlist>] [-s<server_address>]\n\n"
		"  c : Specify a config file. `E.g. sensor.conf'.\n"
		"  h : Print this help message.\n"
		"  i : Network interface. E.g. `eth0', `eth1'.\n"
		"  n : Home network in CIDR notation. E.g. `10.10.1.32/27'.\n"
		"  s : Server Address in IP:Port format. E.g. `12.0.0.1:3540'.\n"
		"  p : Portlist to sniff. E.g. `[1-80],T:6000,U:531'.\n\n",
		pv.prog_name);
	exit(rc);
}


/*
 * Get the command line options
 */
#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)
static int get_clo(int argc, char *argv[], CommandLineOptions *clo)
{
	int c;
	int c_arg = 0;
	int i_arg = 0;
	int n_arg = 0;
	int s_arg = 0;
	int p_arg = 0;

	while ((c = getopt (argc, argv, "hc:i:n:s:p:")) != -1) {
		switch(c) {
			case 'h':
				printusage(0);

			case 'c':
				if (c_arg) {
				PRINT_SPECIFY_ONCE('c');
				return 0;
				}
				clo->conf_file = strdup(optarg);
				break;

			case 'i':
				if (i_arg) {
					PRINT_SPECIFY_ONCE('i');
					return 0;
				}
				i_arg = 1;
				clo->interface = strdup(optarg);
				break;

			case 'n':
				if (n_arg) {
					PRINT_SPECIFY_ONCE('n');
					return 0;
				}
				n_arg = 1;
				clo->homenet_expr = strdup(optarg);
				break;

			case 's':
				if (s_arg) {
					PRINT_SPECIFY_ONCE('s');
					return 0;
				}

				s_arg = 1;
				clo->server =  strdup(optarg);
				break;

			case 'p':
				if (p_arg) {
					PRINT_SPECIFY_ONCE('p');
					return 0;
				}
				p_arg = 1;
				clo->portlist_expr = strdup(optarg);
				break;

			default:
				return 0;
		}
	}

	return 1;
}


/* 
 * Returns the next available ID
 */
static unsigned int get_new_id(void)
{
	static unsigned int next_id=1;

	if (next_id == 0) next_id = 1;

	return next_id++;
}


/*
 * Initialize a new stream
 */
static unsigned int *init_stream(void)
{
	unsigned int *stream_id;
	
	stream_id = malloc(sizeof(unsigned int));
	if ( stream_id == NULL)	return NULL;

	*stream_id =  get_new_id();
	return stream_id;
}



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
				if ((*stream_id = init_stream())) {
					a_tcp->server.collect = YES;
					new_tcp_connection(**stream_id,
							&a_tcp->addr);
					DPRINTF("Established a Connection:%s\n",
							adres(a_tcp->addr));
					DPRINTF("Sequence Number:%u\n",
								**stream_id);
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
				DPRINTF("Sending Break for Stream:%u\n",
								**stream_id);
				tcp_data_break(**stream_id);
				a_tcp->client.collect = NO;
				return;
			}
			/* data sent to the server */
			a_tcp->client.collect = YES;
			hlf = &a_tcp->server;
			send_tcp_data(**stream_id, hlf->data,
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
			close_tcp_connection(**stream_id);
			free(*stream_id);
			return;
	}
}

/*
 * UDP callback function for libnids
 */
void udp_sniff (struct tuple4 *addr, u_char *data, int len, struct ip *pkt)
{
	if (pv.port_table[addr->dest] & UDP_PORT) {
		send_udp_data(addr, data, len, get_new_id());
		DPRINTF("New UDP DATA: %s\n",adres(*addr));
	}
}

int main(int argc, char *argv[])
{
	CommandLineOptions *clo;

	/* Clear the program variable struct */
	memset(&pv, '\0', sizeof(pv));
	pv.prog_name = argv[0];

	clo = calloc(1, sizeof(CommandLineOptions));
	if(clo == NULL) {
		perror("malloc");
		exit(0);
	}

	if (get_clo(argc, argv, clo) == 0)
		printusage(1);

	if(parse_options(clo) == 0)
		printusage(1);

	free(clo);

	/* disable libnids portscan detection feature */
	nids_params.scan_num_hosts = 0;

	/* I'm done with setting up the enviroment, now run libnids */
	if (!nids_init ()) {
		fprintf(stderr,"%s\n", nids_errbuf);
		exit(1);
	}

	if ( all_local_ipaddrs_chksum_disable() == -1) {
		fprintf(stderr,"Error in all_local_ipaddrs_chksum_disable\n");
		exit(1);
	}

	/* connect to the scheduler */
	if (server_connect(pv.server_addr, pv.server_port) == 0) {
		fprintf(stderr,"Can't Connect to the Server\n");
		exit(1);
	}

	nids_register_tcp(tcp_sniff);
	nids_register_udp(udp_sniff);

	nids_run();

	/* This one is never executed */
	return 0;
}
