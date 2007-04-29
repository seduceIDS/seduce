#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <nids.h>
#include "server_contact.h"
#include "errors.h"


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

extern int all_local_ipaddrs_chksum_disable(void);

/* struct filled with command-line arguements */
static struct {
	in_addr_t server_addr ;	/* Server IP Address */
	unsigned short	  server_port ; /* Server Port in Host Byte Order */
	unsigned char port_tbl[65536];
} args;

static unsigned int get_new_id(void)
{
	static unsigned int next_id=1;

	if (next_id == 0) next_id = 1;

	return next_id++;
}

static unsigned int *init_stream(void)
{
	unsigned int *stream_id;
	
	stream_id = malloc(sizeof(unsigned int));
	if ( stream_id == NULL)	return NULL;

	*stream_id =  get_new_id();
	return stream_id;
}


#define TCP_PORT	1
#define UDP_PORT	2

void tcp_sniff (struct tcp_stream *a_tcp, unsigned int **stream_id)
{
	struct half_stream *hlf;
	
	switch (a_tcp->nids_state) {
		case NIDS_JUST_EST:
			if ( args.port_tbl[a_tcp->addr.dest] & TCP_PORT ) {
				if ( (*stream_id = init_stream()) ) {
					a_tcp->server.collect++;
					new_tcp_connection(**stream_id, &a_tcp->addr);
					DPRINTF(("Established a Connection: %s\n", adres(a_tcp->addr)));
					DPRINTF(("Sequence Number:%u\n",**stream_id));
				}
			}
			return;
	
		case NIDS_DATA:
			hlf = &a_tcp->server;
			send_tcp_data(**stream_id, hlf->data, hlf->count - hlf->offset);
			DPRINTF(("New TCP DATA: %s\n",adres(a_tcp->addr)));
			DPRINTF(("Sequence Number:%u\n",**stream_id));
			DPRINTF(("Data Pointer: %p\n", hlf->data));
			DPRINTF(("Data Length: %d\n", hlf->count - hlf->offset));
			return;

		case NIDS_CLOSE:
		case NIDS_RESET:
		case NIDS_TIMED_OUT:
			DPRINTF(("Connection %d is dying...\n",**stream_id));
			close_tcp_connection(**stream_id);
			free(*stream_id);
			return;

	}
}

void udp_sniff (struct tuple4 *addr, u_char *data, int len, struct ip *pkt)
{
	if ( args.port_tbl[addr->dest] & UDP_PORT ) {
		send_udp_data(addr, data, len, get_new_id());
		DPRINTF(("New UDP DATA: %s\n",adres(*addr)));
	}
}


static unsigned short get_valid_port(char *port_str)
{
	int port;

	/* atoi does not detect errors */
	if (port_str == NULL)
		return 0;
		
	port = atoi(port_str);
	if (port <= 0 || port > 65535)
		return 0;

	return (unsigned short) port;
}

#define TCP_PORT	1
#define UDP_PORT	2

/*
 * Parse the portlist option and fill the 
 * port table (port_tbl) in the args struct.
 *
 * The source is from Nmap
 */

int getpts(char *origexpr)
{
	int portwarning = 0; /* have we warned idiot about dup ports yet? */
  	long rangestart = -2343242, rangeend = -9324423;
	char * current_range;
	char *endptr;
	int range_type =0;
	int tcpportcount = 0, udpportcount = 0;

	range_type |= TCP_PORT;
	range_type |= UDP_PORT;
	current_range = origexpr;
	do {
		/* I don't know why I should allow spaces here, but I will */
		while (isspace((int) *current_range))
			current_range++;

		if (*current_range == 'T' && *++current_range == ':') {
			current_range++;
			range_type = TCP_PORT;
			continue;
    		}
    		if (*current_range == 'U' && *++current_range == ':') {
			current_range++;
			range_type = UDP_PORT;
			continue;
		}


		if (*current_range == '-') {
      			rangestart = 1;
		} else if (isdigit((int) *current_range)) {
			rangestart = strtol(current_range, &endptr, 10);
			if (rangestart <= 0 || rangestart > 65535)
				return 0;
      			current_range = endptr;
      			while (isspace((int) *current_range))
				current_range++;

    		} else return 0;
		
		
		/* Now I have a rangestart, time to go after rangeend */
    		if (!*current_range || *current_range == ',') {
			/* Single port specification */
			rangeend = rangestart;
		} else if (*current_range == '-') {
			current_range++;
			if (!*current_range || *current_range == ',') {
				/* Ended with a -, meaning up until the last possible port */
				rangeend = 65535;
			} else if (isdigit((int) *current_range)) {
				rangeend = strtol(current_range, &endptr, 10);
				if (rangeend <= 0 || rangeend > 65535)
					return 0;
				current_range = endptr;
			} else return 0;
		}else return 0;
		
		/* Now I have a rangestart and a rangeend, so I can add these ports */
		while (rangestart <= rangeend) {
			if (args.port_tbl[rangestart] & range_type) {
				if (!portwarning) {
					printf("WARNING: Duplicate port number(s) specified.\n");
					portwarning++;
				}
			} else {
				if (range_type & TCP_PORT)
					tcpportcount++;
				if (range_type & UDP_PORT)
					udpportcount++;
				args.port_tbl[rangestart] |= range_type;
			}
			rangestart++;
		}
		
		/* Find the next range */
		while (isspace((int) *current_range))
			current_range++;

		if (*current_range && *current_range != ',')
			return 0;
		
		if (*current_range == ',')
			current_range++;

	} while (current_range && *current_range);

	if (0 == (tcpportcount + udpportcount)) {
		/* No Ports specified */
		return 0;
	}

	/* No errors... */
	return 1;
}


static int get_args(int argc, char *argv[])
{
	int c;
	int s_arg=0, p_arg=0, i_arg=0, n_arg=0;
	char *s_value, *p_value;
	char *addr, *port;

	memset(args.port_tbl,0,65536);

	while ((c = getopt (argc, argv, "hi:n:s:p:")) != -1) {
		switch(c) {
			case 'h':
				return 0;

			case 'i':
				if (i_arg) {
					fprintf(stderr, "The -i option should be specified only once\n");
					return 0;
				}
				i_arg = 1;
				nids_params.device = strdup(optarg);
				break;

			case 'n':
				if (n_arg) {
					fprintf(stderr, "The -n option should be specified only once\n");
					return 0;
				}
				n_arg = 1;
				if (strlen(optarg) > 18) {
					/* XXX.XXX.XXX.XXX/XX = 18 chars */
					fprintf(stderr, "Invalid -n option. Use CIDR notation\n");
					return 0;
				}
				nids_params.pcap_filter = malloc(strlen(optarg) + strlen("net "));
				sprintf(nids_params.pcap_filter,"net %s",optarg);
				break;

			case 's':
				if (s_arg) {
					fprintf(stderr, "The -s option should be specified only once\n");
					return 0;
				}

				s_arg = 1;
				s_value = strdup(optarg);
				addr = strtok(s_value,":");
				if ((args.server_addr = inet_addr(addr)) != INADDR_NONE) {
					port = strtok(NULL,"");
					if ((args.server_port = get_valid_port(port)) != 0) {
						free(s_value);
						break;
					}
				}
				fprintf(stderr, "Not a valid -s option\n");
				return 0;

			case 'p':
				if (p_arg) {
					fprintf(stderr,"Only 1 -p option allowed, separate multiple ranges with commas\n");
					return 0;
				}

				p_arg = 1;
				p_value = strdup(optarg);
				if (getpts(p_value) == 0) {
					fprintf(stderr, "Not a valid -p option\n");
					return 0;
				}	
				break;
			default:
				return 0;
		}
	}

	if (s_arg == 0) {
		fprintf(stderr, "At least -s must be specified\n");
		return 0;
	}

	/*if no portlist specified then we'll sniff them all */
	if (p_arg == 0)
		memset(args.port_tbl,TCP_PORT | UDP_PORT,65536);

	return 1;
}

static void printusage(int rc)
{
	fprintf(stderr, 
		"usage: sensor [-h] [-i<interface>] [-n<home_network>] -s<server_address> [-p<portlist>]\n\n"
		"  h : Print this help message.\n"
		"  i : Network interface. E.g. `eth0', `eth1'.\n"
		"  n : Home network in CIDR notation. E.g. `10.10.1.32/27'.\n"
		"  s : Server Address in IP:port format. E.g. `12.0.0.1:3540'.\n"
		"  p : Portlist to sniff. E.g. `[1-80],T:6000,U:531'.\n\n");
	exit(rc);
}


int main(int argc, char *argv[])
{
	if (get_args(argc, argv) == 0)
		printusage(1);
		
	if (!nids_init ()) {
		fprintf(stderr,"%s\n", nids_errbuf);
		exit(1);
	}

	if ( all_local_ipaddrs_chksum_disable() == -1) {
		fprintf(stderr,"Error in all_local_ipaddrs_chksum_disable\n");
		exit(1);
	}

	/* connect to the scheduler */
	if (server_connect(args.server_addr, args.server_port) == 0) {
		fprintf(stderr,"Can't Connect to the Server\n");
		exit(1);
	}

	nids_register_tcp(tcp_sniff);
	nids_register_udp(udp_sniff);

	nids_run();

	/* This one is never executed */
	return 0;
}
