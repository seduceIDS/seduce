#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <nids.h>
#include <confuse.h>

#include "sensor.h"

/* struct filled with command-line arguments */
typedef struct _CommandLineOptions {
	char *server;
	char *portlist_expr;
	char *homenet_expr;
	char *interface;
	char *conf_file;
} CLO;

static void hlpmsg(int rc)
{
	fprintf(stderr,"Type `%s -h' for help.\n", pv.prog_name);
	exit(rc);
}

static void printusage(int rc)
{
	fprintf(stderr, 
		"\nUsage:\n%s [-c <config_file>] [-h] [-i<interface>] "
		"[-n<home_network>] [-p<portlist>] [-s<server_address>]\n\n"
		"  h : Print this help message.\n"
		"  c : Specify a config file. `E.g. sensor.conf'.\n"
		"  i : Network interface. E.g. `eth0', `eth1'.\n"
		"  n : Home network in CIDR notation. E.g. `10.10.1.32/27'.\n"
		"  s : Server Address in HOST:Port format. "
		       "E.g. `localhost:3540'.\n"
		"  p : Portlist to sniff. E.g. `[1-80],T:6000,U:531'.\n\n",
		pv.prog_name);
	exit(rc);
}


/*
 * Parse the portlist string and fill the port table.
 * The source is from Nmap.
 * Return value: 
 * 	 1 on success
 * 	 0 if errors occure
 */
static int getpts(char *origexpr)
{
	int portwarning = 0; /* have we warned idiot about dup ports yet? */
  	long rangestart = -2343242, rangeend = -9324423;
	char * current_range;
	char *endptr;
	int range_type =0;
	int tcpportcount = 0, udpportcount = 0;

	/* first zero the port_table */
	memset(pv.port_table, '\0', 65536);

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
				/* Ended with a -, meaning up until the last
				 * possible port */
				rangeend = 65535;
			} else if (isdigit((int) *current_range)) {
				rangeend = strtol(current_range, &endptr, 10);
				if (rangeend <= 0 || rangeend > 65535)
					return 0;
				current_range = endptr;
			} else return 0;
		}else return 0;
		
		/* Now I have a rangestart and a rangeend,
		 * so I can add these ports */
		while (rangestart <= rangeend) {
			if (pv.port_table[rangestart] & range_type) {
				if (!portwarning) {
					printf("WARNING: Duplicate port number"
							    "(s) specified.\n");
					portwarning++;
				}
			} else {
				if (range_type & TCP_PORT)
					tcpportcount++;
				if (range_type & UDP_PORT)
					udpportcount++;
				pv.port_table[rangestart] |= range_type;
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


static int fill_network(char *network)
{
	if(nids_params.pcap_filter)
		free(nids_params.pcap_filter);

	nids_params.pcap_filter = malloc(strlen("net ") + strlen(network) + 1);
	if(nids_params.pcap_filter == NULL) {
		perror("malloc");
		return 0;
	}

	sprintf(nids_params.pcap_filter, "net %s", network);
	return 1;
}


static unsigned short get_valid_port(const char *port_str)
{
	int port;
	size_t size;
	int i;

	/* atoi does not detect errors */
	if (port_str == NULL)
		return 0;
	size = strlen(port_str);
	for(i = 0; i < size; i++)
		if(!isdigit(port_str[i])) {
			fprintf(stderr, "Port should be a number. ");
			return 0;
		}

	port = atoi(port_str);
	if (port <= 0 || port > 65535) {
		fprintf(stderr, "Port is not valid. "
				"Valid port range: [0-65535]. ");
		return 0;
	}

	return (unsigned short) port;
}


/* 
 * Fill the server IP and Port in the pv struct.
 * Returns 1 on success and 0 on error.
 */
static int fill_serveraddr(char *str)
{
	char *addr;
	char *port;
	struct hostent *he;

	addr = strtok(str, ":");
	if (addr == NULL)
		return 0;

	port = strtok(NULL,"");
	if (port == NULL)
		return 0;

	he = gethostbyname(addr);
	if(!he) {
		herror("gethostbyname");
		return 0;
	}
	pv.server_addr = *(in_addr_t *)he->h_addr;
	if(pv.server_addr == INADDR_NONE)
		return 0;

	pv.server_port = get_valid_port(port);
	if(pv.server_port == 0)
		return 0;

	return 1;
}


/* 
 * function wrapper to use it with libconfuse
 * as a validation function.
 */
static int cfg_validate(cfg_t *cfg, cfg_opt_t *opt)
{
	int ret;

	if (strcmp(opt->name, "server_addr") == 0)
		ret = fill_serveraddr(*(char **)opt->simple_value);
	else if (strcmp(opt->name, "portlist") == 0)
		ret = getpts(*(char **)opt->simple_value);
	else if (strcmp(opt->name, "home_net") == 0)
		ret = fill_network(*(char **)opt->simple_value);
	else
		ret = 0;

	if(!ret)
		cfg_error(cfg, "Error while parsing parameter `%s'.",
								opt->name);
	return (ret) ? 0 : -1;
}


/* parse a config file */
static int parse_file(char *filename)
{
	char *home_net = NULL;
	char *server_addr = NULL;
	char *portlist = NULL;
	int ret;

	cfg_opt_t opts[] = {
		CFG_SIMPLE_STR("interface", &nids_params.device),
		CFG_SIMPLE_STR("server_addr",&server_addr),
		CFG_SIMPLE_STR("home_net",&home_net),
		CFG_SIMPLE_STR("portlist",&portlist),
		CFG_SIMPLE_INT("n_tcp_streams", &nids_params.n_tcp_streams),
		CFG_SIMPLE_INT("n_hosts", &nids_params.n_hosts),
		CFG_SIMPLE_STR("filename", &nids_params.filename),
		CFG_SIMPLE_INT("sk_buff_size", &nids_params.sk_buff_size),
		CFG_SIMPLE_INT("dev_addon", &nids_params.dev_addon),
		CFG_SIMPLE_BOOL("promisc", &nids_params.promisc),
		CFG_SIMPLE_BOOL("one_loop_less", &nids_params.one_loop_less),
		CFG_SIMPLE_INT("pcap_timeout", &nids_params.pcap_timeout),
#if (NIDS_MINOR > 20)
		CFG_SIMPLE_BOOL("multiproc", &nids_params.multiproc),
		CFG_SIMPLE_INT("queue_limit", &nids_params.queue_limit),
		CFG_SIMPLE_BOOL("tcp_workarounds", &nids_params.tcp_workarounds),
#endif
		CFG_END()
	};
	cfg_t *cfg;

	cfg = cfg_init(opts, 0);

	/* set validation callback functions */
	cfg_set_validate_func(cfg,"server_addr",cfg_validate);
	cfg_set_validate_func(cfg,"portlist",cfg_validate);
	cfg_set_validate_func(cfg,"home_net",cfg_validate);

	ret = cfg_parse(cfg,filename);
	
	if(ret != CFG_SUCCESS) {
		if (ret == CFG_FILE_ERROR)
			fprintf(stderr, "Can't open config file for reading. "
				"Check the -c option again\n");
		cfg_free(cfg);
		return 0;
	}

	if(server_addr)
		free(server_addr);
	if(home_net)
		free(home_net);
	if(portlist)
		free(portlist);

	cfg_free(cfg);
	return 1;
}


/*
 * Get the command line options
 */
#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)
static int get_cloptions(int argc, char *argv[], CLO *clo)
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
			c_arg = 1;
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


void fill_progvars(int argc, char *argv[])
{
	int i;

	CLO clo;

	memset(&clo, '\0', sizeof(CLO));

	memset(&pv, '\0', sizeof(PV));
	pv.prog_name = argv[0];

	if(!get_cloptions(argc, argv, &clo))
		goto err;


	if(clo.conf_file) {
		if(!parse_file(clo.conf_file))
			goto err;
		free(clo.conf_file);
	}

	if(clo.server) {
		if(!fill_serveraddr(clo.server)) {
			fprintf(stderr, "Error while parsing `-s' option.\n");
			goto err;
		}
		free(clo.server);
	}

	if(clo.portlist_expr) {
		if(!getpts(clo.portlist_expr)) {
			fprintf(stderr, "Error while parsing `-p' option.\n");
			goto err;
		}
		free(clo.portlist_expr);
	}

	if(clo.homenet_expr) {
		if(!fill_network(clo.homenet_expr)) {
			fprintf(stderr, "Error while parsing `-n' option.\n");
			goto err;
		}
		free(clo.homenet_expr);
	}

	if(clo.interface) {
		if(nids_params.device)
			free(nids_params.device);
		nids_params.device = clo.interface;
	}

	/* Check if all needed program variables are set */
	if(pv.server_addr == 0 || pv.server_port == 0) {
		fprintf(stderr, "Manager connection info is missing. "
				"Either use the `-s' command line option "
				"or the `server_addr' variable of the "
				"configuration file.\n");
		goto err;
	}

	/* check if port list is set */
	for (i = 0; i < 65536; i++)
		if(pv.port_table[i] != 0)
			break;
	if (i == 65536)
		/* No port is set, I'll set them ports */
		memset(pv.port_table, TCP_PORT | UDP_PORT, 65536);

	return;

err:
	hlpmsg(1);
}


#if 0
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

PV pv;

int main(int argc, char *argv[])
{
	fill_progvars(argc, argv);

	printf("Options:\n");
	printf("Sever Address: %s\n", inet_ntoa(*(struct in_addr *)
							&pv.server_addr));
	printf("Server Port: %u\n", pv.server_port);

	return 0;
}
#endif
