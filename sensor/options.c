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
#include "../config.h"

/* struct filled with command-line arguments */
typedef struct _CommandLineOptions {
	char *portlist_expr;
	char *homenet_expr;
	char *interface;
	char *conf_file;
	char *agent_port;
	char *max_agents;
	char *mem_softlimit;
	char *mem_hardlimit;
	char *password;
} CLO;

/* 
 * The next value defines the acceptable port range for the agent server. The
 * values were not picked randomly. Actually to open a port which is in the
 * range 1-1024 you need root permission and manager is not supposed to be
 * running with root priveleges. On the other hand at least for the 2.6 version
 * of the linux kernel, the ephemeral port range is 32768-61000, so we picked
 * the inbetween to be the acceptable port range. Feel free to change the bellow
 * values.
 */
#define MIN_PORT_LIMIT 1025
#define MAX_PORT_LIMIT 32768

/* Defaults */
#define MAX_AGENTS	256
#define AGENT_PORT	28001 /* 28001-28239 are unassigned. If you care see: */
			      /* http://www.iana.org/assignments/port-numbers */

static void hlpmsg(int rc)
{
	fprintf(stderr,"Type `%s -h' for help.\n", pv.prog_name);
	exit(rc);
}

static void printusage(int rc)
{
	fprintf(stderr, 
		"%s v%s sensor\n"
		"Usage: %s [-h] [-c <config_file>] [-n<home_network>] "
		"[-i<interface>] [-p<portlist>] [-P<password>] [-a<agent_port>]"
		" [-A<max_agents>] [-l<mem_softlimit>] [-L<mem_hardlimit>] \n\n"
		"  h : Prints this help message.\n"
		"  c : Specify a config file. `E.g. sensor.conf'.\n"
		"  i : Network interface. E.g. `eth0', `eth1'.\n"
		"  n : Home network in CIDR notation. E.g. `10.10.1.32/27'.\n"
		"  p : Portlist to sniff. E.g. `[1-80],T:6000,U:531'.\n"
		"  P : Password for the agents (default: seduce).\n"
		"  a : Port to listen for agent requests (default: 28001).\n"
		"  A : Maximum number of agents allowed (default: 256).\n"
		"  l : Memory usage soft limit in Mb. E.g. `400'.\n"
		"  L : Memory usage hard limit in Mb. E.g. `390'.\n\n",
		PACKAGE_NAME, PACKAGE_VERSION, pv.prog_name);
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


static int fill_network(const char *network)
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

static int str_to_natural(const char *str)
{
	int natural = 0;
	size_t size;
	int i;

	if (str == NULL)
		return -1;

	size = strlen(str);
	for(i = 0; i < size; i++) {

		if(!isdigit(str[i]))
			return -1;
		
		natural = (natural * 10) + (str[i] - '0');
	}

	return natural;
}

static int get_valid_port(const char *str)
{
	int port = str_to_natural(str);
	if (port < 1)
		/* Maybe port is not a number at all */
		goto err;

	if (port < MIN_PORT_LIMIT || port > MAX_PORT_LIMIT)
		goto err;

	return port;
err:
	return 0;

}

static int validate_password(const char *pwd)
{
	return (strlen(pwd) > MAX_PWD_SIZE) ? 0 : 1;
}


/* 
 * function wrapper to use it with libconfuse
 * as a validation function.
 */
static int cfg_validate(cfg_t *cfg, cfg_opt_t *opt)
{
	int ret;

	if (strcmp(opt->name, "portlist") == 0) {
	
		ret = getpts(*(char **)opt->simple_value.string);

	} else if (strcmp(opt->name, "home_net") == 0) {

		ret = fill_network(*(char **)opt->simple_value.string);
	
	} else if (strcmp(opt->name, "agent_port") == 0) {

		if((*(int *)opt->simple_value.number < MIN_PORT_LIMIT) ||
                   (*(int *)opt->simple_value.number > MAX_PORT_LIMIT)) {

			cfg_error(cfg,"Valid agent ports: %d-%d\n",
					MIN_PORT_LIMIT, MAX_PORT_LIMIT);
			ret = 0;
		} else 
			ret = 1;
		
	} else if ((strcmp(opt->name, "max_agents") == 0)    ||
	           (strcmp(opt->name, "mem_softlimit") == 0) ||
	           (strcmp(opt->name, "mem_hardlimit") == 0)) {

		if((*(int *)opt->simple_value.number < 1)) {

			cfg_error(cfg, "'%s' must be at least 1", opt->name);
			
			ret = 0;
		} else
			ret = 1;

	} else if (strcmp(opt->name, "password") == 0) {

		if (!validate_password(*(char **)opt->simple_value.string)) {

			cfg_error(cfg, "Password can't be longer that %d "
					"characters", MAX_PWD_SIZE);
			ret = 0;
		} else
			ret = 1;
	} else
		/* should never reach here */
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
	char *portlist = NULL;
	int ret;

	cfg_opt_t opts[] = {
		CFG_SIMPLE_STR("interface", &nids_params.device),
		CFG_SIMPLE_STR("home_net",&home_net),
		CFG_SIMPLE_STR("portlist",&portlist),
		CFG_SIMPLE_INT("agent_port", &pv.agent_port),
		CFG_SIMPLE_INT("max_agents", &pv.max_agents),
		CFG_SIMPLE_INT("mem_softlimit", &pv.mem_softlimit),
		CFG_SIMPLE_INT("mem_hardlimit", &pv.mem_hardlimit),
		CFG_SIMPLE_STR("password", &pv.password),
	
		/* libnids params */
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
		CFG_SIMPLE_BOOL("tcp_workarounds",&nids_params.tcp_workarounds),
#endif
		CFG_END()
	};

	cfg_t *cfg = cfg_init(opts, 0);

	/* set validation callback functions */
	cfg_set_validate_func(cfg, "portlist", cfg_validate);
	cfg_set_validate_func(cfg, "home_net", cfg_validate);
	cfg_set_validate_func(cfg, "agent_port", cfg_validate);
	cfg_set_validate_func(cfg, "max_agents", cfg_validate);
	cfg_set_validate_func(cfg, "password", cfg_validate);
	cfg_set_validate_func(cfg, "mem_softlimit", cfg_validate);
	cfg_set_validate_func(cfg, "mem_hardlimit", cfg_validate);

	ret = cfg_parse(cfg,filename);
	if(ret != CFG_SUCCESS) {
		if (ret == CFG_FILE_ERROR)
			fprintf(stderr, "Can't open config file for reading. "
					"Check the -c option again\n");
		cfg_free(cfg);
		return 0;
	}

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
	fprintf(stderr, "The -%c option should be specified only once.\n", x)
static void get_cloptions(int argc, char *argv[], CLO *clo)
{
	int c;
	int c_arg = 0;
	int i_arg = 0;
	int n_arg = 0;
	int p_arg = 0;
	int P_arg = 0;
	int a_arg = 0;
	int A_arg = 0;
	int l_arg = 0;
	int L_arg = 0;

	while ((c = getopt (argc, argv, "hc:i:n:s:p:P:a:A:l:L:")) != -1) {
		switch(c) {
		case 'h':
			printusage(0);

		case 'c':
			if (c_arg) {
				PRINT_SPECIFY_ONCE('c');
				goto err;
			}
			c_arg =1;
			clo->conf_file = strdup(optarg);
			break;

		case 'i':
			if (i_arg) {
				PRINT_SPECIFY_ONCE('i');
				goto err;
			}
			i_arg = 1;
			clo->interface = strdup(optarg);
			break;

		case 'n':
			if (n_arg) {
				PRINT_SPECIFY_ONCE('n');
				goto err;
			}
			n_arg = 1;
			clo->homenet_expr = strdup(optarg);
			break;

		case 'p':
			if (p_arg) {
				PRINT_SPECIFY_ONCE('p');
				goto err;
			}
			p_arg = 1;
			clo->portlist_expr = strdup(optarg);
			break;

		case 'P':
			if (P_arg) {
				PRINT_SPECIFY_ONCE('P');
				goto err;
			}
			P_arg = 1;
			clo->password = strdup(optarg);
			break;

		case 'a':
			if (a_arg) {
				PRINT_SPECIFY_ONCE('a');
				goto err;
			}
			a_arg = 1;
			clo->agent_port = strdup(optarg);
			break;

		case 'A':
			if (A_arg) {
				PRINT_SPECIFY_ONCE('A');
				goto err;
			}
			A_arg = 1;
			clo->max_agents = strdup(optarg);
			break;

		case 'l':
			if (l_arg) {
				PRINT_SPECIFY_ONCE('l');
				goto err;
			}
			l_arg = 1;
			clo->mem_softlimit = strdup(optarg);
			break;

		case 'L':
			if (L_arg) {
				PRINT_SPECIFY_ONCE('L');
				goto err;
			}
			L_arg = 1;
			clo->mem_hardlimit = strdup(optarg);
			break;

		default:
			goto err;
		}
	}

	return;

err:
	hlpmsg(1);
}


void fill_progvars(int argc, char *argv[])
{
	int i;

	CLO clo;

	memset(&clo, '\0', sizeof(CLO));
	memset(&pv, '\0', sizeof(PV));
	pv.prog_name = argv[0];

	get_cloptions(argc, argv, &clo);

	if (clo.conf_file) {
		if(!parse_file(clo.conf_file))
			goto err;
		free(clo.conf_file);
	}

	if (clo.portlist_expr) {
		if(!getpts(clo.portlist_expr)) {
			fprintf(stderr, "Portlist expression is not valid. ");
			goto err;
		}
		free(clo.portlist_expr);
	}

	if (clo.homenet_expr) {
		if(!fill_network(clo.homenet_expr)) {
			fprintf(stderr, "Not a valid Home Network. ");
			goto err;
		}
		free(clo.homenet_expr);
	}

	if (clo.interface) {
		if(nids_params.device)
			free(nids_params.device);
		nids_params.device = clo.interface;
	}
	
	if (clo.agent_port) {
		if(!(pv.agent_port = get_valid_port(clo.agent_port))) {
			fprintf(stderr, "Valid agent ports: %d-%d. ",
						MIN_PORT_LIMIT, MAX_PORT_LIMIT);
			goto err;
		}
		free(clo.agent_port);
	} else if(!pv.agent_port)
		pv.agent_port = AGENT_PORT;

	if (clo.max_agents) {
		if((pv.max_agents = str_to_natural(clo.max_agents)) < 1) {
			fprintf(stderr, "Valid values for the maximum number of"
				    " allowed agents are positive integers.\n");
			goto err;
		}
		free(clo.max_agents);
	} else if(!pv.max_agents)
		pv.max_agents = MAX_AGENTS;

	if (clo.mem_softlimit) {
		if((pv.mem_softlimit = str_to_natural(clo.mem_softlimit)) < 1) {
			fprintf(stderr, "Not a valid soft limit value ");
			goto err;
		}
		free(clo.mem_softlimit);
	}

	if (clo.mem_hardlimit) {
		if((pv.mem_hardlimit = str_to_natural(clo.mem_hardlimit)) < 1) {
			fprintf(stderr, "Not a valid hard limit value ");
			goto err;
		}
		free(clo.mem_hardlimit);
	}

	if(clo.password) {
		if(!validate_password(clo.password)) {
			fprintf(stderr, "Password can't be longer than %d "
					"characters. ", MAX_PWD_SIZE);
			goto err;
		}
		if(pv.password)
			free(pv.password);

		pv.password = clo.password;
	}

	/* sanity checks */
	if(!pv.password) {
		fprintf(stderr, "Password is not set. ");
		goto err;
	}

	if(!pv.mem_softlimit || !pv.mem_hardlimit) {
		fprintf(stderr, "Memory limits are not set. ");
		goto err;
	}

	if(pv.mem_softlimit > pv.mem_hardlimit) {
		fprintf(stderr, "Memory soft limit cannot be greater than the "
			        "memory hard limit\n");
		goto err;
	}

	/* OK, now convert the limits from MB to bytes */
	pv.mem_hardlimit <<= 20;
	pv.mem_softlimit <<= 20;

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
	printf("Agent Port: %d\n", pv.agent_port);
	printf("Max Agents: %d\n", pv.max_agents);
	printf("Soft limit: %d\n", pv.mem_softlimit);
	printf("Hard limit: %d\n", pv.mem_hardlimit);
	printf("Password:   %s\n", pv.password);

	return 0;
}
#endif
