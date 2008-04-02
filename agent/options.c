#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <confuse.h>

#include "agent.h"

static void printusage(int rc)
{
	fprintf(stderr, 
		"Usage: %s [-c <config_file>] [-h] [-p<password>] "
		"[-r<retries>] [-s<senver_address]> [-t<timeout>] "
		"[-w<no_work_wait>]\n\n"
		"  c : Specify a config file. `E.g. agent.conf'.\n"
		"  h : Print this help message.\n"
		"  p : Password to use to connecting with the scheduler.\n"
		"  r : Maximum numbers of times to retry when sending a "
		      "request to the scheduler.\n"
		"  s : Server Address in Hostname:Port format. "
		      "E.g. `12.0.0.1:3540'.\n"
		"  t : Time in sec to wait for an answer by the scheduler.\n"
		"  w : Time in sec to wait before requesting again when the "
		      "scheduler has no work available\n\n",
		pv.prog_name);
	exit(rc);
}

static int str_to_natural(const char *str)
{
	int natural;
	size_t size;
	int i;

	if (str == NULL)
		return -1;

	size = strlen(str);
	for(i=0; i < size; i++)
		if(!isdigit(str[i]))
			return -1;

	natural = atoi(str);
	if (natural < 0)
		return -1;

	return natural;
}

static int get_valid_retries(const char *str)
{
	int retries;

	retries = str_to_natural(str);

	if(retries < 0) {
		fprintf(stderr, "the retries value is not valid\n");
		return -1;
	}

	return retries;
}

static unsigned short get_valid_port(const char *str)
{
	unsigned int port;

	port = str_to_natural(str);

	if(port <= 1 || port > 65535) {
		fprintf(stderr,"Not a valid port number\n");
		return 0;
	}

	return (unsigned short) htons(port);
}

static int get_valid_timeout(const char *str)
{
	int timeout;

	timeout = str_to_natural(str);
	if (timeout < 0) {
		fprintf(stderr, "The timeout value is not valid\n");
		return -1;
	}

	return timeout;
}

static int get_valid_no_work_wait(const char *str)
{
	int no_work_wait;

	no_work_wait = str_to_natural(str);
	if (no_work_wait < 0) {
		fprintf(stderr, "The no_work_wait value is not valid\n");
		return -1;
	}

	return no_work_wait;
}



static int validate_password(const char *pwd)
{
	size_t size;

	size = strlen(pwd);
	if(size > MAX_PWD_SIZE) {
		fprintf(stderr,"Password cannot be longer that %d characters\n",
				MAX_PWD_SIZE);
		return 0;
	}

	return 1;
}

static int fill_serverinfo(const char *serverinfo, struct in_addr *addr,
							unsigned short *port)
{
	char *tmp;
	char *port_str;
	char *host_str;
	struct hostent *he;

	tmp = strdup(serverinfo);
	if(!tmp)
		return 0;

	host_str = strtok(tmp,":");
	port_str = strtok(NULL,"");

	if(!(*port = get_valid_port(port_str)))
		goto err;


	if((he = gethostbyname(host_str)) == NULL) {
		herror("gethostbyname");
		goto err;
	}

	*addr = *((struct in_addr *)he->h_addr);

	free(tmp);
	return 1;

err:
	free(tmp);
	return 0;
}

#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)
int get_cloptions(int argc, char *argv[], ProgVars *clo)
{
	int c;
	int c_arg = 0;
	int p_arg = 0;
	int r_arg = 0;
	int s_arg = 0;
	int t_arg = 0;
	int w_arg = 0;


	while ((c = getopt (argc, argv, "hc:p:r:s:t:w:")) != -1) {
		switch(c) {
		case 'h':
			printusage(0);
			break;

		case 'c':
			if(c_arg) {
				PRINT_SPECIFY_ONCE('c');
				return 0;
			}
			clo->config_file = strdup(optarg);
			break;

		case 'p':
			if(p_arg) {
				PRINT_SPECIFY_ONCE('p');
				return 0;
			}
			clo->password = strdup(optarg);
			if(!validate_password(clo->password))
				return 0;
			break;

		case 'r':
			if(r_arg) {
				PRINT_SPECIFY_ONCE('r');
				return 0;
			}
			clo->retries = get_valid_retries(optarg);
			if (clo->retries == -1)
				return 0;
			break;

		case 's':
			if(s_arg) {
				PRINT_SPECIFY_ONCE('s');
				return 0;
			}
			if(!fill_serverinfo(optarg, &clo->addr, &clo->port))
				return 0;
			break;

		case 't':
			if(t_arg) {
				PRINT_SPECIFY_ONCE('t');
				return 0;
			}
			clo->timeout = get_valid_timeout(optarg);
			if (clo->timeout == -1)
				return 0;
			break;

		case 'w':
			if(w_arg) {
				PRINT_SPECIFY_ONCE('w');
				return 0;
			}
			clo->no_work_wait = get_valid_no_work_wait(optarg);
			if (clo->no_work_wait == -1)
				return 0;
			break;

		default:
			printusage(1);
		}
	}

	return 1;
}

static int cfg_validate(cfg_t *cfg, cfg_opt_t *opt)
{
	int ret;

	if (strcmp(opt->name, "server_addr") == 0)
		ret = fill_serverinfo(*(char **)opt->simple_value,
					&pv.addr, &pv.port);
	else if (strcmp(opt->name, "password") == 0)
		ret = validate_password(*(char **)opt->simple_value);
	else if (strcmp(opt->name, "timeout") == 0)
		ret = (*(int **)opt->simple_value < 0) ? 0 : 1;
	else if (strcmp(opt->name, "retries") == 0)
		ret = (*(int **)opt->simple_value < 0) ? 0 : 1;
	else if (strcmp(opt->name, "no_work_wait") == 0)
		ret = (*(int **)opt->simple_value < 0) ? 0 : 1;
	else
		ret = 0;

	if(!ret)
		cfg_error(cfg, "Error while parsing parameter \"%s\".",
								opt->name);
	return (ret) ? 0 : -1;
}


static int parse_fileoptions(char *filename)
{
	char *server_addr = NULL;
	int ret;

	cfg_opt_t opts[] = {
		CFG_SIMPLE_STR("server_addr",&server_addr),
		CFG_SIMPLE_STR("password",&pv.password),
		CFG_SIMPLE_INT("timeout",&pv.timeout),
		CFG_SIMPLE_INT("retries",&pv.retries),
		CFG_SIMPLE_INT("no_work_wait",&pv.no_work_wait),
		CFG_END()
	};

	cfg_t *cfg;

	cfg = cfg_init(opts,0);

	/* set validation callback functions */
	cfg_set_validate_func(cfg,"server_addr",cfg_validate);
	cfg_set_validate_func(cfg,"password",cfg_validate);
	cfg_set_validate_func(cfg,"timeout",cfg_validate);
	cfg_set_validate_func(cfg,"retries",cfg_validate);
	cfg_set_validate_func(cfg,"no_work_wait",cfg_validate);

	ret = cfg_parse(cfg,filename);
	
	if(ret != CFG_SUCCESS) {
		if (ret == CFG_FILE_ERROR)
			fprintf(stderr, "Can't open config file %s\n",filename);
		cfg_free(cfg);
		printusage(1);
	}

	if(server_addr)
		free(server_addr);

	cfg_free(cfg);
	return 1;
}


void fill_progvars(int argc, char *argv[])
{
	int ret;
	ProgVars clo; /* temporary struct to store the command line options */

	memset(&pv, '\0', sizeof(ProgVars));
	pv.prog_name = argv[0];
	pv.timeout = -1;
	pv.retries = -1;
	pv.no_work_wait = -1;

//	pv.addr.sin_family = AF_INET;
//	memset(pv.addr.sin_zero, '\0', 8);

	memset(&clo, '\0', sizeof(ProgVars));
	clo.timeout = -1;
	clo.retries = -1;
	clo.no_work_wait = -1;
	
	ret = get_cloptions(argc, argv, &clo);
	if (!ret)
		printusage(1);

	if(clo.config_file)
		ret = parse_fileoptions(clo.config_file);
	if(!ret)
		exit(1);

	if(clo.port) {
		pv.port = clo.port;
		pv.addr = clo.addr;
	}

	if(clo.password) {
		if(pv.password)
			free(pv.password);
		pv.password = clo.password;
	}

	/* 
	 * if timeout and retries are not set
	 * from the command line or the config file,
	 * we set the default values
	 */
	if(clo.timeout != -1)
		pv.timeout = clo.timeout;
	else if(pv.timeout == -1)
		pv.timeout = DEFAULT_TIMEOUT;

	if(clo.retries != -1)
		pv.retries = clo.retries;
	else if(pv.retries == -1)
		pv.retries = DEFAULT_RETRIES;

	if(clo.no_work_wait != -1)
		pv.no_work_wait = clo.no_work_wait;
	else if(pv.no_work_wait == -1)
		pv.no_work_wait = DEFAULT_NO_WORK_WAIT;

	/* 
	 * Now that command line and config file options are set,
	 * check if a required option is missing.
	 * Required options are the connection info (IP/port & password)
	 */
	if(!pv.port) {
		fprintf(stderr, "Server address and port are not set\n");
		printusage(1);
	}

	if(!pv.password) {
		fprintf(stderr, "No server password is set\n");
		printusage(1);
	}
}

#if 0

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

ProgVars pv;

int main(int argc, char *argv[])
{
	fill_progvars(argc, argv);

	printf("Options:\n");
	printf("Sever Address: %s\n", inet_ntoa(pv.addr));
	printf("Server Port: %u\n", ntohs(pv.port));
	printf("Password: %s\n", pv.password);
	printf("Timeout: %d\n", pv.timeout);
	printf("Retries: %d\n", pv.retries);
	printf("No Work Wait: %d\n", pv.no_work_wait);

	return 0;
}

#endif
