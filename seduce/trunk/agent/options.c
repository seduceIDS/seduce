#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <confuse.h>

#include "options.h"

static void hlpmsg(const char *prog_name, int rc)
{
	fprintf(stderr,"Type `%s -h' for help.\n", prog_name);
	exit(rc);
}


static void printusage(const char *prog_name, int rc)
{
	fprintf(stderr, 
		"\nUsage:\n%s [-c <config_file>] [-h] [-p<password>] "
		"[-r<retries>]\n       [-s<server_address]> [-t<timeout>] "
		"[-w<no_work_wait>]\n\n"
		"  h : Print this help message.\n"
		"  c : Specify a config file. `E.g. agent.conf'.\n"
		"  p : Password to use to connecting with the manager.\n"
		"  r : Maximum numbers of times to retry when sending a "
		      "request to the manager.\n"
		"  s : Server Address in Hostname:Port format. "
		      "E.g. `12.0.0.1:3540'.\n"
		"  t : Time in sec to wait for an answer by the manager.\n"
		"  w : Time in sec to wait before requesting again when the "
		      "manager has no work\n      available.\n\n",
		prog_name);
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

#define VALIDATE_SERVERINFO(x) fill_serverinfo(x, NULL, NULL)

static int fill_serverinfo(const char *serverinfo, struct in_addr *addr,
							   unsigned short *port)
{
	char *tmp;
	unsigned short tmp_port;
	char *port_str;
	char *host_str;
	struct hostent *he;

	tmp = strdup(serverinfo);
	if(!tmp) {
		perror("strdup");
		return 0;
	}

	host_str = strtok(tmp,":");
	port_str = strtok(NULL,"");

	if(!(tmp_port = get_valid_port(port_str)))
		goto err;

	if(port)
		*port = tmp_port;

	if((he = gethostbyname(host_str)) == NULL) {
		herror("gethostbyname");
		goto err;
	}

	if(addr)
		*addr = *((struct in_addr *)he->h_addr);

	free(tmp);
	return 1;

err:
	free(tmp);
	return 0;
}

#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)
static int get_cloptions(int argc, char *argv[], InputOptions *opts)
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
			printusage(opts->prog_name, 0);
			break;

		case 'c':
			if(c_arg) {
				PRINT_SPECIFY_ONCE('c');
				return 0;
			}
			opts->config_file = strdup(optarg);
			break;

		case 'p':
			if(p_arg) {
				PRINT_SPECIFY_ONCE('p');
				return 0;
			}
			opts->password = strdup(optarg);
			if(!validate_password(opts->password))
				return 0;
			break;

		case 'r':
			if(r_arg) {
				PRINT_SPECIFY_ONCE('r');
				return 0;
			}
			opts->retries = get_valid_retries(optarg);
			if (opts->retries == -1)
				return 0;
			break;

		case 's':
			if(s_arg) {
				PRINT_SPECIFY_ONCE('s');
				return 0;
			}
			if(!fill_serverinfo(optarg, &opts->addr, &opts->port))
				return 0;
			break;

		case 't':
			if(t_arg) {
				PRINT_SPECIFY_ONCE('t');
				return 0;
			}
			opts->timeout = get_valid_timeout(optarg);
			if (opts->timeout == -1)
				return 0;
			break;

		case 'w':
			if(w_arg) {
				PRINT_SPECIFY_ONCE('w');
				return 0;
			}
			opts->no_work_wait = get_valid_no_work_wait(optarg);
			if (opts->no_work_wait == -1)
				return 0;
			break;

		default:
			printusage(opts->prog_name, 1);
		}
	}

	return 1;
}

static int cfg_validate(cfg_t *cfg, cfg_opt_t *opt)
{
	int ret;

	if (strcmp(opt->name, "server_addr") == 0)
		ret = VALIDATE_SERVERINFO(*(char **)opt->simple_value);
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


static int parse_fileoptions(const char *filename, InputOptions *opts)
{
	char *server_addr = NULL;
	int ret;

	cfg_opt_t cfg_opts[] = {
		CFG_SIMPLE_STR("server_addr",&server_addr),
		CFG_SIMPLE_STR("password",&opts->password),
		CFG_SIMPLE_INT("timeout",&opts->timeout),
		CFG_SIMPLE_INT("retries",&opts->retries),
		CFG_SIMPLE_INT("no_work_wait",&opts->no_work_wait),
		CFG_END()
	};

	cfg_t *cfg;

	cfg = cfg_init(cfg_opts,0);

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
		return 0;
	}

	if(server_addr) {
		fill_serverinfo(server_addr, &opts->addr, &opts->port);
		free(server_addr);
	}

	cfg_free(cfg);
	return 1;
}


InputOptions *fill_inputopts(int argc, char *argv[])
{
	int ret;
	InputOptions clo; /* temporary store of the command line options */
	InputOptions *final_opts;

	final_opts = calloc(1, sizeof(InputOptions));
	if(final_opts == NULL) {
		perror("calloc");
		return NULL;
	}

	memset(&clo, '\0', sizeof(InputOptions));
	
	final_opts->prog_name = clo.prog_name = argv[0];
	final_opts->timeout = clo.timeout = -1;
	final_opts->retries = clo.retries = -1;
	final_opts->no_work_wait = clo.no_work_wait = -1;
	
	ret = get_cloptions(argc, argv, &clo);
	if (!ret)
		printusage(argv[0], 1);

	if(clo.config_file) {
		ret = parse_fileoptions(clo.config_file, final_opts);
		free(clo.config_file);
		if(!ret)
			printusage(argv[0], 1);
	}

	/* 
	 * if an option is defined in the config file and as a command line
	 * option, we ignore the one config file value. Command line options
	 * always have a higher priority.
	 */
	if(clo.port) {
		final_opts->port = clo.port;
		final_opts->addr = clo.addr;
	}

	if(clo.password) {
		if(final_opts->password)
			free(final_opts->password);
		final_opts->password = clo.password;
	}

	/* 
	 * if timeout, retries and no_work_wait are not set from the command
	 * line or the config file, we set the default values.
	 */

	if(clo.timeout != -1)
		final_opts->timeout = clo.timeout;
	else if(final_opts->timeout == -1)
		final_opts->timeout = DEFAULT_TIMEOUT;

	if(clo.retries != -1)
		final_opts->retries = clo.retries;
	else if(final_opts->retries == -1)
		final_opts->retries = DEFAULT_RETRIES;

	if(clo.no_work_wait != -1)
		final_opts->no_work_wait = clo.no_work_wait;
	else if(final_opts->no_work_wait == -1)
		final_opts->no_work_wait = DEFAULT_NO_WORK_WAIT;

	/* 
	 * Now that command line and config file options are set,
	 * check if a required option is missing.
	 * Required options are the connection info (IP/port & password)
	 */
	if(!final_opts->port) {
		fprintf(stderr, "Server address and port are not set.\n");
		hlpmsg(final_opts->prog_name, 1);
	}

	if(!final_opts->password) {
		fprintf(stderr, "No server password is set.\n");
		hlpmsg(final_opts->prog_name, 1);
	}

	return final_opts;
}

void destroy_inputopts(InputOptions *opts)
{
	if(opts->password)
		free(opts->password);

	free(opts);
}

#if 0

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	InputOptions *in = fill_inputopts(argc, argv);

	if(!in) return 1;

	printf("Options:\n");
	printf("Sever Address: %s\n", inet_ntoa(in->addr));
	printf("Server Port: %u\n", ntohs(in->port));
	printf("Password: %s\n", in->password);
	printf("Timeout: %d\n", in->timeout);
	printf("Retries: %d\n", in->retries);
	printf("No Work Wait: %d\n", in->no_work_wait);

	destroy_inputopts(in);

	return 0;
}

#endif
