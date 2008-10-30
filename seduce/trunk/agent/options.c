#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <confuse.h>
#include <sys/types.h>
#include <regex.h>

#include "options.h"
#include "item_selection.h"

static void hlpmsg(const char *prog_name, int rc)
{
	fprintf(stderr,"Type `%s -h' for help.\n", prog_name);
	exit(rc);
}

static void print_usage(const char *prog_name, int rc)
{
	fprintf(stderr,
		"\n"
		"usage: %s [-h] [-c <config_file>] [-p <password>]\n"
		"\t[-s <sens_addr1,sens_addr2>] [-P <PollingOrder>] "
		"[-t <timeout>]\n"
		"\t[-r <retries>] [-w <no_work_wait>] [-m <max_polls>] "
		"[-f <children>]\n"
		"\n"
		"  h : Prints this help message.\n"
		"  c : Specify a config file. `E.g. /etc/agent.conf'.\n"
		"  p : Password to use for connecting with the sensors.\n"
		"  s : Server Addresses for Sensors in Hostname:Port format\n"
		"      e.g. `12.0.0.1:3540,194.233.11.1:4444'.\n"
		"  P : Sensor polling order (0: Round Robin, 1: Random)\n"
		"  t : Time in sec to wait for a sensor to answer.\n"
		"  r : Maximum numbers of retries when sending a request to "
		      "a sensor.\n"
		"  w : Time in sec to wait before requesting more work from "
		      "an idle sensor.\n"
		"  m : Max number of idle sensors to poll prior to "
		      "sleeping.\n"
		"  f : Number of child processes for handling the work\n"
		"\n",
		prog_name);
	exit(rc);
}

static int regexp_match(const char *pattern, const char *string){
	regex_t compiled;

	regcomp(&compiled, pattern, REG_EXTENDED | REG_NOSUB);

	return (regexec(&compiled, string, 0, NULL, 0) != REG_NOMATCH);
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

static SelectionType get_valid_polling(const char *str)
{
	SelectionType polling;

	polling = str_to_natural(str);
	if (!is_selection_valid(polling)) {
		fprintf(stderr, "invalid polling order option specified\n");
		return -1;
	}

	return polling; 
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
		fprintf(stderr,"%u is not a valid port number\n", port);
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

static int get_valid_max_polls(const char *str)
{
	int max_polls;

	max_polls = str_to_natural(str);
	if (max_polls < 1) {
		fprintf(stderr, "max_polls cannot be less than 1\n");
		return -1;
	}

	return max_polls;
}

static int get_valid_children(const char *str)
{
	int children;

	children = str_to_natural(str);
	if (children < 1) {
		fprintf(stderr, "children cannot be less than 1\n");
		return -1;
	}

	return children;
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

#define HOST_ATOM "[a-zA-Z0-9_-]+"
#define FQDN_PATTERN HOST_ATOM "(\\." HOST_ATOM ")*"
#define HOST_PORT_PATTERN FQDN_PATTERN ":[0-9]{1,5}"

static int validate_sensor(const char *str)
{
	char pattern[] = "^" HOST_PORT_PATTERN "$";

	if (regexp_match(pattern, str))
		return 1;
	else
		return 0;
}

static int validate_sensors_str(const char *str)
{
	char pattern[] = "^" HOST_PORT_PATTERN "(," HOST_PORT_PATTERN ")*$";

	if (regexp_match(pattern, str))
		return 1;
	else
		return 0;
}

static char **split_sensorinfo(const char *cmdline_arg, const char delimiter,
			       int *count)
{
	char *p, *tmp;
	int delimiter_count = 0;
	char **sensors;
	int i;
	char delim_str[2] = { delimiter, '\0' };

	tmp = strdup(cmdline_arg);
	p = tmp;

	for (;*p;p++) {
		if (*p == delimiter)
			delimiter_count++;
	}

	if (!(sensors = malloc((delimiter_count+1) * sizeof(char *)))) {
		fprintf(stderr, "error allocating memory for sensor "
				"string pointers\n");
		return NULL;
	}

	for (i = 0; i < delimiter_count + 1; i++) {
		sensors[i] = strsep(&tmp, delim_str);
	}
	*count = i;

	return sensors;
}

static int extract_sensorinfo(int num_sensors, 
			      const char **sensors,
			      InputOptions *input)
{
	int i;

	if (input->sensors) {
		fprintf(stderr, "extract_sensorinfo called, but input->sensors"
				" was already filled in!\n");
		return 0;
	}

	if (!(input->sensors = malloc(num_sensors * sizeof(Sensor)))) {
		perror("error allocating space for Sensor structs");
		return 0;
	}
	
	input->num_sensors = 0;

	for (i = 0; i<num_sensors; i++) {
		char *tmp;
		unsigned short tmp_port;
		char *port_str;
		char *host_str;
		struct hostent *he;

		if (!(tmp = strdup(sensors[i]))) {
			perror("error while duplicating sensor string");
			goto err;
		}

		host_str = strtok(tmp,":");
		port_str = strtok(NULL,"");

		if (!(tmp_port = get_valid_port(port_str))) {
			free(tmp);
			goto err;
		}

		if ((he = gethostbyname(host_str)) == NULL) {
			herror("gethostbyname");
			free(tmp);
			goto err;
		}
		
		input->sensors[i].addr = *((struct in_addr *) he->h_addr);
		input->sensors[i].port = tmp_port;					
		input->num_sensors += 1;

		free(tmp);
	}
	return 1;
err:
	free(input->sensors);
	input->num_sensors = 0;
	return 0;
}

#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)

static int get_cloptions(int argc, char *argv[], InputOptions *opts)
{
	int c;
	int c_arg = 0;
	int p_arg = 0;
	int P_arg = 0;
	int r_arg = 0;
	int s_arg = 0;
	int t_arg = 0;
	int w_arg = 0;
	int m_arg = 0;
	int f_arg = 0;

	int mgr_count;
	char **sensors;

	while ((c = getopt (argc, argv, "hc:p:r:s:t:w:P:m:f:")) != -1) {
		switch(c) {
		case 'h':
			print_usage(opts->prog_name, 0);
			break;

		case 'c':
			if (c_arg++) {
				PRINT_SPECIFY_ONCE('c');
				return 0;
			}
			opts->config_file = strdup(optarg);
			break;

		case 'p':
			if (p_arg++) {
				PRINT_SPECIFY_ONCE('p');
				return 0;
			}
			opts->password = strdup(optarg);
			if(!validate_password(opts->password))
				return 0;
			break;

		case 'P':
			if (P_arg++) {
				PRINT_SPECIFY_ONCE('P');
				return 0;
			}
			opts->polling = get_valid_polling(optarg);
			if (opts->polling == -1)
				return 0;
			break;

		case 'r':
			if (r_arg++) {
				PRINT_SPECIFY_ONCE('r');
				return 0;
			}
			opts->retries = get_valid_retries(optarg);
			if (opts->retries == -1)
				return 0;
			break;

		case 's':
			if (s_arg++) {
				PRINT_SPECIFY_ONCE('s');
				return 0;
			}

			if (!validate_sensors_str(optarg)){
				fprintf(stderr, 
					"syntax error at -s argument\n");
				return 0;
			}

			sensors = split_sensorinfo(optarg, ',', &mgr_count);
			if (!sensors)
				return 0;

			if (!extract_sensorinfo(mgr_count,
			                        (const char **) sensors,
						opts))
				return 0;
			break;

		case 't':
			if (t_arg++) {
				PRINT_SPECIFY_ONCE('t');
				return 0;
			}
			opts->timeout = get_valid_timeout(optarg);
			if (opts->timeout == -1)
				return 0;
			break;

		case 'w':
			if (w_arg++) {
				PRINT_SPECIFY_ONCE('w');
				return 0;
			}
			opts->no_work_wait = get_valid_no_work_wait(optarg);
			if (opts->no_work_wait == -1)
				return 0;
			break;

		case 'm':
			if (m_arg++) {
				PRINT_SPECIFY_ONCE('m');
				return 0;
			}
			opts->max_polls = get_valid_max_polls(optarg);
			if (opts->max_polls == -1)
				return 0;
			break;

		case 'f':
			if (f_arg++) { 
				PRINT_SPECIFY_ONCE('f');
				return 0;
			}
			opts->children = get_valid_children(optarg);
			if (opts->children == -1)
				return 0;
			break;

		default:
			print_usage(opts->prog_name, 1);
		}
	}

	return 1;
}


static int cfg_validate(cfg_t *cfg, cfg_opt_t *opt)
{
	int ret;

	if (strcmp(opt->name, "password") == 0)
		ret = validate_password(*(char **)opt->simple_value);
	else if (strcmp(opt->name, "polling_order") == 0)
		ret = is_selection_valid(*(int *)opt->simple_value);
	else if (strcmp(opt->name, "timeout") == 0)
		ret = (*(int *)opt->simple_value < 0) ? 0 : 1;
	else if (strcmp(opt->name, "retries") == 0)
		ret = (*(int *)opt->simple_value < 0) ? 0 : 1;
	else if (strcmp(opt->name, "no_work_wait") == 0)
		ret = (*(int *)opt->simple_value < 0) ? 0 : 1;
	else if (strcmp(opt->name, "max_polls") == 0)
		ret = (*(int *)opt->simple_value < 1) ? 0 : 1;
	else if (strcmp(opt->name, "children") == 0)
		ret = (*(int *)opt->simple_value < 1) ? 0 : 1;
	else
		ret = 0;

	if(!ret)
		cfg_error(cfg, "Error while parsing parameter \"%s\".",
		   	  opt->name);

	return (ret) ? 0 : -1;
}


static int parse_fileoptions(const char *filename, InputOptions *opts)
{
	char **sensors = NULL;
	int num_sensors, i, ret, retval = 1;

	cfg_opt_t cfg_opts[] = {
		CFG_STR_LIST("sensors", NULL, CFGF_NONE),
		CFG_SIMPLE_STR("password", &opts->password),
		CFG_SIMPLE_INT("polling_order", &opts->polling),
		CFG_SIMPLE_INT("timeout", &opts->timeout),
		CFG_SIMPLE_INT("retries", &opts->retries),
		CFG_SIMPLE_INT("no_work_wait", &opts->no_work_wait),
		CFG_SIMPLE_INT("max_polls", &opts->max_polls),
		CFG_SIMPLE_INT("children", &opts->children),
		CFG_END()
	};

	cfg_t *cfg;

	cfg = cfg_init(cfg_opts,0);

	/* set validation callback functions */
	
	/* "sensors" option gets validated later */
	cfg_set_validate_func(cfg,"password",cfg_validate);
	cfg_set_validate_func(cfg,"polling_order", cfg_validate);
	cfg_set_validate_func(cfg,"timeout",cfg_validate);
	cfg_set_validate_func(cfg,"retries",cfg_validate);
	cfg_set_validate_func(cfg,"no_work_wait",cfg_validate);
	cfg_set_validate_func(cfg,"max_polls", cfg_validate);
	cfg_set_validate_func(cfg,"children", cfg_validate);

	ret = cfg_parse(cfg,filename);
	
	if(ret != CFG_SUCCESS) {
		if (ret == CFG_FILE_ERROR)
			fprintf(stderr, "Can't open config file %s\n",filename);
		else if (ret == CFG_PARSE_ERROR)
			fprintf(stderr, "parse error: %s\n", filename);
		retval = 0;
		goto exit;
	}

	if (!(num_sensors = cfg_size(cfg, "sensors"))) {
		fprintf(stderr, "No value given for `sensors' option in config"
				" file %s\n", filename);
		retval = 0;
		goto exit;
	}
	
	if (!(sensors = malloc(num_sensors * sizeof(char *)))) {
		perror("malloc error while creating array of sensors");
		retval = 0;
		goto exit;
	}

	for(i=0; i<num_sensors; i++) {
		sensors[i] = cfg_getnstr(cfg, "sensors", i);
		if (!validate_sensor(sensors[i])) {
			fprintf(stderr,"invalid sensor string: %s\n",
				sensors[i]);
			retval = 0;
			goto exit;
		}
	}

	if (!extract_sensorinfo(num_sensors, (const char **) sensors, opts))
		retval = 0;
exit:
	free(sensors);
	cfg_free(cfg);
	return retval;
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
	final_opts->polling = clo.polling = -1;
	final_opts->timeout = clo.timeout = -1;
	final_opts->retries = clo.retries = -1;
	final_opts->no_work_wait = clo.no_work_wait = -1;
	final_opts->max_polls = clo.max_polls = -1;
	final_opts->children = clo.children = -1;

	ret = get_cloptions(argc, argv, &clo);
	if (!ret)
		print_usage(argv[0], 1);

	if (clo.config_file) {
		ret = parse_fileoptions(clo.config_file, final_opts);
		free(clo.config_file);
		if(!ret)
			print_usage(argv[0], 1);
	}

	/* 
	 * if an option is defined in the config file and as a command line
	 * option, we ignore the value found in the config file. Command line
	 * options always have a higher priority.
	 */

	if (clo.sensors) {
		if (final_opts->sensors)
			free(final_opts->sensors);
		
		final_opts->sensors = clo.sensors;
		final_opts->num_sensors = clo.num_sensors;
	}

	if(clo.password) {
		if(final_opts->password)
			free(final_opts->password);
		final_opts->password = clo.password;
	}


	/* 
	 * if timeout, retries, no_work_wait, polling and max_polls
	 * are not set from the command line or the config file, we set the 
	 * default values.
	 */


	if (clo.polling != -1)
		final_opts->polling = clo.polling;
	else if (final_opts->polling == -1)
		final_opts->polling = DEFAULT_POLLING_ORDER;

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

	if(clo.max_polls != -1)
		final_opts->max_polls = clo.max_polls;
	else if(final_opts->max_polls == -1)
		final_opts->max_polls = DEFAULT_MAX_POLLS;

	if(clo.children != -1)
		final_opts->children = clo.children;
	else if(final_opts->children == -1)
		final_opts->children = DEFAULT_CHILDREN;


	/* 
	 * Now that command line and config file options are set,
	 * check if a required option is missing.
	 * Required options are the connection info (IP/port & password)
	 */

	if (!final_opts->sensors){
		fprintf(stderr, "Sensor address(es) not set.\n");
		hlpmsg(final_opts->prog_name, 1);
	}

	if(!final_opts->password) {
		fprintf(stderr, "No sensor password is set.\n");
		hlpmsg(final_opts->prog_name, 1);
	}

	return final_opts;
}

void destroy_inputopts(InputOptions *opts)
{
	if (opts->sensors)
		free(opts->sensors);

	if (opts->password)
		free(opts->password);

	free(opts);
}

#if 0
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	Sensor s;
	InputOptions *in = fill_inputopts(argc, argv);
	int i;

	if(!in) return 1;

	printf("Options:\n");
	printf("Sensor Address(es): ");
	for(i=0; i < in->num_sensors; i++){
		s = in->sensors[i];
		printf("%s:%u ", inet_ntoa(s.addr), ntohs(s.port));
	}
	printf("\n");

	printf("Polling Method: ");
	if (in->polling == RANDOM){
		printf("Random\n");
	} else if (in->polling == ROUND_ROBIN) {
		printf("Round Robin\n");
	} else {
		printf("Unknown\n");
	}

	printf("Password: %s\n", in->password);
	printf("Timeout: %d\n", in->timeout);
	printf("Retries: %d\n", in->retries);
	printf("No Work Wait: %d\n", in->no_work_wait);
	printf("Max Polls before sleep: %d\n", in->max_polls);
	printf("Children: %d\n", in->children);

	destroy_inputopts(in);

	return 0;
}
#endif
