#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <confuse.h>

#include "scheduler.h"

typedef struct _CommandLineOptions {
	char *agent_port;
	char *sensor_port;
	char *max_agents;
	char *max_sensors;
	char *mem_softlimit;
	char *mem_hardlimit;
	char *password;
	char *conf_file;
} CLO;

/* 
 * The next 2 values define the acceptable port range for the agent and sensor
 * servers. The values were not picked randomly. Actually to open a port which 
 * in the range 1-1024 you need root permission and scheduler is not supposed to
 * run with root priveleges. On the other hand at least for the 2.6 version of
 * the linux kernel, the ephemeral port range is 32768-61000, so we picked the
 * inbetween to be the acceptable port range. Feel free to change the bellow
 * values.
 */ 
#define MIN_PORT_LIMIT 1025
#define MAX_PORT_LIMIT 32768

/* Defaults */
#define SENSOR_PORT	28001 /* 28001-28239 are unassigned. If you care see: */
#define AGENT_PORT	28002 /* http://www.iana.org/assignments/port-numbers */
#define MAX_AGENTS	256
#define MAX_SENSORS	8
#define PASSWORD	"password"

static void printusage(int rc)
{
	fprintf(stderr,
		"Usage: %s [-h] [-a<agent_port>] [-A<max_agents>] "
		"[-l<mem_softlimit>] [-L<mem_hardlimit>] [-s<sensor_port>] "
		"[-S<max_sensors>] [-p<password>]\n\n"
		"  h: Print this message.\n"
		"  a: Specify the port to listen for agent requests. "
		"Default value is 28001.\n"
		"  A: Maximum number of agents allowed. "
		"Default value is 256.\n"
		"  c: Confuguration file. E.g. `scheduler.conf'.\n"
		"  l: Memory usage soft limit in Mb. E.g. `400'.\n"
		"  L: Memory usage hard limit in Mb. E.g. `390'.\n"
		"  p: Password for the agents.\n"
		"  s: Specify the port to listen for sensor connections. "
		"Default value is 28002.\n"
		"  S: Maximum number of sensor connections allowed. "
		"The Default value is 8.\n\n",
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

static int get_valid_port(const char *str)
{
	int port;

	port = str_to_natural(str);
	if (port <= 1) {
		fprintf(stderr, "Not a valid port\n");
		return -1;
	}

	if (port < MIN_PORT_LIMIT || port > MAX_PORT_LIMIT) {
		fprintf(stderr, "The valid port range is from %d to %d\n",
				MIN_PORT_LIMIT, MAX_PORT_LIMIT);
		return -1;
	}

	return port;
}

static int validate_password(const char *pwd)
{
	size_t size;

	size = strlen(pwd);
	if(size > MAX_PWD_SIZE)
		return 0;

	return 1;
}


#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)
static void get_cloptions(int argc, char *argv[], CLO *clo)
{
	int c;
	int a_arg = 0;
	int A_arg = 0;
	int c_arg = 0;
	int l_arg = 0;
	int L_arg = 0;
	int p_arg = 0;
	int s_arg = 0;
	int S_arg = 0;

	while((c = getopt(argc, argv, "a:A:c:hl:L:p:s:S:")) != -1) {
		switch(c) {
			case 'h':
				printusage(0);

			case 'a':
				if (a_arg) {
					PRINT_SPECIFY_ONCE('a');
					goto err;
				}
				clo->agent_port = strdup(optarg);
				break;

			case 'A':
				if (A_arg) {
					PRINT_SPECIFY_ONCE('A');
					goto err;
				}
				clo->max_agents = strdup(optarg);
				break;

			case 'c':
				if (c_arg) {
					PRINT_SPECIFY_ONCE('c');
					goto err;
				}
				clo->conf_file = strdup(optarg);
				break;

			case 'l':
				if (l_arg) {
					PRINT_SPECIFY_ONCE('l');
					goto err;
				}
				clo->mem_softlimit = strdup(optarg);
				break;

			case 'L':
				if (L_arg) {
					PRINT_SPECIFY_ONCE('L');
					goto err;
				}
				clo->mem_hardlimit = strdup(optarg);
				break;

			case 's':
				if (s_arg) {
					PRINT_SPECIFY_ONCE('s');
					goto err;
				}
				clo->sensor_port = strdup(optarg);
				break;

			case 'S':
				if (S_arg) {
					PRINT_SPECIFY_ONCE('S');
					goto err;
				}
				clo->max_sensors = strdup(optarg);
				break;

			case 'p':
				if (p_arg) {
					PRINT_SPECIFY_ONCE('p');
					goto err;
				}
				clo->password = strdup(optarg);
				break;

			default:
				goto err;
		}
	}

	return;

err:
	printusage(1);
}

static int cfg_validate(cfg_t *cfg, cfg_opt_t *opt)
{
	if ((strcmp(opt->name, "sensor_port") == 0) ||
	    (strcmp(opt->name, "agent_port") == 0)) {
		if((*(int *)opt->simple_value < MIN_PORT_LIMIT) ||
                   (*(int *)opt->simple_value > MAX_PORT_LIMIT)) { 
			cfg_error(cfg,"The valid port range is from %d to %d\n",
				MIN_PORT_LIMIT, MAX_PORT_LIMIT);
			return -1;
		}
	} else if ((strcmp(opt->name, "max_sensors") == 0)   ||
	           (strcmp(opt->name, "max_agents") == 0)    ||
	           (strcmp(opt->name, "mem_softlimit") == 0) ||
	           (strcmp(opt->name, "mem_hardlimit") == 0)) {
		if((*(int *)opt->simple_value < 1)) {
			cfg_error(cfg, "'%s' must be at least 1", opt->name);
			return -1;
		}
	} else if (strcmp(opt->name, "password") == 0) {
		if (!validate_password(*(char **)opt->simple_value)) {
			cfg_error(cfg, "Password can't be longer that %d "
					"characters", MAX_PWD_SIZE);
			return -1;
		}
	} else return -1;

	return 0;
}

static int parse_file(char *filename)
{
	int ret;

	cfg_opt_t opts[] = {
		CFG_SIMPLE_INT("agents_port", &pv.agent_port),
		CFG_SIMPLE_INT("sensors_port", &pv.sensor_port),
		CFG_SIMPLE_INT("max_agents", &pv.max_agents),
		CFG_SIMPLE_INT("max_sensors", &pv.max_sensors),
		CFG_SIMPLE_INT("mem_softlimit", &pv.mem_softlimit),
		CFG_SIMPLE_INT("mem_hardlimit", &pv.mem_hardlimit),
		CFG_SIMPLE_STR("password", &pv.password),
		CFG_END()
	};
	cfg_t *cfg;

	cfg = cfg_init(opts, 0);

	/* set validation callback functions */
	cfg_set_validate_func(cfg, "sensors_port", cfg_validate);
	cfg_set_validate_func(cfg, "agents_port", cfg_validate);
	cfg_set_validate_func(cfg, "max_sensors", cfg_validate);
	cfg_set_validate_func(cfg, "max_agents", cfg_validate);
	cfg_set_validate_func(cfg, "password", cfg_validate);
	cfg_set_validate_func(cfg, "mem_softlimit", cfg_validate);
	cfg_set_validate_func(cfg, "mem_hardlimit", cfg_validate);

	ret = cfg_parse(cfg,filename);
	
	if(ret != CFG_SUCCESS) {
		if (ret == CFG_FILE_ERROR)
			fprintf(stderr, "Can't open config file\n");
		cfg_free(cfg);
		return 0;
	}

	return 1;
}



void fill_progvars(int argc, char *argv[])
{
	CLO clo;

	memset(&clo, '\0', sizeof(CLO));

	memset(&pv, '\0', sizeof(PV));
	pv.prog_name = argv[0];

	get_cloptions(argc, argv, &clo);

	if(clo.conf_file) {
		if(!parse_file(clo.conf_file))
			exit(0);
		free(clo.conf_file);
	}

	if (clo.sensor_port) {
		if(!(pv.sensor_port = get_valid_port(clo.sensor_port)))
			exit(1);
		free(clo.sensor_port);
	} else if(!pv.sensor_port)
		pv.sensor_port = SENSOR_PORT;


	if (clo.agent_port) {
		if(!(pv.agent_port = get_valid_port(clo.agent_port)))
			exit(1);
		free(clo.agent_port);
	} else if(!pv.agent_port)
		pv.agent_port = AGENT_PORT;

	if (clo.max_agents) {
		if((pv.max_agents = str_to_natural(clo.max_agents)) < 1) {
			fprintf(stderr, "Maximum number of allowed agents must "
					"be at least 1\n");
			exit(1);
		}
		free(clo.max_agents);
	} else if(!pv.max_agents)
		pv.max_agents = MAX_AGENTS;

	if (clo.max_sensors) {
		if((pv.max_sensors = str_to_natural(clo.max_sensors)) < 1) {
			fprintf(stderr, "Maximum number of allowed sensors "
					"must be at least 1\n");
			exit(1);
		}
		free(clo.max_sensors);
	} else if(!pv.max_sensors)
		pv.max_sensors = MAX_SENSORS;

	if (clo.mem_softlimit) {
		if((pv.mem_softlimit = str_to_natural(clo.mem_softlimit)) < 1) {
			fprintf(stderr, "Not a valid soft limit value\n");
			exit(1);
		}
		free(clo.mem_softlimit);
	}

	if (clo.mem_hardlimit) {
		if((pv.mem_hardlimit = str_to_natural(clo.mem_hardlimit)) < 1) {
			fprintf(stderr, "Not a valid hard limit calue\n");
			exit(1);
		}
		free(clo.mem_hardlimit);
	}

	if(clo.password) {
		if(!validate_password(clo.password)) {
			fprintf(stderr, "Password can't be longer than %d "
					"characters\n", MAX_PWD_SIZE);
			exit(1);
		}
		if(pv.password)
			free(pv.password);
		pv.password = clo.password;
	}

	/* sanity checks */
	if(!pv.password) {
		fprintf(stderr, "Password is not set. Type -h for help.\n");
		exit(1);
	}

	if(!pv.mem_softlimit || !pv.mem_hardlimit) {
		fprintf(stderr, "Memory limits are not set. "
				"Type -h for help.\n");
		exit(1);
	}

	if(pv.mem_softlimit > pv.mem_hardlimit) {
		fprintf(stderr, "Memory soft limit cannot be greater than the "
			        "memory hard limit\n");
		exit(1);
	}

	/* OK, now convert the limits to MB */
	pv.mem_hardlimit <<= 20;
	pv.mem_softlimit <<= 20;
}

#if 0
PV pv;

int main(int argc, char *argv[])
{
	fill_progvars(argc, argv);
	
	printf("Options:\n");
	printf("Sensor Port:%d\n", pv.sensor_port);
	printf("Agent Port:%d\n", pv.agent_port);
	printf("Max Sensors:%d\n", pv.max_sensors);
	printf("Max Agents:%d\n", pv.max_agents);
	printf("Soft limit:%d\n", pv.mem_softlimit);
	printf("Hard limit:%d\n", pv.mem_hardlimit);
	printf("Password:%s\n", pv.password);

	return 0;
}
#endif
