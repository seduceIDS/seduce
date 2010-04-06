#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "options.h"
#include "manager.h"

typedef struct _CommandLineOptions {
	char *agent_port;
#ifndef TWO_TIER_ARCH
	char *sensor_port;
	char *max_sensors;
	char *conf_file;
#endif
	char *max_agents;
	char *mem_softlimit;
	char *mem_hardlimit;
	char *password;
} CLO;

static CLO clo;

/* 
 * The next 2 values define the acceptable port range for the agent and sensor
 * servers. The values were not picked randomly. Actually to open a port which 
 * is in the range 1-1024 you need root permission and manager is not supposed
 * to be running with root priveleges. On the other hand at least for the 2.6
 * version of the linux kernel, the ephemeral port range is 32768-61000, so we 
 * picked the inbetween to be the acceptable port range. Feel free to change
 * the bellow values.
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
		"\nUsage:\n%s [-h] [-a<agent_port>] [-A<max_agents>] "
		"[-l<mem_softlimit>] [-L<mem_hardlimit>] "
		"[-s<sensor_port>] [-S<max_sensors>] [-p<password>]\n\n"
		"  h: Print this message.\n"
		"  c: Confuguration file. E.g. `manager.conf'.\n"
		"  P: Password for the agents.\n"
		"  a: Specify the port to listen for agent requests. "
		"Default value is 28002.\n"
		"  A: Maximum number of agents allowed. "
		"Default value is 256.\n"
		"  l: Memory usage soft limit in Mb. E.g. `400'.\n"
		"  L: Memory usage hard limit in Mb. E.g. `390'.\n"
		"  s: Specify the port to listen for sensor connections. "
		"Default value is 28001.\n"
		"  S: Maximum number of sensor connections allowed. "
		"The Default value is 8.\n\n",
		mpv.prog_name);
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

void validate_manager_fileopts(cfg_t *cfg)
{
	/* set validation callback functions */
	cfg_set_validate_func(cfg, "sensors_port", cfg_validate);
	cfg_set_validate_func(cfg, "agents_port", cfg_validate);
	cfg_set_validate_func(cfg, "max_sensors", cfg_validate);
	cfg_set_validate_func(cfg, "max_agents", cfg_validate);
	cfg_set_validate_func(cfg, "password", cfg_validate);
	cfg_set_validate_func(cfg, "mem_softlimit", cfg_validate);
	cfg_set_validate_func(cfg, "mem_hardlimit", cfg_validate);
}

cfg_opt_t *get_manager_fileopts()
{
	static cfg_opt_t opts[] = {
		CFG_SIMPLE_INT("agents_port", &mpv.agent_port),
#ifndef TWO_TIER_ARCH
		CFG_SIMPLE_INT("sensors_port", &mpv.sensor_port),
		CFG_SIMPLE_INT("max_sensors", &mpv.max_sensors),
#endif
		CFG_SIMPLE_INT("max_agents", &mpv.max_agents),
		CFG_SIMPLE_INT("mem_softlimit", &mpv.mem_softlimit),
		CFG_SIMPLE_INT("mem_hardlimit", &mpv.mem_hardlimit),
		CFG_SIMPLE_STR("password", &mpv.password),
		CFG_END()
		};

       return opts;
}


static int parse_file(char *filename)
{
	int ret;

	cfg_t *cfg = cfg_init(get_manager_fileopts(), 0);

	validate_manager_fileopts(cfg);

	ret = cfg_parse(cfg,filename);
	
	if(ret != CFG_SUCCESS) {
		if (ret == CFG_FILE_ERROR)
			fprintf(stderr, "Can't open config file\n");
		cfg_free(cfg);
		return 0;
	}

	cfg_free(cfg);
	return 1;
}


const char *get_manager_optstring(void)
{
#ifndef TWO_TIER_ARCH
	return "a:A:c:hl:L:P:s:S:";
#else
	return "a:A:l:L:P:";
#endif
}

#define PRINT_SPECIFY_ONCE(x) \
	fprintf(stderr, "The -%c option should be specified only once\n", x)
int process_manager_optchars(int c)
{
	static int a_arg = 0;
	static int A_arg = 0;
	static int l_arg = 0;
	static int L_arg = 0;
	static int P_arg = 0;
#ifndef TWO_TIER_ARCH
	static int c_arg = 0;
	static int s_arg = 0;
	static int S_arg = 0;
#endif

	switch(c) {
	case 'h':
		printusage(0);

	case 'a':
		if (a_arg) {
			PRINT_SPECIFY_ONCE('a');
			goto err;
		}
		a_arg = 1;
		clo.agent_port = strdup(optarg);
		break;

	case 'A':
		if (A_arg) {
			PRINT_SPECIFY_ONCE('A');
			goto err;
		}
		A_arg = 1;
		clo.max_agents = strdup(optarg);
		break;
#ifndef TWO_TIER_ARCH
	case 'c':
		if (c_arg) {
			PRINT_SPECIFY_ONCE('c');
			goto err;
		}
		c_arg = 1;
		clo.conf_file = strdup(optarg);
		break;
	case 's':
		if (s_arg) {
			PRINT_SPECIFY_ONCE('s');
			goto err;
		}
		s_arg = 1;
		clo.sensor_port = strdup(optarg);
		break;

	case 'S':
		if (S_arg) {
			PRINT_SPECIFY_ONCE('S');
			goto err;
		}
		S_arg = 1;
		clo.max_sensors = strdup(optarg);
		break;
#endif
	case 'l':
		if (l_arg) {
			PRINT_SPECIFY_ONCE('l');
			goto err;
		}
		l_arg = 1;
		clo.mem_softlimit = strdup(optarg);
		break;

	case 'L':
		if (L_arg) {
			PRINT_SPECIFY_ONCE('L');
			goto err;
		}
		L_arg = 1;
		clo.mem_hardlimit = strdup(optarg);
		break;

	case 'P':
		if (P_arg) {
			PRINT_SPECIFY_ONCE('P');
			goto err;
		}
		P_arg = 1;
		clo.password = strdup(optarg);
		break;
	default:
		return 2;
	}

	return 1;
err:
	return 0;
}

static void get_cloptions(int argc, char *argv[])
{
	int ret, c;
	while((c = getopt(argc, argv, get_manager_optstring())) != -1) {
		ret = process_manager_optchars(c);
		if (ret == 0)
			goto err;
	}

	return;
err:
	printusage(1);
}

void clear_manager_clops()
{
	memset(&clo, '\0', sizeof(CLO));
}

void fill_manager_progvars(int argc, char *argv[])
{

#ifndef TWO_TIER_ARCH
	clear_manager_clops();
	memset(&mpv, '\0', sizeof(MPV));
#endif
	mpv.prog_name = argv[0];

#ifndef TWO_TIER_ARCH
	
	get_cloptions(argc, argv);

	if(clo.conf_file) {
		if(!parse_file(clo.conf_file))
			exit(0);
		free(clo.conf_file);
	}

	if (clo.sensor_port) {
		if(!(mpv.sensor_port = get_valid_port(clo.sensor_port)))
			exit(1);
		free(clo.sensor_port);
	} else if(!mpv.sensor_port)
		mpv.sensor_port = SENSOR_PORT;

	if (clo.max_sensors) {
		if((mpv.max_sensors = str_to_natural(clo.max_sensors)) < 1) {
			fprintf(stderr, "Maximum number of allowed sensors "
					"must be at least 1\n");
			exit(1);
		}
		free(clo.max_sensors);
	} else if(!mpv.max_sensors)
		mpv.max_sensors = MAX_SENSORS;
#endif
	if (clo.agent_port) {
		if(!(mpv.agent_port = get_valid_port(clo.agent_port)))
			exit(1);
		free(clo.agent_port);
	} else if(!mpv.agent_port)
		mpv.agent_port = AGENT_PORT;

	if (clo.max_agents) {
		if((mpv.max_agents = str_to_natural(clo.max_agents)) < 1) {
			fprintf(stderr, "Maximum number of allowed agents must "
					"be at least 1\n");
			exit(1);
		}
		free(clo.max_agents);
	} else if(!mpv.max_agents)
		mpv.max_agents = MAX_AGENTS;

	if (clo.mem_softlimit) {
		if((mpv.mem_softlimit = 
				str_to_natural(clo.mem_softlimit)) < 1) {
			fprintf(stderr, "Not a valid soft limit value\n");
			exit(1);
		}
		free(clo.mem_softlimit);
	}

	if (clo.mem_hardlimit) {
		if((mpv.mem_hardlimit =
				str_to_natural(clo.mem_hardlimit)) < 1) {
			fprintf(stderr, "Not a valid hard limit value\n");
			exit(1);
		}
		free(clo.mem_hardlimit);
	}

	if(clo.password) {
		fprintf(stderr, "I'm in  password\n");
		if(!validate_password(clo.password)) {
			fprintf(stderr, "Password can't be longer than %d "
					"characters\n", MAX_PWD_SIZE);
			exit(1);
		}
		if(mpv.password)
			free(mpv.password);
		mpv.password = clo.password;
	}

	/* sanity checks */
	if(!mpv.password) {
		fprintf(stderr, "Password is not set. Type -h for help.\n");
		exit(1);
	}

	if(!mpv.mem_softlimit || !mpv.mem_hardlimit) {
		fprintf(stderr, "Memory limits are not set. "
				"Type -h for help.\n");
		exit(1);
	}

	if(mpv.mem_softlimit > mpv.mem_hardlimit) {
		fprintf(stderr, "Memory soft limit cannot be greater than the "
			        "memory hard limit\n");
		exit(1);
	}

	/* OK, now convert the limits to MB */
	mpv.mem_hardlimit <<= 20;
	mpv.mem_softlimit <<= 20;
}

#if 0
MPV mpv;

int main(int argc, char *argv[])
{
	fill_manager_progvars(argc, argv);
	
	printf("Options:\n");
	printf("Sensor Port:%d\n", mpv.sensor_port);
	printf("Agent Port:%d\n", mpv.agent_port);
	printf("Max Sensors:%d\n", mpv.max_sensors);
	printf("Max Agents:%d\n", mpv.max_agents);
	printf("Soft limit:%d\n", mpv.mem_softlimit);
	printf("Hard limit:%d\n", mpv.mem_hardlimit);
	printf("Password:%s\n", mpv.password);

	return 0;
}
#endif
