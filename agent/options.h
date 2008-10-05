#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <netinet/in.h>

typedef struct {
	struct in_addr addr;    /* Server Address */
	unsigned short port;	/* Server Port in network byte order */
} Manager;

typedef enum { ROUND_ROBIN, RANDOM } Scheduling;

typedef struct _InputOptions {
	const char *prog_name;	/* Program name */
	char *config_file;	/* Configuration File*/
	Manager *servers;	/* Array of manager nodes to use */
	int num_servers;	/* Number of members in manager array */
	Scheduling sched_algo;	/* Scheduling Algorithm */
	char *password;		/* Connection password */
	int timeout;		/* Seconds to wait before timeout */
	int retries;		/* Number of allowed retries */
	int no_work_wait;	/* Seconds to wait when no work available */
	int max_polls;		/* Number of idle servers to have polled prior
				   to sleeping for no_work_wait seconds */
} InputOptions;

/* Default Options */
#define DEFAULT_SCHED_ALGO	ROUND_ROBIN
#define DEFAULT_TIMEOUT		5
#define DEFAULT_RETRIES		5
#define DEFAULT_NO_WORK_WAIT	5
#define DEFAULT_MAX_POLLS	10

#define MAX_PWD_SIZE		16

InputOptions *fill_inputopts(int argc, char *argv[]);
void destroy_inputopts(InputOptions *);

#endif /* _OPTIONS_H */
