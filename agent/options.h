#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <netinet/in.h>
#include "item_selection.h"

typedef struct {
	struct in_addr addr;    /* Manager Address */
	unsigned short port;	/* Manager Port in network byte order */
} Manager;

typedef struct _InputOptions {
	const char *prog_name;	/* Program name */
	char *config_file;	/* Configuration File*/
	Manager *managers;	/* Array of manager nodes to contact */
	int num_managers;	/* Number of members in manager array */
	SelectionType polling;	/* Order in which to poll the managers */
	char *password;		/* Connection password */
	int timeout;		/* Seconds to wait before timeout */
	int retries;		/* Number of allowed retries */
	int no_work_wait;	/* Seconds to wait when no work is available */
	int max_polls;		/* Number of idle managers to have polled prior
				   to sleeping for no_work_wait seconds */
	int workers;		/* Number of forked children handling the 
				   work */
} InputOptions;

/* Default Options */
#define DEFAULT_POLLING_ORDER	ROUND_ROBIN
#define DEFAULT_TIMEOUT		5
#define DEFAULT_RETRIES		5
#define DEFAULT_NO_WORK_WAIT	5
#define DEFAULT_MAX_POLLS	10
#define DEFAULT_WORKERS		1

#define MAX_PWD_SIZE		16

InputOptions *fill_inputopts(int argc, char *argv[]);
void destroy_inputopts(InputOptions *);

#endif /* _OPTIONS_H */
