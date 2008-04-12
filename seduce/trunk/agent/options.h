#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <netinet/in.h>

typedef struct _InputOptions {
	const char *prog_name;	/* Program name */
	char *config_file;	/* Configuration File*/
	struct in_addr addr;	/* Server Address */
	unsigned short port;	/* Server Port in network byte order*/
	char *password;		/* Connection password */
	int timeout;		/* Seconds to wait before timeout */
	int retries;		/* Number of allowed retries */
	int no_work_wait;	/* Seconds to wait when no work available */
} InputOptions;

/* Default Options */
#define DEFAULT_TIMEOUT		5
#define DEFAULT_RETRIES		5
#define DEFAULT_NO_WORK_WAIT	5

#define MAX_PWD_SIZE		16

InputOptions *fill_inputopts(int argv, char *argc[]);
void destroy_inputopts(InputOptions *);

#endif /* _OPTIONS_H */
