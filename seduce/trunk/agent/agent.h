#ifndef _AGENT_H
#define _AGENT_H

#include <netinet/in.h>

typedef struct _ProgVars {
	char *prog_name;	/* program name */
	char *config_file;	/* Configuration File*/
	struct in_addr addr;	/* Server Address */
	unsigned short port;	/* Server Port in network byte order*/
	char *password;		/* Connection Password */
	int timeout;		/* Seconds to wait before timeout */
	int retries;		/* Number of allowed retries */
	int no_work_wait;	/* Seconds to wait when no work available */

	/* Detection Engine */
	void (*detect_engine_init)(void);
	void (*detect_engine_stop)(void);
	int (*detect_engine_process)(char *, size_t);
} ProgVars;

/* Default Options */
#define DEFAULT_TIMEOUT		5
#define DEFAULT_RETRIES		5
#define DEFAULT_NO_WORK_WAIT	5

#define MAX_PWD_SIZE		16

extern ProgVars pv;

#endif /* _AGENT_H */
