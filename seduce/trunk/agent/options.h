#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <netinet/in.h>
#include "sensor_election.h"

typedef struct {
	struct in_addr addr;    /* Sensor Address */
	unsigned short port;	/* Sensor Port in network byte order */
} Sensor;

typedef struct _InputOptions {
	const char *prog_name;	/* Program name */
	char *config_file;	/* Configuration File*/
	Sensor *sensors;	/* Array of sensor nodes to contact */
	int num_sensors;	/* Number of members in sensor array */
	ElectionType polling;	/* Order in which to poll the sensors */
	char *password;		/* Connection password */
	int timeout;		/* Seconds to wait before timeout */
	int retries;		/* Number of allowed retries */
	int no_work_wait;	/* Seconds to wait when no work is available */
	int max_polls;		/* Number of idle sensors to have polled prior
				   to sleeping for no_work_wait seconds */
} InputOptions;

/* Default Options */
#define DEFAULT_ELECTION_TYPE	ROUND_ROBIN
#define DEFAULT_TIMEOUT		5
#define DEFAULT_RETRIES		5
#define DEFAULT_NO_WORK_WAIT	5
#define DEFAULT_MAX_POLLS	10

#define MAX_PWD_SIZE		16

InputOptions *fill_inputopts(int argc, char *argv[]);
void destroy_inputopts(InputOptions *);

#endif /* _OPTIONS_H */
