#ifndef _SENSOR_H
#define _SENSOR_H

#include <inttypes.h> /* unint8_t */

/* Program variables */
typedef struct _ProgVars {
	char *prog_name;
	long agent_port;
	long max_agents;
	long mem_softlimit;
	long mem_hardlimit;
	char *password;
	uint8_t port_table[65536];
} PV;

extern PV pv;

#define TCP_PORT	0x01
#define UDP_PORT	0x10

#define MAX_PWD_SIZE  16
#endif /* _SENSOR_H */
