#ifndef _SENSOR_H
#define _SENSOR_H

#include <stdint.h> /* unint8_t */

/* Program variables */
typedef struct _ProgVars {
	char *prog_name;
	int agent_port;
	int max_agents;
	int mem_softlimit;
	int mem_hardlimit;
	char *password;
	uint8_t port_table[65536];
} PV;

extern PV pv;

#define TCP_PORT	0x01
#define UDP_PORT	0x10

#define MAX_PWD_SIZE  16
#endif /* _SENSOR_H */
