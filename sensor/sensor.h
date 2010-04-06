#ifndef _SENSOR_H
#define _SENSOR_H

#include <netinet/in.h> /* for in_addr_t */

/* Program variables */
typedef struct _SensorProgVars {
	char *prog_name;
#ifndef TWO_TIER_ARCH
	in_addr_t server_addr;
	unsigned short server_port;
#endif
	u_int8_t port_table[65536];
} SPV;

extern SPV spv;

#define TCP_PORT	0x01
#define UDP_PORT	0x10

#endif /* _SENSOR_H */
