#ifndef _SENSOR_CONTACT_H
#define _SENSOR_CONTACT_H

#include <netinet/in.h>
#include "data.h"

typedef struct _SensorData {
	int connfd;
	struct in_addr sensor_ip;
	unsigned short sensor_port;
} SensorData;

void *sensor_contact(SensorData *);


#ifdef TWO_TIER_ARCH

int new_tcp(unsigned id, const struct tuple4 * addr);
int close_tcp(unsigned id);
int tcp_data(unsigned id, void *p, size_t len);
int tcp_break(unsigned id);
int udp_data(const struct tuple4 *addr, void *p, size_t len, unsigned id);

#endif 

#endif /* _SENSOR_CONTACT_H */

