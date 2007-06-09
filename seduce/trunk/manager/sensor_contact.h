#ifndef _SENSOR_CONTACT_H
#define _SENSOR_CONTACT_H

#include <netinet/in.h>

typedef struct _SensorData {
	int connfd;
	struct in_addr sensor_ip;
	unsigned short sensor_port;
} SensorData;

void *sensor_contact(SensorData *);

#endif /* _SENSOR_CONTACT_H */

