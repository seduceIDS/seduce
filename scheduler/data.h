#ifndef _DATA_H
#define _DATA_H

#include <time.h>
#include <arpa/inet.h>
#include <glib.h>

#include "thread.h"

#define MAXSENSORS 256

enum _IPProtocol {TCP, UDP};
typedef enum _IPProtocol IPProtocol;

struct tuple4 { /* Don't ask about the name, it's from libnids... */
	u_int16_t s_port,d_port;	/* source and destination port */
	u_int32_t s_addr,d_addr;	/* source and destination ip   */
};

typedef struct _TCPData {
	unsigned char *payload;		/* The data pointer */
	int length;			/* The data dength */
	unsigned int id;		/* The data ID */

	struct _TCPData *next;
	struct _TCPData *prev;
} TCPData;

typedef struct _UDPData {
	unsigned char *payload;		/* The data pointer */
	int length;			/* The data length */
} UDPData;

typedef struct _Session {
	struct _Session *next;
	struct _Session *prev;

	unsigned int id;		/* Session ID */
	unsigned int next_data_id;

	int is_active;			/* Is the session still open? */
	struct tuple4 addr;		/* Session Address Info */
	IPProtocol proto;		/* UDP or TCP */

	union {
		UDPData *udp;
		TCPData *tcp;
	} data_head;			/* Session data head */
	union {
		UDPData *udp;
		TCPData *tcp;
	} data_tail;			/* Session data tail */
} Session;

typedef struct _Sensor {
	struct _Sensor *next;

	int is_connected;		/* Is the Sensor still connected? */
	time_t start;			/* Connect time */
	time_t stop;			/* Close time */

	u_int16_t port;			/* Sensor's Port */
	struct in_addr ip;		/* Sensor's Address */
	unsigned int id;

	Session *sessionlist_head;
	Session *sessionlist_tail;

	unsigned int id_start;		/* the first session id */
	GHashTable *hash;

	pthread_mutex_t mutex;
} Sensor;

typedef struct _SensorList {
	Sensor *head;
	Sensor *tail;
	int cnt;
	pthread_mutex_t mutex;
	GHashTable *hash;
} SensorList;


/* Functions */
void init_sensorlist (void);

int  add_sensor     (struct in_addr, unsigned short, Sensor **);
void close_sensor   (Sensor *);
void destroy_sensor (Sensor *);

Session * add_session (Sensor *, unsigned int, struct tuple4 *, IPProtocol);
Session * find_session (Sensor *, unsigned int);
int close_session   (Sensor *, unsigned int);
int destroy_session (Sensor *, unsigned int);

/* returns a TCPData or UDPData pointer */ 
void *add_data (Sensor *, unsigned int, IPProtocol, char *, int);
TCPData *find_data(Session *, unsigned int);

#endif /* _DATA_H */
