#ifndef _DATA_H
#define _DATA_H

#include <time.h>
#include <arpa/inet.h>
#include <glib.h>
#include <netinet/in.h>

#include "thread.h"

#ifndef TWO_TIER_ARCH
struct tuple4
{
  u_short source; /* source port */
  u_short dest;   /* destination port */
  u_int saddr;    /* source address */
  u_int daddr;    /* destination address */
};

#else /* TWO_TIER_ARCH */

#include <nids.h> /* for struct tuple4 */

#endif /* TWO_TIER_ARCH */

typedef struct _TCPData {
	void *payload;			/* The data pointer */
	size_t length;			/* The data dength */
	unsigned id;			/* The data ID */

	struct _TCPData *next;
	struct _TCPData *prev;
} TCPData;

typedef struct _UDPData {
	void *payload;			/* The data pointer */
	size_t length;			/* The data length */
} UDPData;

typedef struct _Session {
	struct _Session *next;
	struct _Session *prev;

	unsigned int id;		/* Session ID */
	unsigned int next_data_id;

	int is_active;			/* Is the session still open? */
	struct tuple4 addr;		/* Session Address Info */
	int proto;			/* UDP or TCP */

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

#ifndef TWO_TIER_ARCH
	struct _Sensor *next;
	int is_connected;		/* Is the Sensor still connected? */
	time_t start;			/* Connect time */
	time_t stop;			/* Close time */

	u_int16_t port;			/* Sensor's Port */
	struct in_addr ip;		/* Sensor's Address */
	unsigned int id;
#endif
	Session *sessionlist_head;
	Session *sessionlist_tail;

	unsigned int id_start;		/* the first session id */
	GHashTable *hash;

	pthread_mutex_t mutex;
} Sensor;

typedef struct _DataInfo {	/* A triplet that defines a unite of data */
	Sensor  *sensor;
	Session *session;
	union {
		UDPData *udp;
		TCPData *tcp;
	} data;
	int is_grouphead; /* Are those data the head of a group? */
} DataInfo;

typedef struct _Group {
	struct _Group *next;
	struct _Group *prev;
	DataInfo grouphead; /* The heading data of a group */
} Group;

typedef struct _GroupList {
	Group *head;
	Group *tail;
	int cnt;
	pthread_mutex_t mutex;
} GroupList;

typedef struct _SensorList {
	Sensor *head;
	Sensor *tail;
	int cnt;
	pthread_mutex_t mutex;
	GHashTable *hash;
} SensorList;


/* Functions */
void init_datalists(void);

#ifndef TWO_TIER_ARCH
int  add_sensor(struct in_addr, unsigned short port, Sensor **);
int close_sensor(Sensor *);
int destroy_sensor(Sensor *);
#endif

Session * add_session(Sensor *, unsigned, const struct tuple4 *, int proto);
Session * find_session(Sensor *, unsigned stream_id);
int close_session(Sensor *, unsigned stream_id);

/* returns a TCPData or UDPData pointer */ 
void *add_data(Session *, void *payload, size_t len);

TCPData *get_next_data(const TCPData *);

int destroy_data(DataInfo *);
int destroy_datagroup(DataInfo *);

int add_group(Sensor *, Session *, void *);
int consume_group(int (*func)(), void * params);

#endif /* _DATA_H */
