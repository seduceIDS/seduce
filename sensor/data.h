#ifndef _DATA_H
#define _DATA_H

#include <time.h>
#include <arpa/inet.h>
#include <glib.h>
#include <netinet/in.h>

#include <nids.h> /* struct tuple4 */

#include "thread.h"


typedef struct _TCPData {
	void *payload;		/* The data pointer */
	size_t length;		/* The data dength */
	unsigned id;		/* The data ID */

	struct _TCPData *next;
	struct _TCPData *prev;
} TCPData;

typedef struct _UDPData {
	void *payload;		/* The data pointer */
	size_t length;		/* The data length */
} UDPData;

typedef struct _Session {
	struct _Session *next;
	struct _Session *prev;

	unsigned id;		/* Session ID */
	unsigned next_data_id;

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
	Session *sessionlist_head;
	Session *sessionlist_tail;
	unsigned id_start;		/* the first session id */
	GHashTable *hash;
	pthread_mutex_t mutex;
} Sensor;

typedef struct _DataInfo {	/* A pair that defines a unite of data */
	Session *session;
	union {
		UDPData *udp;
		TCPData *tcp;
	} data;
	int is_grouphead; /* Are those data the head of a group? */
} DataInfo;

extern Sensor sensor;

/* Functions */
void init_datalists(void);

Session *add_session(unsigned id, const struct tuple4 *addr, int proto);
Session *find_session(unsigned id);
int close_session (unsigned id);

/* returns a TCPData or UDPData pointer */ 
void *add_data(Session *, void *payload, size_t len);

TCPData *get_next_data(const TCPData *);

int destroy_data(DataInfo *);
int destroy_datagroup(DataInfo *);

#endif /* _DATA_H */
