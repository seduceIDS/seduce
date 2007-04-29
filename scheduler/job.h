#ifndef _JOB_H
#define _JOB_H

#include "thread.h"
#include "data.h"

typedef struct _DataInfo {
	union {
		UDPData *udp;
		TCPData *tcp;
	} data;
	Session *session;
	Sensor  *sensor;
} DataInfo;

typedef struct _Job {
	struct _Job *next;
	struct _Job *prev;
	DataInfo data_info;
} Job;

typedef struct _JobList {
	Job *head;
	Job *tail;
	int cnt;
	pthread_mutex_t mutex;
} JobList;

/* 	Functions	*/
void *jobs_thread(void *);
void init_joblist(void);
int  add_job(Sensor *, Session *, void *);
int execute_job(int (*func)(), void *params);

#endif /* _JOB_H */
