#ifndef _DATA_GROUP_H
#define _DATA_GROUP_H

#include "thread.h"
#include "data.h"

typedef struct _Group {
	struct _Group *next;
	struct _Group *prev;
	DataInfo grouphead;
} Group;

typedef struct _GroupList {
	Group *head;
	Group *tail;
	int cnt;
	pthread_mutex_t mutex;
} GroupList;

/* 	Functions	*/
void init_grouplist(void);
int  add_group(Session *, void *);
int consume_group(int (*func)(), void *params);

#endif /* _DATA_GROUP_H */
