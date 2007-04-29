#ifndef _ALERT_H
#include "data.h"

typedef struct _AlertNode {
	struct _AlertNode *next;
	struct tuple4 addr;
	IPProtocol proto;
	char *data;
	int length;
} AlertNode;

typedef struct _AlertList {
	AlertNode *head;
	AlertNode *tail;
	int cnt;
	pthread_mutex_t mutex;
	pthread_cond_t empty_cond;
} AlertList;

void init_alertlist(void);
int push_alert(struct tuple4 *, IPProtocol, char *, int);
void pop_alert(void);
void *alert_thread(void *);
#endif /* _ALERT_H */
