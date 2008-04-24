#ifndef _ALERT_H
#include "data.h"

typedef struct _Alert {
	struct tuple4 addr; /*fields are in Network Byte Order*/
	int proto;
	int severity;
	char *msg;
	unsigned char *data;
	int length;
}Alert;

typedef struct _AlertNode {
	Alert *alert;
	struct _AlertNode *next;
} AlertNode;

typedef struct _AlertList {
	AlertNode *head;
	AlertNode *tail;
	int cnt;
	pthread_mutex_t mutex;
	pthread_cond_t empty_cond;
} AlertList;

void init_alertlist(void);
int push_alert(Alert *);
void pop_alert(void (*func)(Alert *));
void *alert_thread(void *);
#endif /* _ALERT_H */
