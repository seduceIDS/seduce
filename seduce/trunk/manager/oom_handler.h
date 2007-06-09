#ifndef _OOM_HANDLER_H
#define _OOM_HANDLER_H

#include "thread.h"

extern pthread_mutex_t oom_mutex;
extern pthread_cond_t oom_cond;

/* definitions */
void init_oom_handler(void);
void *oom_handler();

#endif /* _OOM_HANDLER_H */
