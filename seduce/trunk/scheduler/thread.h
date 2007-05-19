#ifndef _THREAD_H
#define _THREAD_H

#include <pthread.h>

void create_thread(void *(*func)(void *), void *data);

void mutex_init(pthread_mutex_t *mutex);
void mutex_destroy(pthread_mutex_t *mutex);
void mutex_lock(pthread_mutex_t *mutex);
void mutex_unlock(pthread_mutex_t *mutex);

void cond_init(pthread_cond_t *cond);
void cond_destroy(pthread_cond_t *cond);
void cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
void cond_signal(pthread_cond_t *cond);

#endif /* _THREAD_H */
