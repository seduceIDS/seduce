#include "thread.h"
#include "errors.h"


void create_thread(void *(*func)(void *), void *data)
{
	int status;
	pthread_t id;

	status = pthread_create(&id, NULL, func, data);
	if (status != 0)
		err_abort (status, "Create thread");
	status = pthread_detach(id);
	if (status != 0)
		err_abort (status, "Detach thread");
}


void mutex_init(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_init (mutex, NULL);
	if (status != 0)
		err_abort (status, "Init mutex");
}

void mutex_destroy(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_destroy(mutex);
	if (status != 0)
		err_abort (status, "Destroy mutex");
}

void mutex_lock(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_lock (mutex);
	if (status != 0)
		err_abort (status, "Lock mutex");
}

void mutex_unlock(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_unlock (mutex);
	if (status != 0)
		err_abort (status, "Unlock mutex");
}

void cond_init(pthread_cond_t *cond)
{
	int status;

	status = pthread_cond_init (cond, NULL);
	if (status != 0)
		err_abort (status, "Init condition");
}

void cond_destroy(pthread_cond_t *cond)
{
	int status;

	status = pthread_cond_destroy (cond);
	if (status != 0)
		err_abort (status, "Destroy condition");
}

void cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	int status;

	status = pthread_cond_wait(cond, mutex);
	if (status != 0)
		err_abort (status, "Wait on condition");
}

void cond_signal(pthread_cond_t *cond)
{
	int status;

	status = pthread_cond_signal(cond);
	if (status != 0)
		err_abort (status, "Signal condition");
}

void signals_block(sigset_t *signal_set)
{
	int status;

	status = pthread_sigmask(SIG_BLOCK, signal_set, NULL);
	if (status != 0)
		err_abort (status, "Set signal mask");
}

