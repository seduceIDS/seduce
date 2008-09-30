#include "thread.h"
#include "errors.h"


inline void create_thread(void *(*func)(void *), void *data)
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


inline void mutex_init(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_init (mutex, NULL);
	if (status != 0)
		err_abort (status, "Init mutex");
}

inline void mutex_destroy(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_destroy(mutex);
	if (status != 0)
		err_abort (status, "Destroy mutex");
}

inline void mutex_lock(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_lock (mutex);
	if (status != 0)
		err_abort (status, "Lock mutex");
}

inline void mutex_unlock(pthread_mutex_t *mutex)
{
	int status;

	status = pthread_mutex_unlock (mutex);
	if (status != 0)
		err_abort (status, "Unlock mutex");
}

inline void cond_init(pthread_cond_t *cond)
{
	int status;

	status = pthread_cond_init (cond, NULL);
	if (status != 0)
		err_abort (status, "Init condition");
}

inline void cond_destroy(pthread_cond_t *cond)
{
	int status;

	status = pthread_cond_destroy (cond);
	if (status != 0)
		err_abort (status, "Destroy condition");
}

inline void cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	int status;

	status = pthread_cond_wait(cond, mutex);
	if (status != 0)
		err_abort (status, "Wait on condition");
}

inline void cond_signal(pthread_cond_t *cond)
{
	int status;

	status = pthread_cond_signal(cond);
	if (status != 0)
		err_abort (status, "Signal condition");
}

