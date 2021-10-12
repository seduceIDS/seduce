#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "manager_protocol.h"
#include "item_selection.h"
#include "detection_engine.h"
#include "utils.h"
#include "options.h"
#include "error.h"
#include "alert.h"

static ManagerSession *manager_session = NULL; /* current manager session */
static SelectionMethod select_manager; /* "Next manager" selection method */
static Manager *mgr_ctx = NULL; /* used by the manager selection method */

/*
 * Function: manager_disconnect()
 * Purpose: Disconnect from the manager and release all resources
 */
static void manager_disconnect(void)
{
	if (manager_session) {
		manager_request(manager_session, SEND_QUIT);
		destroy_session(&manager_session);
	}
}


static void destroy_single_engine(DetectionEngine *e, void *param) 
{
	e->destroy();
}


static void init_single_engine(DetectionEngine *e, void *param)
{
	e->init();
}


static void reset_single_engine(DetectionEngine *e, void *param)
{
	e->reset();
}

static void worker_shutdown(void)
{
	apply_to_engines(&destroy_single_engine, NULL);
	DPRINTF("process %d sending QUIT Message to manager...\n", getpid());
	manager_disconnect();
}


static void worker_quit_handler(int signum)
{
	worker_shutdown();
	exit(signum);
}


/*
 * Function: get_new_work()
 *
 * Purpose: Get a new data group by the sensor
 *
 * Arguments:
 *
 * Returns:  NULL => No new Data group available
 *           work => Data Group's Heading data
 */
static const Work *get_new_work()
{
	int ret;

	ret = manager_request(manager_session, SEND_NEW_WORK);

	if(ret == 1)
		return fetch_current_work(manager_session);
	else if(ret == -1)
		critical_error(1, "Bad communication with manager");

	/* ret == 0 */
	return NULL;
}


/*
 * Function: manager_connect()
 *
 * Purpose: use the manager address/port info to connect to the manager
 *
 * Arguments:
 *
 * Returns:  1 => Connected 
 *           0 => Not Connected
 */
static int manager_connect(Manager *m, const char *pwd, int timeout, int retries)
{
	int ret;
	
	manager_session = init_session(m->addr, m->port, pwd, timeout, 
					 retries);
	if(manager_session == NULL)
		critical_error(1, "Unable to connect to: %s:%u\n", 
			       inet_ntoa(m->addr), ntohs(m->port));

	ret = manager_request(manager_session, SEND_NEW_AGENT);
	if(ret == -1) {
		/* 
		 * If something needs to be cleaned up before quiting,
		 * here is the place to do it.
		 */
		critical_error(1, "Bad communication with manager: %s:%u\n",
			       inet_ntoa(m->addr), ntohs(m->port));
	}

	return ret;
}


/* returns NULL only when there was a problem connecting to a manager */

static const Work * find_work(InputOptions *in)
{
	static Manager *last_manager = NULL;
	int failed_polls = 0;
	int manager_sz = sizeof(Manager);
	const Work *w;

	do {
		Manager *m;

		m = select_manager(in->num_managers, in->managers, manager_sz, (void **) &mgr_ctx);

		DPRINTF("polling manager: %s:%u\n",
			inet_ntoa(m->addr), ntohs(m->port));

		/* this happens both in the random case, and when there's
		 * a single manager in the list */
		if (last_manager && m == last_manager) {
			if (!(w = get_new_work())) {
                                DPRINTF("No work available on %s:%u. "
					"I'll sleep\n", inet_ntoa(m->addr),
					ntohs(m->port));

				sleep(in->no_work_wait);
				w = get_new_work();
				/*
				 * If this second try fails,
				 * we look for a new manager
				 */
			} 

		} else {
			/* a new manager was selected */
			manager_disconnect();

			if(!manager_connect(m, in->password, in->timeout, 
					    in->retries))
				return NULL;

			last_manager = m;
			
			if (!(w = get_new_work())) {
				failed_polls++;
				if (failed_polls >= in->max_polls) {
					failed_polls = 0;
					DPRINTF("max_polls reached, "
						"going to sleep...\n");
					sleep(in->no_work_wait);
				}
			}
		}

	} while(w == NULL);

	return w;
}

/* returns -1 if there was an error while sending the alert */

static int process_work(const Work *w)
{
	DetectionEngine *e, **ctx = NULL;
	int alert_ret, proc_ret, retval = 0;
	Threat t;
#ifdef _DEBUG
	struct in_addr src_addr;
	src_addr.s_addr = htonl(w->info.s_addr);
#endif

	DPRINTF_MD5(w->payload, w->length, 
		    "Inspecting new work [src:%s]\n", 
		    inet_ntoa(src_addr));

	while((e = cycle_engines(&ctx))) {
		proc_ret = e->process(w->payload, w->length, &t);
		if (proc_ret == 1) {
		     	DPRINTF_MD5(w->payload, w->length, 
				    "Threat Detected [src:%s]\n",
				    inet_ntoa(src_addr));

			/* send the threat */
			alert_ret = submit_alert(manager_session,
					 	 &w->info,&t);
					 
			destroy_threat(&t);
		 	if (alert_ret <= 0) {
				fprintf(stderr,"Couln't send alert\n");
				retval = -1;
				break;
			}

		} else if (proc_ret == -1) {
			/* detection engine error */
			/* TODO: we consider this non-lethal ... */
			fprintf(stderr, "Error processing packet with engine %s\n", 
				e->name);
                        DPRINTF_MD5(w->payload, w->length,
                                    "[src:%s]\n", inet_ntoa(src_addr));
		}
	}
	return retval;
}


/*
 * Function: get_next_work()
 *
 * Purpose: Get the next data of a particular work group from the manager
 *
 * Arguments:
 *
 * Returns:  NULL => No next Data available
 *           work => next data in this data_group
 */
static const Work * get_next_work(void)
{
	int ret;

	ret = manager_request(manager_session, SEND_GET_NEXT);

	if(ret == 1)
		return fetch_current_work(manager_session);
	else if(ret == -1)
		critical_error(1, "The communication with the sensor is bad");

	/* ret == 0 */
	return NULL;
}


/* returns 0 if there's an error contacting a manager,
  	  -1 if there's an error during alert submission */

static int main_loop(InputOptions *in)
{
	const Work *w;
	int retval = 0;

	/* init all engines */
	apply_to_engines(&init_single_engine, NULL);

	while((w = find_work(in))) {
		DPRINTF("Got new data_group\n");

		/* reset all engines */
		apply_to_engines(&reset_single_engine, NULL);
	
		do {
			retval = process_work(w);
			if (retval == -1)
				goto err;

		} while((w = get_next_work()) != NULL);
	}
err:
	worker_shutdown(); /* this takes care of sending quit to the server
			      and destroying the detection engines */
	return retval;
}

void worker_init(InputOptions *in) 
{
	struct sigaction sa;

	/* initialize handlers for quiting */
	sa.sa_handler = worker_quit_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("error while registering worker SIGTERM handler");
		exit(2);
	}

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("error while registering worker SIGINT handler");
		exit(2);
	}

	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("error while registering worker SIGCHLD handler");
		exit(2);
	}

	/* this MUST happen within the context of the process that 
	   will call main_loop */
	srand((unsigned int) getpid());

	if (in->polling == RANDOM)
		select_manager = &random_selection;
	else
		select_manager = &round_robin_selection;

	/* Everything is ready, go to the main loop */
	main_loop(in);

	/* we exit the main loop only on critical fault */

	exit(1);
}


