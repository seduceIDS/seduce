#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "agent.h"
#include "alert.h"
#include "error.h"
#include "options.h"


/* Globals */
static ProgVars pv;

/*
 * Function: manager_connect()
 *
 * Purpose: use the server address/port info of pv and connect to the manager
 *
 * Arguments:
 *
 * Returns:  1 => Connected 
 *           0 => Not Connected
 */
static int manager_connect(struct in_addr addr, unsigned short port,
				const char * pwd, int timeout, int retries)
{
	int ret;
	
	pv.server_session = init_session(addr, port, pwd, timeout, retries);
	if(pv.server_session == NULL)
		critical_error(1, "Unable to initialize the connection info");

	ret = server_request(pv.server_session, SEND_NEW_AGENT);
	if(ret == -1) {
		
		/* 
		 * If something needs to be cleaned up before quiting,
		 * here is the place to do it.
		 */
		critical_error(1, "The communication with the server is bad");
	}

	return ret;
}

/*
 * Function: manager_disconnect()
 *
 * Purpose: Disconnect from the manager and release all resources
 *
 * Arguments:
 *
 * Returns: 
 */
static void manager_disconnect(void)
{
	server_request(pv.server_session, SEND_QUIT);
	destroy_session(pv.server_session);
}

/*
 * Function: get_new_work()
 *
 * Purpose: Get a new data group by the manager
 *
 * Arguments:
 *
 * Returns:  NULL => No new Data group available
 *           work => Data Group's Heading data
 */
static const Work * get_new_work()
{
	int ret;

	ret = server_request(pv.server_session, SEND_NEW_WORK);

	if(ret == 1)
		return fetch_current_work(pv.server_session);
	else if(ret == -1)
		critical_error(1, "The communication with the server is bad");

	/* ret == 0 */
	return NULL;
}

/*
 * Function: get_new_work()
 *
 * Purpose: Get a new data group by the manager
 *
 * Arguments:
 *
 * Returns:  NULL => No next Data available
 *           work => next data in this data_group
 */
static const Work * get_next_work(void)
{
	int ret;

	ret = server_request(pv.server_session, SEND_GET_NEXT);

	if(ret == 1)
		return fetch_current_work(pv.server_session);
	else if(ret == -1)
		critical_error(1, "The communication with the server is bad");

	/* ret == 0 */
	return NULL;
}

void quit_handler(int s)
{
	pv.detect_engine->destroy();
	printf("Sending QUIT Message...\n");
	manager_disconnect();
	exit(0);
}

static void main_loop(int wait_time)
{
	const Work *w;
	Threat t;
	int ret;

	pv.detect_engine->init();
	for (;;) {
		w = get_new_work();
		if(w == NULL) {
			printf("No work is available, I'll sleep\n");
			fflush(stdout);
			sleep(wait_time);
			continue;	
		}

		printf("Got a new data_group\n");

		/* reset the detect engine */
		pv.detect_engine->reset();
	
		do {
			printf("Detect data\n");
			ret = pv.detect_engine->process(w->payload, w->length);
			if(ret == 1) {
				printf("Threat Detected\n");
				pv.detect_engine->get_threat(&t);

				/* send the treat */
				ret = submit_alert(pv.server_session,
								&w->info, &t);
				destroy_threat(&t);
				if(ret <= 0) {
					fprintf(stderr,"Couln't send alert\n");
					quit_handler(0);
				}
			} else if(ret == -1) {
	
				/* detection engine error */
			}
		} while((w = get_next_work()) != NULL);
	}
}

/* Someone should export this */
extern DetectEngine engine;

int main(int argc, char *argv[])
{
	struct sigaction sa;
	InputOptions *in;
	int no_work_wait;
	
	pv.detect_engine = &engine;
	
	/* get the input options */
	in = fill_inputopts(argc, argv);
	if(in == NULL)
		goto err1;

	pv.prog_name = in->prog_name;

	no_work_wait = in->no_work_wait;

	/* Try to connect to the sceduler */
	if(!manager_connect(in->addr, in->port, in->password, in->timeout,
								in->retries)) {
		fprintf(stderr, "Can't connect to the scheduler\n");
		goto err2;
	}

	/* no longer needed */
	destroy_inputopts(in);

	/* if connected, initialize handlers for quiting */
	sa.sa_handler = quit_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	/* Everything is initialized, go to the main loop */
	main_loop(no_work_wait);

	/* never reached */
	return 0;

err2:
	destroy_inputopts(in);
err1:
	return 1;
}
