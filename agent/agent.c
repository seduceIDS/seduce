#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "detect_engine.h"
#include "server_contact.h"
#include "alert.h"
#include "error.h"
#include "options.h"
#include "utils.h"

struct ProgVars {
        DetectEngine *detect_engine;
        ServerSession *server_session;		    /* current server session */
	Manager *(*select_manager)(int, Manager *); /* manager selection
						       strategy */
} pv;

/* The linked-in engine will export this */
extern DetectEngine engine;

static Manager *select_manager_rnd(int num_servers, Manager *servers)
{
	int new_idx;

	new_idx = (int) (num_servers * (rand()/(RAND_MAX + 1.0)));

	return &servers[new_idx];
}

static Manager *select_manager_rr(int num_servers, Manager *servers)
{
	static Manager *current = NULL;
	Manager *last_on_list;

	last_on_list = servers + num_servers - 1;

	if (!current || current == last_on_list){
		current = &servers[0];
		return current;
	}

	current++;

	return current;
}

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
static int manager_connect(Manager *m, const char * pwd, int timeout, 
			   int retries)
{
	int ret;
	
	pv.server_session = init_session(m->addr, m->port, pwd, timeout, 
					 retries);
	if(pv.server_session == NULL)
		critical_error(1, "Unable to connect to: %s:%u\n", 
			       inet_ntoa(m->addr), ntohs(m->port));

	ret = server_request(pv.server_session, SEND_NEW_AGENT);
	if(ret == -1) {
		
		/* 
		 * If something needs to be cleaned up before quiting,
		 * here is the place to do it.
		 */
		critical_error(1, "Bad communication with server: %s:%u\n",
			       inet_ntoa(m->addr), ntohs(m->port));
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
	if (pv.server_session){
		server_request(pv.server_session, SEND_QUIT);
		destroy_session(&pv.server_session);
	}
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

	ret = server_request(pv.server_session, SEND_GET_NEXT);

	if(ret == 1)
		return fetch_current_work(pv.server_session);
	else if(ret == -1)
		critical_error(1, "The communication with the server is bad");

	/* ret == 0 */
	return NULL;
}

/* returns NULL only when there was a problem connecting to a server */

static const Work * find_work(InputOptions *in)
{
	static Manager *last_server = NULL;
	int failed_polls = 0;
	const Work *w;

	do {
		Manager *m;

		m = pv.select_manager(in->num_servers, in->servers);

		DPRINTF("polling manager: %s:%u\n",
			inet_ntoa(m->addr), ntohs(m->port));

		/* this happens both in the random case, and when there's
		 * a single server in the list */
		if (last_server && m == last_server){
			if (!(w = get_new_work())){
                                DPRINTF("No work available on %s:%u. "
					"I'll sleep\n", inet_ntoa(m->addr),
					ntohs(m->port));
				sleep(in->no_work_wait);
				w = get_new_work();
				/*
				 * If this second try fails,
				 * we look for a new server
				 */
			} 
		} else {
			/* a new server was selected */
			manager_disconnect();

			if(!manager_connect(m, in->password, in->timeout, 
					    in->retries))
				return NULL;

			last_server = m;
			
			if (!(w = get_new_work())){
				failed_polls++;
				if (failed_polls >= in->max_polls){
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

void quit_handler(int s)
{
	pv.detect_engine->destroy();
	DPRINTF("Sending QUIT Message...\n");
	manager_disconnect();
	exit(0);
}

/* returns 0 if there's an error contacting a server,
  	   1 if there's an error during alert submission */

static int main_loop(InputOptions *in)
{
	const Work *w;
	int ret;
	Threat t;
	int retval = 0;
	int alert_ret;

	pv.detect_engine->init();

	while((w = find_work(in))) {
		DPRINTF("Got new data_group\n");

		/* reset the detect engine */
		pv.detect_engine->reset();
	
		do {
			char md5sum[33];
			struct in_addr src_addr;

			src_addr.s_addr = w->info.s_addr;

			compute_md5(w->payload, w->length, md5sum);

			DPRINTF("Inspecting Data [src:%s] [%i bytes] [%s]\n",
 			       inet_ntoa(src_addr), w->length, md5sum);

			ret = pv.detect_engine->process(w->payload,
							w->length,&t);
			if (ret == 1) {
			     	DPRINTF("Threat Detected [src:%s] [%i bytes]"
				        " [%s]\n", inet_ntoa(src_addr), 
				        w->length, md5sum);

				/* send the threat */
				alert_ret = submit_alert(pv.server_session,
						 	 &w->info,&t);
						 
				destroy_threat(&t);
			 	if (alert_ret <= 0) {
					fprintf(stderr,"Couln't send alert\n");
					retval = 1;
					goto err;
				}
			} else if (ret == -1) {
				/* detection engine error */
				/* TODO: we consider this non-lethal ... */
				fprintf(stderr, "Error processing packet\n");
			}
		} while((w = get_next_work()) != NULL);
	}
err:
	pv.detect_engine->destroy();
	manager_disconnect();

	return retval;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	InputOptions *in;
	
	pv.detect_engine = &engine;
	
	/* get the input options */
	if ((in = fill_inputopts(argc, argv)) == NULL)
		return 1;

	if (in->sched_algo == RANDOM)
		pv.select_manager = &select_manager_rnd;
	else
		pv.select_manager = &select_manager_rr;
		

	/* initialize handlers for quiting */
	sa.sa_handler = quit_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		return 1;
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction");
		return 1;
	}

	/* this MUST happen within the context of the process that 
	   will call main_loop */
	srand((unsigned int) getpid());

	/* Everything is ready, go to the main loop */
	main_loop(in);

	destroy_inputopts(in);

	return 1;
}
