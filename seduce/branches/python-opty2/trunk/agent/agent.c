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
#include <sys/wait.h>

#include "detect_engine.h"
#include "sensor_contact.h"
#include "item_selection.h"
#include "alert.h"
#include "error.h"
#include "options.h"
#include "utils.h"

struct ProgVars {
        DetectEngine *detect_engine;	/* registered detection engine */
        SensorSession *sensor_session;	/* current sensor session */
	SelectionMethod select_sensor; 	/* "Next sensor" selection method */
	int max_children;		/* the size of the child_pids array */
	int running_children;		/* the actual number of running procs */
	pid_t *child_pids;		/* an array holding the child PIDs */
} pv;

/* The linked-in engine will export this */
extern DetectEngine engine;

/*
 * Function: sensor_connect()
 *
 * Purpose: use the sensor address/port info of pv and connect to the sensor
 *
 * Arguments:
 *
 * Returns:  1 => Connected 
 *           0 => Not Connected
 */
static int sensor_connect(Sensor *m, const char * pwd, int timeout, int retries)
{
	int ret;
	
	pv.sensor_session = init_session(m->addr, m->port, pwd, timeout, 
					 retries);
	if(pv.sensor_session == NULL)
		critical_error(1, "Unable to connect to: %s:%u\n", 
			       inet_ntoa(m->addr), ntohs(m->port));

	ret = sensor_request(pv.sensor_session, SEND_NEW_AGENT);
	if(ret == -1) {
		/* 
		 * If something needs to be cleaned up before quiting,
		 * here is the place to do it.
		 */
		critical_error(1, "Bad communication with sensor: %s:%u\n",
			       inet_ntoa(m->addr), ntohs(m->port));
	}

	return ret;
}

/*
 * Function: sensor_disconnect()
 *
 * Purpose: Disconnect from the sensor and release all resources
 *
 * Arguments:
 *
 * Returns: 
 */
static void sensor_disconnect(void)
{
	if (pv.sensor_session) {
		sensor_request(pv.sensor_session, SEND_QUIT);
		destroy_session(&pv.sensor_session);
	}
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
static const Work * get_new_work()
{
	int ret;

	ret = sensor_request(pv.sensor_session, SEND_NEW_WORK);

	if(ret == 1)
		return fetch_current_work(pv.sensor_session);
	else if(ret == -1)
		critical_error(1, "The communication with the sensor is bad");

	/* ret == 0 */
	return NULL;
}

/*
 * Function: get_next_work()
 *
 * Purpose: Get the next data of a particular work group from the sensor
 *
 * Arguments:
 *
 * Returns:  NULL => No next Data available
 *           work => next data in this data_group
 */
static const Work * get_next_work(void)
{
	int ret;

	ret = sensor_request(pv.sensor_session, SEND_GET_NEXT);

	if(ret == 1)
		return fetch_current_work(pv.sensor_session);
	else if(ret == -1)
		critical_error(1, "The communication with the sensor is bad");

	/* ret == 0 */
	return NULL;
}

/* returns NULL only when there was a problem connecting to a sensor */

static const Work * find_work(InputOptions *in)
{
	static Sensor *last_sensor = NULL;
	int failed_polls = 0;
	int sensor_sz = sizeof(Sensor);
	const Work *w;

	do {
		Sensor *m;

		m = pv.select_sensor(in->num_sensors, in->sensors, sensor_sz);

		DPRINTF("polling sensor: %s:%u\n",
			inet_ntoa(m->addr), ntohs(m->port));

		/* this happens both in the random case, and when there's
		 * a single sensor in the list */
		if (last_sensor && m == last_sensor) {
			if (!(w = get_new_work())) {
                                DPRINTF("No work available on %s:%u. "
					"I'll sleep\n", inet_ntoa(m->addr),
					ntohs(m->port));

				sleep(in->no_work_wait);
				w = get_new_work();
				/*
				 * If this second try fails,
				 * we look for a new sensor
				 */
			} 

		} else {
			/* a new sensor was selected */
			sensor_disconnect();

			if(!sensor_connect(m, in->password, in->timeout, 
					    in->retries))
				return NULL;

			last_sensor = m;
			
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

static void child_shutdown(void)
{
	pv.detect_engine->destroy();
	DPRINTF("process %d sending QUIT Message to sensor...\n", getpid());
	sensor_disconnect();
}

void child_quit_handler(int s)
{
	child_shutdown();
	exit(0);
}

static void kill_all_children(void)
{
	int i; 
	pid_t pid;
	
        for(i = 0; i < pv.max_children; i++){
                if ((pid = pv.child_pids[i]) != 0) {
                        DPRINTF("sending TERM signal to process %d\n", pid);
                        kill(pid, SIGTERM);
                }
        }

	while(pv.running_children > 0)
		pause();
}

void father_quit_handler(int s)
{
	kill_all_children();
	exit(0);
}

void child_reaper(int s)
{
	int status, i;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status))
			fprintf(stderr, "child %d exited with status %d\n",
				pid, WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			fprintf(stderr, "child %d exited with signal %d\n",
				pid, WTERMSIG(status));

		for(i = 0; i < pv.max_children; i++) {
			if (pv.child_pids[i] == pid) {
				pv.child_pids[i] = 0;
				pv.running_children -= 1;
			}
		}
	}
}


/* returns 0 if there's an error contacting a sensor,
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

		/* reset the detection engine */
		pv.detect_engine->reset();
	
		do {
			struct in_addr src_addr;
			src_addr.s_addr = htonl(w->info.s_addr);

			DPRINTF_MD5(w->payload, w->length, 
				    "Inspecting new work [src:%s]\n",
				    inet_ntoa(src_addr));

			ret = pv.detect_engine->process(w->payload,
							w->length,&t);
			if (ret == 1) {
			     	DPRINTF_MD5(w->payload, w->length, 
					    "Threat Detected [src:%s]\n",
					    inet_ntoa(src_addr));

				/* send the threat */
				alert_ret = submit_alert(pv.sensor_session,
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
	child_shutdown(); /* this takes care of sending quit to the server
			     and destroying the detection engine */
	return retval;
}


/* returns PID of newly spawned process or 0 if an error was encountered */

static pid_t spawn_child(InputOptions *in)
{
	pid_t pid;
	struct sigaction sa;

	if ((pid = fork())== -1) {
		perror("error while forking child process");
		return 0;
	}
	
	if (!pid) { /* child code */
		/* initialize handlers for quiting */
		sa.sa_handler = child_quit_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		
		if (sigaction(SIGTERM, &sa, NULL) == -1) {
			perror("sigaction SIGTERM");
			exit(2);
		}
	
		sa.sa_handler = SIG_IGN;
		if (sigaction(SIGINT, &sa, NULL) == -1) {
			perror("sigaction SIGINT");
			exit(2);
		}

		sa.sa_handler = SIG_DFL;
		sa.sa_flags = SA_NOCLDSTOP;
		if (sigaction(SIGCHLD, &sa, NULL) == -1) {
			perror("sigaction SIGCHLD");
			exit(2);
		}
	
		/* this MUST happen within the context of the process that 
		   will call main_loop */
		srand((unsigned int) getpid());

		/* Everything is ready, go to the main loop */
		main_loop(in);

		/* exiting the main loop means something went wrong */
		exit(1);
	}

	/* parent code */
	pv.running_children += 1;
	return pid;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	InputOptions *in;
	int i;
	
	pv.detect_engine = &engine;
	
	/* get the input options */
	if ((in = fill_inputopts(argc, argv)) == NULL)
		return 1;

	if (in->polling == RANDOM)
		pv.select_sensor = &random_selection;
	else
		pv.select_sensor = &round_robin_selection;
	
	pv.max_children = in->children;

	if (!(pv.child_pids = malloc(pv.max_children * sizeof(pid_t)))) {
		perror("error allocating memory for child pid array");
		return 1;
	}

	memset(pv.child_pids, 0, pv.max_children * sizeof(pid_t));

	pv.running_children = 0;

	/* initialize handlers for quiting */
	sa.sa_handler = father_quit_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction SIGINT");
		return 1;
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction SIGTERM");
		return 1;
	}

	sa.sa_handler = child_reaper;
	sa.sa_flags = SA_NOCLDSTOP;

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction SIGCHLD");
		return 1;
	}

	for(i = 0; i < pv.max_children; i++) {
		if (!(pv.child_pids[i] = spawn_child(in)))
			goto err;
	}

	while (1) {
		pause();

		/* If we get here, 1 or more children have died.
		   We thus ressurect them */

		for(i = 0; i < pv.max_children; i++) {
			if ((pv.child_pids[i] == 0) && 
			    (!(pv.child_pids[i] = spawn_child(in))))
				goto err;
		}

	}

err:
	/* reached only on error */
	kill_all_children();
	destroy_inputopts(in);
	free(pv.child_pids);
	return 1;
}
