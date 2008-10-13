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
	if (pv.sensor_session){
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
		if (last_sensor && m == last_sensor){
			if (!(w = get_new_work())){
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
	sensor_disconnect();
	exit(0);
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
			src_addr.s_addr = w->info.s_addr;

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
	pv.detect_engine->destroy();
	sensor_disconnect();

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

	if (in->polling == RANDOM)
		pv.select_sensor = &random_selection;
	else
		pv.select_sensor = &round_robin_selection;
		

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
