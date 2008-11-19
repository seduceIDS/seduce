#include "sensor.h"
#include "sniffer.h"
#include "agent_contact.h"
#include "options.h"
#include "data.h"
#include "alert.h"
#include "oom_handler.h"
#include "alert_recv.h"
#include "signal_waiter.h"

/* globals */
PV pv;

static inline void start_oom_handler(void)
{
	create_thread(oom_handler, NULL);
}

static inline void start_alert_thread(void)
{
	create_thread(alert_thread, NULL);
}

static inline void start_agents_thread(void)
{
	create_thread(agents_contact, NULL);
}

static inline void start_signal_thread(void)
{
	create_thread(signal_waiter, NULL);
}

int main(int argc, char *argv[])
{
	fill_progvars(argc, argv);

	/* Initialization functions */
	if(init_sniffer() == 0)
		return 1;
	init_datalists();
	init_alertlist();
	init_oom_handler();
	init_alert_receiver();
	/*
 	 * I need to be carefull with this one: init_signal_water should only
	 * be called by the main thread and before the creation of any other
	 * thread!!! It creates a signal mask that should be inherited by all
	 * threads in the process.
	 */
	init_signal_waiter();

	/* thread starting functions */
	start_signal_thread();
	start_alert_thread();
	start_agents_thread();
	start_oom_handler();

	/* All threads created, now sniff! */ 
	start_sniffer();

	/* This one is never executed */
	return 0;
}
