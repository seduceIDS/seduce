#include "sensor.h"
#include "sniffer.h"
#include "agent_contact.h"
#include "options.h"
#include "data.h"
#include "alert.h"
#include "oom_handler.h"
#include "alert_recv.h"

/* globals */
PV pv;

static void start_oom_handler(void)
{
	create_thread(oom_handler, NULL);
}

static void start_alert_thread(void)
{
	create_thread(alert_thread, NULL);
}

static void start_agents_thread(void)
{
	create_thread (agents_contact, NULL);
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

	/* thread starting functions */
	start_alert_thread();
	start_agents_thread();
	start_oom_handler();

	start_sniffer();

	/* This one is never executed */
	return 0;
}
