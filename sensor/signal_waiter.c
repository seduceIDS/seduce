#include "signal_waiter.h"
#include "thread.h"
#include "utils.h"
#include "data.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static sigset_t signal_set;

void compute_stats(void)
{
	StatUnit in, out, proto, oom, left;

	mutex_lock(&sensor.mutex);
	
	in = sensor.in;
	out = sensor.out;
	proto = sensor.proto_lost;
	oom = sensor.oom_lost;
	
	mutex_unlock(&sensor.mutex);

	left.pcks = in.pcks - out.pcks - oom.pcks - proto.pcks;
	left.bytes = in.bytes - out.bytes - oom.bytes - proto.bytes;

	printf("Sensor Statistics:\n");
	printf("                     Packets\tBytes\n");
	printf("Input:               %llu   \t%llu\n", in.pcks, in.bytes);
	printf("Consumed by Agents:  %llu   \t%llu\n", out.pcks, out.bytes);
	printf("Discarded by Agents: %llu   \t%llu\n", proto.pcks, proto.bytes);
	printf("Consumed by OOM:     %llu   \t%llu\n", oom.pcks, oom.bytes);
	printf("Left inside:         %llu   \t%llu\n", left.pcks, left.bytes); 
}

void init_signal_waiter(void)
{
	/* 
	 * Before I create the needed process threads, I need to mask out all
	 * the "interesting" signals. Because all threads inherit the signal
	 * mask from their creator, all threads in the process will have the
	 * "interesting" signals masked unless one explicititly unmasks it. We
	 * create a dedicated signal handling thread to wait for them.
	 */
	sigemptyset(&signal_set);
	sigaddset (&signal_set, SIGINT);

	signals_block(&signal_set);
}

void *signal_waiter(void *arg)
{
	int sig_number;

	while(1) {
		sigwait(&signal_set, &sig_number);

		switch(sig_number) {
		case SIGINT:
			compute_stats();
			exit(0);
		default:
			printf("Ignoring signal with ID: %d.\n", sig_number);
		}
	}

	return NULL;
}

