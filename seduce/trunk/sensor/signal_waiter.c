#include "signal_waiter.h"
#include "thread.h"
#include "utils.h"
#include "data.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

static sigset_t signal_set;

static void dump_time_measurements(void)
{
       int i, remainder;
       time_t *sec;
       suseconds_t *usec;
       char filename[] = "/tmp/seduce.out";
       FILE * fp;

       fp = fopen(filename, "w");

       for (i = 0; i < MEASURED_TIMES; i++) {

               sec = & measured_times[i].tv_sec;
               usec = & measured_times[i].tv_usec;

               remainder = *sec % SAMPLE_NUMBER;
               remainder *= 1000000;
               remainder /= SAMPLE_NUMBER;
               
               *sec /= SAMPLE_NUMBER;
               *usec /= SAMPLE_NUMBER;
               *usec += remainder;

               if(*usec >= 1000000) {
                       *usec -= 1000000;
                       *sec += 1;
               }

               fprintf(fp, "%d:\t%llu\t%llu\n", i+1,
                               (long long int)*sec, (long long int)*usec);
       }

       fclose(fp);
}

static void compute_stats(void)
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
			dump_time_measurements();
			exit(0);
		default:
			printf("Ignoring signal with ID: %d.\n", sig_number);
		}
	}

	return NULL;
}

