#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detect_engine.h"

#define TIMES	10

char *threat_payload;
size_t threat_length;

void sigvtalrm_handler(int signum)
{
	return;
}

void detect_engine_init(QemuVars *qv)
{
	return;
}

void detect_engine_stop(QemuVars *qv)
{
	return;
}

int execute_work(char *data, size_t len, QemuVars *qv)
{
	static int times = 0;

	if((data == NULL) || (len == 0))
		return WORK_DONE;
	times++;

	if(times < TIMES) {
		fprintf(stderr, "work done\n");
		return NEED_NEXT;
	}
	else {
		fprintf(stderr,"Thread detected\n");
		times = 0;
		threat_length = strlen("Example threat");
		threat_payload = malloc(threat_length + 1);
		strcpy(threat_payload,"Example threat");
		return THREAT_DETECTED;
	}
}
