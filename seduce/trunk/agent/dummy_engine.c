#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TIMES	10

char *threat_payload;
size_t threat_length;

void dummy_engine_init()
{
	return;
}

void dummy_engine_stop()
{
	return;
}

int dummy_engine_process(char *data, size_t len)
{
	static int times = 0;

	if((data == NULL) || (len == 0))
		return 1; /* WORK_DONE */
	times++;

	if(times < TIMES) {
		fprintf(stderr, "work done\n");
		return 2; /* NEED_NEXT */
	}
	else {
		fprintf(stderr,"Thread detected\n");
		times = 0;
		threat_length = strlen("Example threat");
		threat_payload = malloc(threat_length + 1);
		strcpy(threat_payload,"Example threat");
		return 3; /* THREAT_DETECTED */
	}
}
