#include "detect_engine.h"

char *threat_payload = NULL;
size_t threat_length = 0;

int execute_work(char *data, size_t len)
{
	static int times = 0;

	times++;

	if(times < 10) {
		fprintf(stderr, "work done\n");
		return WORK_DONE;
	}
	else {
		fprintf(stderr,"Thread detected\n");
		times = 0;
		return THREAT_DETECTED;
	}
}
 
