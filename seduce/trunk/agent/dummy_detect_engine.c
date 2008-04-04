#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detect_engine.h"

#define TIMES	10

void dummy_engine_init();
void dummy_engine_stop();
int  dummy_engine_process(char *data, size_t len);
int  dummy_engine_get_threat();

DetectEngine dummy_engine = {
	.init = &dummy_engine_init,
	.stop = &dummy_engine_stop,
	.process = &dummy_engine_process,
	.get_threat = &dummy_engine_get_threat
};

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

	if((data == NULL) || (len == 0)) {
		fprintf(stderr, "engine reset\n");
		return 0;
	}

	if(times++ < TIMES) {
		fprintf(stderr, "work done\n");
		return 0;
	}
	else {
		fprintf(stderr,"Thread detected\n");
		times = 0;
		return 1;
	}
}

int dummy_engine_get_threat(Threat *t)
{
	memcpy(t->payload, "\x01\x02\x03\x04", 4); 
	t->length = 4;
	t->severity = SEVERITY_HIGH;
	t->msg = strdup("Example threat");
	return 0;
}
