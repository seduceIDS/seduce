#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detect_engine.h"

#define TIMES	10

static int dummy_engine_init();
static void dummy_engine_destroy();
static int  dummy_engine_process();
static void dummy_engine_reset();
static int  dummy_engine_get_threat();

DetectEngine engine = {
	.init = &dummy_engine_init,
	.destroy = &dummy_engine_destroy,
	.reset = &dummy_engine_reset,
	.process = &dummy_engine_process,
	.get_threat = &dummy_engine_get_threat
};

static int dummy_engine_init()
{
	printf("Dummy engine initialized\n");
	return 1;
}

static void dummy_engine_destroy()
{
	return;
}

static void dummy_engine_reset()
{
	printf("Dummy engine destroyed\n");
	return;
}

static int dummy_engine_process(char *data, size_t len)
{
	static int times = 0;

	if((data == NULL) || (len == 0))
		return -1;

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

static int dummy_engine_get_threat(Threat *t)
{
	memcpy(t->payload, "\x01\x02\x03\x04", 4); 
	t->length = 4;
	t->severity = SEVERITY_HIGH;
	t->msg = strdup("Example threat");
	return 0;
}
