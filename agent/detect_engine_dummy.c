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
	.name = "Dummy Engine",
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
	printf("Dummy engine reset\n");
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
	} else {
		fprintf(stderr,"Thread detected\n");
		times = 0;
		return 1;
	}
}

static int dummy_engine_get_threat(Threat *t)
{
	static const char shellcode[] =
		"\xbe\x2d\x62\x03\xe1\xda\xc5\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
		"\x0c\x31\x72\x12\x83\xc2\x04\x03\x5f\x6c\xe1\x14\xf5\x7b\xbd"
		"\x4f\x5b\x1a\x55\x5d\x38\x6b\x42\xf5\x91\x18\xe5\x06\x85\xf1"
		"\x97\x6f\x3b\x87\xbb\x22\x2b\x9f\x3b\xc3\xab\x8f\x59\xaa\xc5"
		"\xe0\xee\x44\x19\xa8\x43\x1c\xf8\x9b\xe4\x1e";
	const size_t size = 71;

	t->payload = malloc(size);
	if(t->payload == NULL)
		return 0;

	memcpy(t->payload, shellcode, size);
	t->length = size;
	t->severity = SEVERITY_HIGH;
	t->msg = strdup("Example threat");
	return 1;
}
