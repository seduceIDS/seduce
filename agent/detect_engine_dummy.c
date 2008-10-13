#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detect_engine.h"
#include "utils.h"

#define TIMES	10

static int dummy_engine_init();
static void dummy_engine_destroy();
static int  dummy_engine_process();
static void dummy_engine_reset();

DetectEngine engine = {
	.name = "Dummy Engine",
	.init = &dummy_engine_init,
	.destroy = &dummy_engine_destroy,
	.reset = &dummy_engine_reset,
	.process = &dummy_engine_process
};

static int dummy_engine_init()
{
	DPRINTF("Dummy engine initialized\n");
	return 1;
}

static void dummy_engine_destroy()
{
	return;
}

static void dummy_engine_reset()
{
	DPRINTF("Dummy engine reset\n");
	return;
}

static int dummy_engine_process(char *data, size_t len, Threat *t)
{
	static int times = 0;
	static const char shellcode[] =
		"\xbe\x2d\x62\x03\xe1\xda\xc5\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
		"\x0c\x31\x72\x12\x83\xc2\x04\x03\x5f\x6c\xe1\x14\xf5\x7b\xbd"
		"\x4f\x5b\x1a\x55\x5d\x38\x6b\x42\xf5\x91\x18\xe5\x06\x85\xf1"
		"\x97\x6f\x3b\x87\xbb\x22\x2b\x9f\x3b\xc3\xab\x8f\x59\xaa\xc5"
		"\xe0\xee\x44\x19\xa8\x43\x1c\xf8\x9b\xe4\x1e";
	int size;
	
	if((data == NULL) || (len == 0))
		return -1;

	if(times++ < TIMES) {
		fprintf(stderr, "work done\n");
		return 0;
	}

	/* if we got this far, a threat must be returned */
	size = sizeof(shellcode);

	if((t->payload = malloc(size)) == NULL)
		return -1;

	memcpy(t->payload, shellcode, size);
	t->length = size;
	t->severity = SEVERITY_HIGH;
	t->msg = strdup("Example threat");

	DPRINTF("Threat detected\n");

	times = 0;
	return 1;
}
