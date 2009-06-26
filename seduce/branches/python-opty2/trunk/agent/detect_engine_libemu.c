#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect_engine.h"
#include "utils.h"

#include <emu/emu.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_memory.h>

/* function prototypes */

int libemu_engine_process(char *, size_t, Threat *);
int libemu_engine_init(void);
void libemu_engine_reset(void);
void libemu_engine_destroy(void);

DetectEngine engine = {
	.name = "Libemu Engine",
	.init = &libemu_engine_init,
	.destroy = &libemu_engine_destroy,
	.reset = &libemu_engine_reset,
	.process = &libemu_engine_process
};

static struct emu *emu = NULL; /* the libemu handler */

/*
 * Function: libemu_engine_process()
 *
 * Purpose: Process a new data group with the libemu engine. 
 *
 * Arguments:
 *           data => A character array with the data to process
 *           len  => The character array length
 *           threat => The threat data structure to be filled in if a
 *           		threat has been detected (see return value 1)
 *
 * Returns:   0 => No threat detected
 *            1 => Threat detected
 *           -1 => An error occured
 */
int libemu_engine_process(char *data, size_t len, Threat *threat)
{
	int offset;
	const char *p;
	int block_size, block_num = 0;
	char threat_msg[51];
	void *block;

	if((data == NULL) || (len == 0))
		return 0;

	if (!emu) {
		fprintf(stderr, "error: libemu_engine_process called with "
				"uninitialised libemu environment\n");
		return -1;
	}

	while((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
				  block_num++))) 
	{
		block = malloc(block_size);
		if (block == NULL) {
			perror("malloc failed while building block\n");
			return -1;
		}

		memcpy(block, p, block_size);

		offset = emu_shellcode_test(emu,(uint8_t *)block,block_size);

		emu_memory_clear(emu_memory_get(emu));

		if (offset >= 0) {
			DPRINTF("libemu detected shellcode at offset %d\n", 
				offset);
			threat->payload = block;
			threat->length = block_size;
                        threat->severity = SEVERITY_HIGH;
			snprintf(threat_msg, 50, 
				"shellcode detected at offset %d",
				offset);
			threat->msg = strdup(threat_msg);
                        return 1;
		}
		free(block);
	}
	return 0;
}

/*
 * Function: libemu_engine_init()
 *
 * Purpose: Initialize important structures for the libemu engine.
 *
 * Arguments:
 *
 * Returns:   0 => Error occured
 *            1 => Everything ok
 */
int libemu_engine_init(void)
{
	if(emu){
		fprintf(stderr, "error: libemu engine has already been "
				"initialised!\n");
		return 0;
	}

	emu = emu_new();
	if (!emu) {
		fprintf(stderr, "error: could not initialise libemu!\n");
		return 0;
	}
	return 1;
}

/*
 * Function: libemu_engine_destroy()
 *
 * Purpose: Shut down the libemu engine
 *
 * Arguments:
 *
 * Returns:
 */
void libemu_engine_destroy(void)
{
	if (emu)
		emu_free(emu);
}

/*
 * Function: libemu_engine_reset()
 *
 * Purpose: Not used by libemu engine
 *
 * Arguments:
 *
 * Returns:
 */
void libemu_engine_reset(void)
{
	/* 
	 * We don't use this function but it is required by the agent 
	 * implementation.* 
	 */

	return;
}

