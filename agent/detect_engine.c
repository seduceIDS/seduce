#include "detect_engine.h"
#include <stdlib.h>

/* Parses data and returns a pointer to the next NUL delimited block
   making sure that the block returned is at least of min_len size.
   block_len contains the length of the block returned and 
   use_previous_data denotes if the function should continue on the same
   data buffer */
const char *get_next_block(const char *data, size_t len, int min_len, 
		     int *block_len, int use_previous_data)
{
	const char *p, *ret_val, *block_end, *block_next;

	static const char *block_start = NULL;
	const char *last_byte = data + len - 1;

	if (use_previous_data == 0)
		block_start = data;

	if (last_byte - block_start < min_len - 1)
		return NULL;

search:
	/* look for the terminator */
	block_end = block_next = NULL;

   	for(p = block_start; ((p <= last_byte) && (*p != '\0')); p++)
		;

	/* terminator was found */
	block_end = p - 1;

	if (!*p)
		block_next = p + 1;
	else  /* past last byte (that btw wasn't NUL) */
		block_next = p;

	/* 
	 * yes block_next might now point right after the buffer, 
	 * but that's not a bug, it's a feature!
	 */

	*block_len = block_end - block_start + 1;

	if ((*block_len < min_len) && (last_byte - block_next >= min_len - 1)) {
		/* small block found, other blocks follow */
		block_start = block_next;
		goto search;
	} else if (*block_len < min_len) {
		/* small block found, no other blocks follow */
		ret_val = NULL;
	} else {
		/* ok block found, other blocks might follow */
		ret_val = block_start;
		block_start = block_next;
	}

	return ret_val;
}

void destroy_threat(Threat *t)
{
	if(t->length)
		free(t->payload);

	if(t->msg)
		free(t->msg);
}
