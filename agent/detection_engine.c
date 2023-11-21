#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "detection_engine.h"
#include "../config.h"

#ifdef HAVE_DUMMY 
        extern DetectionEngine dummy_engine; 
#endif 
#ifdef HAVE_QEMU 
        extern DetectionEngine qemu_engine; 
#endif 
#ifdef HAVE_LINUX_X86_64
	extern DetectionEngine uni_lx86_64_engine;
#endif
#ifdef HAVE_WINDOWS_X86
	extern DetectionEngine uni_windows_x86_engine;
#endif
#ifdef HAVE_LIBEMU 
        extern DetectionEngine libemu_engine; 
#endif 
#ifdef HAVE_YARA 
        extern DetectionEngine yara_engine; 
#endif 
#ifdef HAVE_FNORD 
        extern DetectionEngine fnord_engine; 
#endif 
#ifdef HAVE_PYOPTY2 
        extern DetectionEngine pyopty2_engine; 
#endif 
 
static DetectionEngine *avail_engines[] = { 
#ifdef HAVE_DUMMY 
        &dummy_engine, 
#endif 
#ifdef HAVE_QEMU 
        &qemu_engine, 
#endif 
#ifdef HAVE_LINUX_X86_64
	&uni_lx86_64_engine,
#endif
#ifdef HAVE_WINDOWS_X86
	&uni_windows_x86_engine,
#endif 
#ifdef HAVE_LIBEMU 
        &libemu_engine, 
#endif 
#ifdef HAVE_YARA
        &yara_engine, 
#endif 
#ifdef HAVE_FNORD 
        &fnord_engine, 
#endif 
#ifdef HAVE_PYOPTY2
        &pyopty2_engine, 
#endif 
        NULL 
}; 

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

#ifdef _NO_SPLIT_AT_NUL
	*block_len = len;
	ret_val = block_start;
	/* next block_start */
	block_start = data + len;
	return ret_val;
#endif

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

DetectionEngine *get_engine_by_name(char *name)
{
	DetectionEngine *p;
	int i;

	for(i=0; (p = avail_engines[i]) != NULL; i++) {
		if (!(strncmp(p->name, name, strlen(p->name)+1))) {
			return p;
		}
	}

	return NULL;
}

DetectionEngine *cycle_engines(DetectionEngine ***context)
{
	assert(context != NULL);

	/* reset point */
	if (*context == NULL || **context == NULL)
		*context = &avail_engines[0];
	else
		*context += 1;
	
	return **context;
}

int format_engine_list(char *buf, int bufsize)
{
	DetectionEngine *p;
	int chars, i;
	int rem = bufsize;
	int pos = 0;

	memset(buf, 0, bufsize);

	for (i=0; (p = avail_engines[i]) != NULL; i++) {
		chars = snprintf(buf + pos, rem, "%s : %s\n", p->name, p->descr);
		pos += chars;
		rem -= chars;
	}

	return pos;
}

void apply_to_engines(void (*fun)(DetectionEngine *, void *), void *param) {
	DetectionEngine *p;
	int i;

	for(i=0; (p = avail_engines[i]) != NULL; i++) {
		fun(p, param);
	}
}

