#ifndef _DETECT_ENGINE_LIBEMU_H
#define _DETECT_ENGINE_LIBEMU_H

#include <stdio.h>

#include "detect_engine.h"

/* Blocks smaller than this are not emulated */
#define MIN_BLOCK_LENGTH        30

int libemu_engine_init(void);
int libemu_engine_process(char *data, size_t len, Threat *threat);
void libemu_engine_reset(void);
void libemu_engine_destroy(void);

#endif
