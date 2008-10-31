#ifndef _DETECT_ENGINE_QEMU_H
#define _DETECT_ENGINE_QEMU_H

#include <stdio.h>    /* for size_t */
#include <sys/time.h> /* for struct itimerval */

#include "qemu.h"     /* for CPUX86State */
#include "detect_engine.h"

typedef struct _QemuVars {
	struct itimerval value;
	struct itimerval zvalue;
	unsigned long stack_base;
	CPUX86State *cpu;
} QemuVars;

/* Blocks smaller than this are not emulated */
#define MIN_BLOCK_LENGTH        30

void sigvtalrm_handler(int signum);
int qemu_engine_process(char *data, size_t len, Threat *threat);
int qemu_engine_init(void);
void qemu_engine_destroy(void);
int qemu_engine_get_threat(Threat *t);
void qemu_engine_reset(void);

#endif /* _DETECT_ENGINE_QEMU_H */
