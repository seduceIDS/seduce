#ifndef _DETECT_ENGINE_H
#define _DETECT_ENGINE_H

#include <stdio.h>    /* for size_t */
#include <sys/time.h> /* for struct itimerval */

#include "qemu.h"     /* for CPUX86State */

#define WORK_DONE 1
#define NEED_NEXT 2
#define THREAT_DETECTED 3

typedef struct _QemuVars {
    struct itimerval value;
    struct itimerval zvalue;
    unsigned long stack_base;
    CPUX86State *cpu;
} QemuVars;

#endif /* _DETECT_ENGINE_H */
