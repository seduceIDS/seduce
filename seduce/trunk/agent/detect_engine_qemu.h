#ifndef _DETECT_ENGINE_QEMU_H
#define _DETECT_ENGINE_QEMU_H

#include <stdio.h>    /* for size_t */
#include <sys/time.h> /* for struct itimerval */

#include "qemu.h"     /* for CPUX86State */

typedef struct _QemuVars {
    struct itimerval value;
    struct itimerval zvalue;
    unsigned long stack_base;
    CPUX86State *cpu;
} QemuVars;

#endif /* _DETECT_ENGINE_QEMU_H */