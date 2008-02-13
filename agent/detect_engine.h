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

void sigvtalrm_handler(int signum);
void detect_engine_init(QemuVars *qv);
void detect_engine_stop(QemuVars *qv);
int execute_work(char *data, size_t len, QemuVars *qv);
#endif /* _DETECT_ENGINE_H */
