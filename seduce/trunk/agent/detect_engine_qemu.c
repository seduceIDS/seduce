#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "qemu.h"
#include "exec-all.h"
#include "debug.h"
#include "detect_engine.h"
#include "detect_engine_qemu.h"

DetectEngine engine = {
	.name = "QEMU Engine",
	.init = &qemu_engine_init,
	.destroy = &qemu_engine_destroy,
	.reset = &qemu_engine_reset,
	.process = &qemu_engine_process
};

extern unsigned long x86_stack_size;

static QemuVars qv;

/* Globals */
sigjmp_buf env;


void sigvtalrm_handler(int signum)
{
    tb_lock = SPIN_LOCK_UNLOCKED;
    siglongjmp(env, 100);
}

static void cleanup(void)
{
    int c;
    for (c = 1; c < 24; c++)
    {
        free(struct_entries[c].field_offsets[0]);
        free(struct_entries[c].field_offsets[1]);
    }
    memset(struct_entries, 0, sizeof(StructEntry) * 128);
}

static char *getBlock(char *data, size_t len, int min, int reset)
{
    data[len - 1] = 0;

    static char *p = NULL;
    if (reset) p = data;
    char *last;
    
    for (last = p; p < data + len; p++)
    {
        if (!*p)
        {
            if (p - last < min)
                last = p + 1;
            else
            {
                p++;
                return last;
            }
        }
    }
    return NULL;
}

/*
 * Function: qemu_engine_process()
 *
 * Purpose: Process a new data group with the Qemu emulator. 
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
int qemu_engine_process(char *data, size_t len, Threat *threat)
{
    char *p;
    void *block;
    int reset = 1, blocksize, l = 0, i, ret;
    char tmp[51];
    memset(tmp, 0, 51);

    if((data == NULL) || (len == 0))
        return 0;
 
    while ((p = getBlock(data, len, 30, reset)) != NULL)
    {
        reset = 0;
        l++;

        blocksize = strlen(p);
        block = calloc(1, blocksize + 1);
        if (block == NULL) {
            fprintf(stderr,"calloc failed\n");
            exit(1);
        }

        for (i = 0; i < blocksize - 5; i++)
        {
            memcpy(block, p, blocksize);
            DPRINTF("block %d - byte %.2d - ", l, i);
            if (sigsetjmp(env,1) == 100) {
                DPRINTF("Endless Loop detected!\n");
                setitimer(ITIMER_VIRTUAL, &qv.zvalue, (struct itimerval*) NULL);
                goto prepare_next_iter;
            }
    	    setitimer(ITIMER_VIRTUAL, &qv.value, (struct itimerval*) NULL);
            ret = qemu_exec(block + i, blocksize - i, qv.stack_base, qv.cpu);
            setitimer(ITIMER_VIRTUAL, &qv.zvalue, (struct itimerval*) NULL);

            switch(ret)
            {
                case HIGH_RISK_SYSCALL:
                    DPRINTF("High risk syscall - %d\n", qv.cpu->regs[R_EAX]);
                    threat->payload = calloc(1, blocksize + 1);
                    memcpy(threat->payload, p, blocksize);
                    threat->length = blocksize;
                    threat->severity = SEVERITY_HIGH;
                    snprintf(tmp, 50, "High risk syscall %d detected", qv.cpu->regs[R_EAX]);
                    threat->msg = strdup(tmp);
                    cleanup();
                    free(block);
                    return 1;
                case EXIT_SYSCALL:
                    DPRINTF("Syscall exit\n");
                    break;
                case EXCEPTION_INTERRUPT:
                    DPRINTF("exception - INTERRUPT\n");
                    break;
                case EXCEPTION_NOSEG:
                    DPRINTF("exception - NOSEG\n");
                    break;
                case EXCEPTION_STACK:
                    DPRINTF("exception - Stack Fault\n");
                    break;
                case EXCEPTION_GPF:
                    DPRINTF("exception - General Protection Fault\n");
                    break;
                case EXCEPTION_PAGE:
                    DPRINTF("exception - Page Fault\n");
                    break;
                case EXCEPTION_DIVZ:
                    DPRINTF("exception - Division by Zero\n");
                    break;
                case EXCEPTION_SSTP:
                    DPRINTF("exception - SSTP\n");
                    break;
                case EXCEPTION_INT3:
                    DPRINTF("exception - INT3\n");
                    break;
                case EXCEPTION_INTO:
                    DPRINTF("exception - INTO\n");
                    break;
                case EXCEPTION_BOUND:
                    DPRINTF("exception - BOUND\n");
                    break;
                case EXCEPTION_ILLOP:
                    DPRINTF("exception - Illegal Operation\n");
                    break;
                case EXCEPTION_DEBUG:
                    DPRINTF("exception - DEBUG\n");
                    break;
                default:
                    DPRINTF("unknown exception\n");
            }
prepare_next_iter:
            cleanup();
        }
        free(block);
    }
    return 0;
}

/*
 * Function: qemu_engine_init()
 *
 * Purpose: Initialize important structures for the Qemu engine.
 *
 * Arguments:
 *
 * Returns:   0 => Error occured
 *            1 => Everything ok
 */
int qemu_engine_init(void)
{
    struct sigaction sa;

    sa.sa_handler = sigvtalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGVTALRM, &sa, NULL) == -1)
    {
        perror("sigaction sigvtalrm");
        return 0;
    }

    qv.value.it_interval.tv_usec =
    qv.value.it_value.tv_usec = 1000;
    qv.value.it_interval.tv_sec =
    qv.value.it_value.tv_sec = 0;

    qv.zvalue.it_interval.tv_sec =
    qv.zvalue.it_interval.tv_usec =
    qv.zvalue.it_value.tv_sec =
    qv.zvalue.it_value.tv_usec = 0;

    qv.cpu = malloc(sizeof(CPUX86State));
    if (qv.cpu == NULL)
    {
        perror("malloc CPUX86State");
        return 0;
    }
    qv.stack_base = setup_stack();

    return 1;
}

/*
 * Function: qemu_engine_destroy()
 *
 * Purpose: Shut down the qemu engine
 *
 * Arguments:
 *
 * Returns:
 */
void qemu_engine_destroy(void)
{
    free(qv.cpu);

    if (munmap((void *)qv.stack_base - x86_stack_size, x86_stack_size) == -1)
    {
        perror("munmap stack_base");
        exit(1);
    }
}

/*
 * Function: qemu_engine_reset()
 *
 * Purpose: Not used by Qemu engine
 *
 * Arguments:
 *
 * Returns:
 */
void qemu_engine_reset(void)
{
	/* We don't use this function but it is required by
     * the agent implementation.
     */
	return;
}

