#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "qemu.h"
#include "exec-all.h"
#include "detect_engine.h"
#include "detect_engine_qemu.h"

#include "utils.h"

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

static char *get_next_block(char *data, size_t len, int min_len, int *block_len)
{
	static char *block_start = NULL;
	char *p, *ret_val, *block_end, *block_next;
	char *last_byte = data + len - 1;

	if (!block_start){
    		block_start = data;
	} else if (block_start > last_byte){
		/*
		 * WATCHOUT: this is the case where the last call to
		 * get_next_block returned the final block 
		 */
		block_start = NULL;
		return NULL;
	}

search:
	/* look for the terminator */
	block_end = block_next = NULL;
   	for(p = block_start; ((p <= last_byte) && (*p != '\0')); p++);

	/* terminator was found */
	block_end = p - 1;

	if (!*p){
		block_next = p + 1;
	} else { /* past last byte (that btw wasn't NUL) */
		block_next = p;
	}

	/* 
	 * yes block_next might now point right after the buffer, 
	 * but that's not a bug, it's a feature!
	 */

	*block_len = block_end - block_start + 1;

	if ((*block_len < min_len) && (last_byte - block_next >= min_len - 1))
	{
		/* small block found, other blocks follow */
		block_start = block_next;
		goto search;
	} else if (*block_len < min_len){
		/* small block found, no other blocks follow */
		ret_val = NULL;
		block_start = NULL;
	} else {
		/* ok block found, other blocks might follow */
		ret_val = block_start;
		block_start = block_next; /* see WATCHOUT */
	}

	return ret_val;
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
    int block_size, i, ret, block_num = 0;
    char threat_msg[51];

    if((data == NULL) || (len == 0))
        return 0;
 
    while ((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size)))
    {
        block_num++;

        block = malloc(block_size);
        if (block == NULL) {
            fprintf(stderr,"malloc failed while building block\n");
            exit(1);
        }
	memcpy(block, p, block_size);

        for (i = 0; i < block_size - 5; i++)
        {
            if (sigsetjmp(env,1) == 100) {
                DPRINTF("block %d byte %d - Endless Loop detected!\n",
			block_num, i);
                setitimer(ITIMER_VIRTUAL, &qv.zvalue, (struct itimerval*) NULL);
                goto prepare_next_iter;
            }

    	    setitimer(ITIMER_VIRTUAL, &qv.value, (struct itimerval*) NULL);
            ret = qemu_exec(block + i, block_size - i, qv.stack_base, qv.cpu);
            setitimer(ITIMER_VIRTUAL, &qv.zvalue, (struct itimerval*) NULL);

            switch(ret)
            {
                case HIGH_RISK_SYSCALL:
                    DPRINTF("block %d byte %d - High risk syscall - %d\n", 
		    	    block_num, i, qv.cpu->regs[R_EAX]);
                    threat->payload = block; /* we don't have to free this
		    				now, it will get free'd
						once the Threat is free'd */
                    threat->length = block_size;
                    threat->severity = SEVERITY_HIGH;
                    snprintf(threat_msg, 50, "High risk syscall %d detected", 
		    	     qv.cpu->regs[R_EAX]);
                    threat->msg = strdup(threat_msg);
                    cleanup();
                    return 1;
                case EXIT_SYSCALL:
                    DPRINTF("block %d byte %d - Syscall exit\n", block_num, i);
                    break;
                case EXCEPTION_INTERRUPT:
                    DPRINTF("block %d byte %d - exception - INTERRUPT\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_NOSEG:
                    DPRINTF("block %d byte %d - exception - NOSEG\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_STACK:
                    DPRINTF("block %d byte %d - exception - Stack Fault\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_GPF:
                    DPRINTF("block %d byte %d - exception - General Protection"
		    	    " Fault\n",block_num, i);
                    break;
                case EXCEPTION_PAGE:
                    DPRINTF("block %d byte %d - exception - Page Fault\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_DIVZ:
                    DPRINTF("block %d byte %d - exception - Division by Zero\n",			    block_num, i);
                    break;
                case EXCEPTION_SSTP:
                    DPRINTF("block %d byte %d - exception - SSTP\n",
		    	   block_num, i);
                    break;
                case EXCEPTION_INT3:
                    DPRINTF("block %d byte %d - exception - INT3\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_INTO:
                    DPRINTF("block %d byte %d - exception - INTO\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_BOUND:
                    DPRINTF("block %d byte %d - exception - BOUND\n",
		    	    block_num, i);
                    break;
                case EXCEPTION_ILLOP:
                    DPRINTF("block %d byte %d - exception - Illegal Operation\n"
		    	    ,block_num, i);
                    break;
                case EXCEPTION_DEBUG:
                    DPRINTF("block %d byte %d - exception - DEBUG\n",
		    	    block_num, i);
                    break;
                default:
                    DPRINTF("block %d byte %d - unknown exception\n",
		    	    block_num, i);
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

