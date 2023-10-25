#include <unicorn/unicorn.h>
#include "detection_engine.h"
#include "syscalls-linux-x86-64.h"
#include <unicorn/x86.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "utils.h"

#define MEM_LOW 0x10000
#define MEM_SPACE 16 * 1024 * 1024
#define STACK_SIZE 4 * 1024 * 1024

typedef struct {
	int gotcha; // 1: detected, 0: no luck, -1: allocation error
	Threat *threat;
} EmulationResult;

static uc_engine *uc;
static void *emu_memory; 

/* prototypes of functions related to the detection engine API */

static int uni_engine_init(void);
static int uni_engine_process(char *, size_t, Threat *);
static void uni_engine_reset(void);
static void uni_engine_destroy(void);

DetectionEngine uni_lx86_64_engine = {
	.name = "linux64",
	.descr = "Unicorn-based Linux x86_64 Detection Engine",
	.init = &uni_engine_init,
	.destroy = &uni_engine_destroy,
	.reset = &uni_engine_reset,
	.process = &uni_engine_process
};

static void hook_syscall(uc_engine *uc, void *user_data)
{
	uint64_t value;
	EmulationResult *er;
	char threat_msg[101];
	Threat *threat;

	er = (EmulationResult *) user_data;
	threat = er->threat;

	uc_reg_read(uc, UC_X86_REG_RAX, &value);
	if (value == 59) { // execve
		er->gotcha = 1;
		threat->severity = SEVERITY_HIGH;
		snprintf(threat_msg, 100, 
			"High risk syscall %lu (%s) detected",
			value, syscalls_linux64[value]);
		threat->msg = strdup(threat_msg);
		if (!threat->msg) {
			perror("could not allocate memory in syscall callback");
			er->gotcha = -1;
		}
		uc_emu_stop(uc);
	}
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
static int uni_engine_process(char *data, size_t len, Threat *threat)
{
	void *code_segment;
	const char *p;
	int block_size, i, block_num = 0;
	uc_hook trace_handle;
	EmulationResult er;
	int ret = 0;
	uint64_t stack_top = MEM_LOW + STACK_SIZE;
	uint64_t rbp = stack_top + sizeof(void *);
	uc_err err;

	if((data == NULL) || (len == 0))
		return 0;

	er.gotcha = 0;
	er.threat = threat;

	err = uc_hook_add(uc, &trace_handle, UC_HOOK_INSN, hook_syscall, 
			  &er,  1, 0, UC_X86_INS_SYSCALL);
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not add x86_64 syscall hook");
		return -1;
	}

	code_segment = emu_memory + STACK_SIZE + 4096;

	while((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
					block_num++))) 
	{
		if ((code_segment + block_size) > (emu_memory + MEM_SPACE)) {
			fprintf(stderr,
				"block size larger than emulated memory\n");
			ret = -1;
			goto exit_loop;
		}

		memcpy(code_segment, p, block_size);

		for (i = 0; i < block_size - 5; i++) {
			uc_reg_write(uc, UC_X86_REG_RSP, &stack_top);
			uc_reg_write(uc, UC_X86_REG_RBP, &rbp);

			err = uc_emu_start(uc, 
				  MEM_LOW + STACK_SIZE + 4096,
				  MEM_LOW + STACK_SIZE + 4096 + block_size,
				  0, 0);

			if (er.gotcha == -1) { // callback allocation error
				ret = -1;
				goto exit_loop;
			}

			if (er.gotcha == 1) { // detected malicious code
				DPRINTF_MD5(p, block_size, "detection at offset %d\n", i);
				threat->payload = malloc(block_size);
				if (!threat->payload) {
					perror("could not allocate memory "
						"for malicious payload");
					ret = -1;
					goto exit_loop;
				}
				memcpy(threat->payload, p, block_size);
				threat->length = block_size;
				ret = 1;
				goto exit_loop;
			}
			// in all other cases, do nothing
		}
	}
exit_loop:
	uc_hook_del(uc, trace_handle);
	return ret;
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
static int uni_engine_init(void)
{
	uc_err err;
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) {
		perror("could not initialize unicorn engine for x86_64");
		return 0;
	}
	
	emu_memory = mmap(NULL, MEM_SPACE, PROT_READ | PROT_WRITE | PROT_EXEC, 
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (emu_memory == MAP_FAILED) {
		perror("could not allocate emulation memory");
		uc_close(uc);
		return 0;
	}
	err = uc_mem_map_ptr(uc, MEM_LOW, MEM_SPACE, UC_PROT_ALL, emu_memory);
	if (err != UC_ERR_OK) {
		perror("could not map host memory to emulator");
		uc_close(uc);
		free(emu_memory);
		return 0;
	}
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
static void uni_engine_destroy(void)
{
	uc_mem_unmap(uc, MEM_LOW, MEM_SPACE);
	uc_close(uc);
	munmap(emu_memory, MEM_SPACE);
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
static void uni_engine_reset(void)
{
	/* 
	 * We don't use this function but it is required by the agent 
	 * implementation.* 
	 */

	return;
}

