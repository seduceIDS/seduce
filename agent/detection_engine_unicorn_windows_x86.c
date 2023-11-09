#include <unicorn/unicorn.h>
#include "detection_engine.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "utils.h"
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <libpe/pe.h>
#include "winternl.h"

/* Based on the MSc dissertation code of Dimitrios Tsilis (c) 2023 */

/* The following memory zones are missing PROT_WRITE so we don't need to 
 * re-init them on each loop
 *
 * PEB_LDR_ADDR (PROT_READ)
 * PEB_ADDR (PROT_READ)
 * TEB_ADDR (PROT_READ)
 * GDT_BASE (PROT_READ)
 * DLL_BASE (PROT_READ | PROT_EXEC)
 * DLL_META (PROT_READ)
 * 
 * The following memory zones are mapped with PROT_WRITE so we need to re-init 
 * them on each loop
 *
 * HEAP_BASE (PROT_READ | PROT_WRITE | PROT_EXEC)
 * BASE_ADDR (PROT_READ | PROT_WRITE | PROT_EXEC)
 * stack_top (PROT_READ | PROT_WRITE | PROT_EXEC)
 */

#define BASE_ADDR      0x400000
#define EXEC_SIZE      0x600000
#define STACK_BASE     0xD00000
#define STACK_SIZE     0x010000
#define HEAP_BASE      0xD50000
#define HEAP_SIZE      0x010000

#define DLL_META     0x60000000
#define DLL_META_SZ  0x00010000
#define DLL_BASE     0x70000000
#define PEB_LDR_ADDR 0x77dff000
#define TEB_ADDR     0x79000000 /* was 0x00b7d000 */
#define PEB_ADDR     0x7A000000 /* was 0x00b2f000 */
#define GDT_BASE     0x80000000
#define GDT_SIZE         0x1000

typedef struct {
	int gotcha; 	// 1: detected, 0: no luck, -1: allocation error, 
			// -2: uc_read_mem error
	Threat *threat;
} EmulationResult;

static uc_engine *uc;
static pe_exports_t *pe_exported_functions;
static size_t raw_pe_size;
static void *disposable_mem;
static pe_ctx_t ctx;
static uc_x86_mmr gdtr;

static inline size_t align4k(size_t size)
{
	size_t alignment = 0x1000;
	size_t mask = ((size_t)-1) & -alignment;
	return (size + (alignment - 1)) & mask;
}

/* return value: 1 everything ok
 *               0 an error occured */
static int create_LDR_Module(uc_engine * uc, pe_ctx_t ctx,
			     uint64_t dll_base_address, uint64_t dll_meta_addr)
{
	uc_err err;
	char *dll_name;
	char full_dll_name[PATH_MAX];
	size_t base_dll_name_len, full_dll_name_len, base_dll_name_wide_len,
	    full_dll_name_wide_len;
	const char *directory_path = "C:\\Windows\\System32\\";
	LDR_MODULE _dataDLL;
	int retval = 1;

	// Align function addresses based on DLL Base address
	for (int i = 0; i < pe_exported_functions->functions_count; i++) {
		pe_exported_functions->functions[i].address += dll_base_address;
	}

	// Creating LDR_MODULE struct for the DLL

	dll_name = strrchr(ctx.path, '/');
	if (!dll_name) {
		return 0;
	}
	dll_name++;		// walk past the /

	base_dll_name_len = strlen(dll_name);	// length of the narrow character string
	snprintf(full_dll_name, sizeof(full_dll_name), "%s%s", directory_path,
		 dll_name);

	full_dll_name_len = strlen(full_dll_name);	// length of the narrow character string
	uint16_t *wideString_base_dll_name =
	    (uint16_t *) malloc((base_dll_name_len + 1) * sizeof(uint16_t));
	uint16_t *wideString_full_dll_name =
	    (uint16_t *) malloc((full_dll_name_len + 1) * sizeof(uint16_t));

	// Convert the narrow strings to a wide string
	for (size_t i = 0; i < base_dll_name_len; i++) {
		wideString_base_dll_name[i] = (uint16_t) dll_name[i];
	}
	wideString_base_dll_name[base_dll_name_len] = 0;

	for (size_t i = 0; i < full_dll_name_len; i++) {
		wideString_full_dll_name[i] = (uint16_t) full_dll_name[i];
	}
	wideString_full_dll_name[full_dll_name_len] = 0;

	base_dll_name_wide_len = (base_dll_name_len) * sizeof(uint16_t);	// size of the wide character string in bytes
	full_dll_name_wide_len = (full_dll_name_len) * sizeof(uint16_t);	// size of the wide character string in bytes

	memset(&_dataDLL, 0, sizeof(LDR_MODULE));

	_dataDLL.BaseAddress = (uint32_t) dll_base_address;
	_dataDLL.EntryPoint = (uint32_t) ctx.pe.entrypoint;
	_dataDLL.SizeOfImage = (uint32_t) ctx.map_size;
	_dataDLL.FullDllName.Length = (uint16_t) full_dll_name_wide_len;
	_dataDLL.FullDllName.MaximumLength =
	    (uint16_t) full_dll_name_wide_len + 2;
	_dataDLL.FullDllName.Buffer = dll_meta_addr + sizeof(_dataDLL);
	_dataDLL.BaseDllName.Length = (uint16_t) base_dll_name_wide_len;
	_dataDLL.BaseDllName.MaximumLength =
	    (uint16_t) base_dll_name_wide_len + 2;
	_dataDLL.BaseDllName.Buffer =
	    dll_meta_addr + sizeof(_dataDLL) +
	    _dataDLL.FullDllName.MaximumLength;

	_dataDLL.InInitializationOrderModuleList.Flink =
	    (uint32_t) PEB_LDR_ADDR + 0xc;
	_dataDLL.InInitializationOrderModuleList.Blink =
	    (uint32_t) PEB_LDR_ADDR + 0xc;
	_dataDLL.InMemoryOrderModuleList.Flink = (uint32_t) PEB_LDR_ADDR + 0x14;
	_dataDLL.InMemoryOrderModuleList.Blink = (uint32_t) PEB_LDR_ADDR + 0x14;
	_dataDLL.InInitializationOrderModuleList.Flink =
	    (uint32_t) PEB_LDR_ADDR + 0x1c;
	_dataDLL.InInitializationOrderModuleList.Blink =
	    (uint32_t) PEB_LDR_ADDR + 0x1c;

	err = uc_mem_write(uc, _dataDLL.FullDllName.Buffer,
			   wideString_full_dll_name, full_dll_name_wide_len);
	if (err != UC_ERR_OK) {
		retval = 0;
		goto exit;
	}

	err = uc_mem_write(uc, _dataDLL.BaseDllName.Buffer,
			   wideString_base_dll_name, base_dll_name_wide_len);
	if (err != UC_ERR_OK) {
		retval = 0;
		goto exit;
	}

	err = uc_mem_write(uc, dll_meta_addr, &_dataDLL, sizeof(_dataDLL));
	if (err != UC_ERR_OK) {
		retval = 0;
	}
 exit:
	free(wideString_full_dll_name);
	free(wideString_base_dll_name);
	return retval;
}

/* return value: 0 an error occured
 *               1 everything OK */
static int setup_PEB_LDR(uc_engine * uc)
{
	uc_err err;
	size_t size;
	PEB_LDR_DATA _dataPEB_LDR;

	memset(&_dataPEB_LDR, 0, sizeof(PEB_LDR_DATA));
	_dataPEB_LDR.InInitializationOrderModuleList.Flink =
	    (uint32_t) DLL_META;
	_dataPEB_LDR.InInitializationOrderModuleList.Blink =
	    (uint32_t) DLL_META;
	_dataPEB_LDR.InMemoryOrderModuleList.Flink = (uint32_t) DLL_META + 0x8;
	_dataPEB_LDR.InMemoryOrderModuleList.Blink = (uint32_t) DLL_META + 0x8;
	_dataPEB_LDR.InInitializationOrderModuleList.Flink =
	    (uint32_t) DLL_META + 0x10;
	_dataPEB_LDR.InInitializationOrderModuleList.Blink =
	    (uint32_t) DLL_META + 0x10;
	size = align4k(sizeof(_dataPEB_LDR));
	err = uc_mem_map(uc, PEB_LDR_ADDR, size, UC_PROT_READ);
	if (err != UC_ERR_OK)
		return 0;

	err = uc_mem_write(uc, PEB_LDR_ADDR, &_dataPEB_LDR, 
				sizeof(_dataPEB_LDR));
	if (err != UC_ERR_OK) {
		uc_mem_unmap(uc, PEB_LDR_ADDR, size);
		return 0;
	}

	return 1;
}

/* return value: 0 an error occured
 *               1 everything OK */
static int create_PEB_TEB(uc_engine * uc)
{
	uc_err err;
	size_t size;
	PEB _PEB;
	TEB _TEB;

	memset(&_PEB, 0, sizeof(PEB));
	memset(&_TEB, 0, sizeof(TEB));

	_PEB.ImageBaseAddress = (uint32_t) BASE_ADDR;
	_PEB.Ldr = (uint32_t) PEB_LDR_ADDR;
	_PEB.ProcessHeap = (uint32_t) HEAP_BASE;
	_TEB.NtTib.StackBase = (uint32_t) STACK_BASE;
	_TEB.NtTib.StackLimit = (uint32_t) STACK_BASE - (uint32_t) STACK_SIZE;
	_TEB.NtTib.Self = (uint32_t) TEB_ADDR;
	_TEB.ThreadLocalStoragePointer = (uint32_t) TEB_ADDR;
	_TEB.ProcessEnvironmentBlock = (uint32_t) PEB_ADDR;

	size = align4k(sizeof(_PEB));

	err = uc_mem_map(uc, PEB_ADDR, size, UC_PROT_READ);
	if (err != UC_ERR_OK)
		return 0;

	err = uc_mem_write(uc, PEB_ADDR, &_PEB, size);
	if (err != UC_ERR_OK) {
		uc_mem_unmap(uc, PEB_ADDR, size);
		return 0;
	}

	size = align4k(sizeof(TEB));
	err = uc_mem_map(uc, TEB_ADDR, size, UC_PROT_READ);
	if (err != UC_ERR_OK) {
		uc_mem_unmap(uc, PEB_ADDR, align4k(sizeof(PEB)));
		return 0;
	}

	err = uc_mem_write(uc, TEB_ADDR, &_TEB, size);
	if (err != UC_ERR_OK) {
		uc_mem_unmap(uc, TEB_ADDR, align4k(sizeof(TEB)));
		uc_mem_unmap(uc, PEB_ADDR, align4k(sizeof(PEB)));
		return 0;
	}

	return 1;
}

/* return value: 0 an error occured
 *               1 everything OK */
static int create_GDT(uc_engine * uc)
{
	uc_err err;

	err = uc_mem_map(uc, GDT_BASE, GDT_SIZE, UC_PROT_READ);
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not memory map GDT\n");
		return 0;
	}
	/* relevant registers are init by setup_segment_registers */

	const uint8_t a[] = "\xff\xff\x00\x00\x00\xfb\xcf\x00";
	err = uc_mem_write(uc, GDT_BASE + 4 * 8, a, sizeof(a));
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not write at offset 32 of GDT\n");
		uc_mem_unmap(uc, GDT_BASE, GDT_SIZE);
		return 0;
	}

	const uint8_t a1[] = "\xff\xff\x00\x00\x00\xf3\xcf\x00";
	err = uc_mem_write(uc, GDT_BASE + 5 * 8, a1, sizeof(a1));
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not write at offset 40 of GDT\n");
		uc_mem_unmap(uc, GDT_BASE, GDT_SIZE);
		return 0;
	}

	const uint8_t a2[] = "\xff\xff\x00\x00\x00\x97\xcf\x00";
	err = uc_mem_write(uc, GDT_BASE + 6 * 8, a2, sizeof(a2));
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not write at offset 48 of GDT\n");
		uc_mem_unmap(uc, GDT_BASE, GDT_SIZE);
		return 0;
	}

	/* was const uint8_t a3[] = "\xff\x0f\x00\xd0\xb7\xf3\x40\x00"; */
	const uint8_t a3[] = "\xff\x0f\x00\x00\x00\xf3\x40\x79"; 
	err = uc_mem_write(uc, GDT_BASE + 10 * 8, a3, sizeof(a3));
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not write at offset 80 of GDT\n");
		uc_mem_unmap(uc, GDT_BASE, GDT_SIZE);
		return 0;
	}

	return 1;
}

static inline int setup_segment_registers(void)
{
	uc_err err;

	memset(&gdtr, 0, sizeof(uc_x86_mmr));
	gdtr.base = GDT_BASE;
	gdtr.flags = 0;
	gdtr.limit = GDT_SIZE;
	gdtr.selector = 0;

	err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
	if (err != UC_ERR_OK) {
		return 0;
	}

	int b = 35;
	err = uc_reg_write(uc, UC_X86_REG_CS, &b);
	if (err != UC_ERR_OK) {
		return 0;
	}

	int b1 = 43;
	err = uc_reg_write(uc, UC_X86_REG_DS, &b1);
	if (err != UC_ERR_OK) {
		return 0;
	}

	err = uc_reg_write(uc, UC_X86_REG_ES, &b1);
	if (err != UC_ERR_OK) {
		return 0;
	}

	err = uc_reg_write(uc, UC_X86_REG_GS, &b1);
	if (err != UC_ERR_OK) {
		return 0;
	}

	int b2 = 48;
	err = uc_reg_write(uc, UC_X86_REG_SS, &b2);
	if (err != UC_ERR_OK) {
		return 0;
	}

	int b3 = 83;
	err = uc_reg_write(uc, UC_X86_REG_FS, &b3);
	if (err != UC_ERR_OK) {
		return 0;
	}

	return 1;
}

/* prototypes of functions related to the detection engine API */

static int uni_engine_init(void);
static int uni_engine_process(char *, size_t, Threat *);
static void uni_engine_reset(void);
static void uni_engine_destroy(void);

DetectionEngine uni_windows_x86_engine = {
	.name = "windows_x86",
	.descr = "Unicorn-based Windows x86 Detection Engine",
	.init = &uni_engine_init,
	.destroy = &uni_engine_destroy,
	.reset = &uni_engine_reset,
	.process = &uni_engine_process
};

static void hook_dll_functions(uc_engine * uc, uint64_t address, uint32_t size,
			       void *user_data)
{
	EmulationResult *er;
	Threat *threat;
	char threat_msg[400];

	if ((uint32_t) address < (uint32_t) DLL_BASE)
		return;

	er = (EmulationResult *) user_data;
	threat = er->threat;

	for (int i = 0; i < pe_exported_functions->functions_count; i++) {
		uint32_t funcAddress =
		    (uint32_t) pe_exported_functions->functions[i].address;
		if ((uint32_t) funcAddress == (uint32_t) address) {
			er->gotcha = 1;
			threat->severity = SEVERITY_HIGH;
			snprintf(threat_msg, sizeof(threat_msg),
				 "Windows x86 kernel32.dll call detected (%s)",
				 pe_exported_functions->functions[i].name);
			threat->msg = strdup(threat_msg);
			if (!threat->msg) {
				fprintf(stderr, "could not allocate memory for threat string\n");
				er->gotcha = -1;
			}
			uc_emu_stop(uc);
			return;
		}
	}
}

/*
 * Function: uni_engine_process()
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
static int uni_engine_process(char *data, size_t len, Threat * threat)
{
	uc_err err;
	uc_hook trace_handle;
	EmulationResult er;
	const char *p;
	int block_size, i, block_num = 0;
	int ret = 0;
	uint32_t stack_top, ebp;

	if ((data == NULL) || (len == 0))
		return 0;

	er.gotcha = 0;
	er.threat = threat;

	stack_top = STACK_BASE; // that's where it starts off from
	ebp = stack_top + sizeof(void *);

	/* when the payload is in some offset (e.g. we have leading garbage)
	 * QEMU will only detect this if we hook ALL instructions and 
	 * not just the DLL instructions (i.e. s/BASE_ADDR,/DLL_BASE,/) 
	 * doesn't work ?! */

	err = uc_hook_add(uc, &trace_handle, UC_HOOK_CODE, hook_dll_functions,
			  &er, BASE_ADDR, DLL_BASE + raw_pe_size - 1);
/*
			  &er, DLL_BASE, DLL_BASE + raw_pe_size - 1);
*/
	if (err != UC_ERR_OK) {
		fprintf(stderr,
			"could not add windows x86 kernel32.dll function hook");
		return -1;
	}

	while ((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
				   block_num++))) {
		if (block_size > EXEC_SIZE) {
			fprintf(stderr, "block size larger than available "
				 	"memory for emulation\n");
			ret = -1;
			goto exit_loop;
		}

		// Start of disposable_mem is BASE_ADDR in emulator.
		// This is where we copy the payload.
		memcpy(disposable_mem, p, block_size);

		for (i = 0; i < block_size; i++) {
			err = uc_reg_write(uc, UC_X86_REG_ESP, &stack_top);
			if (err != UC_ERR_OK) {
				fprintf(stderr, "could not set ESP\n");
				ret = -1;
				goto exit_loop;
			}

			err = uc_reg_write(uc, UC_X86_REG_EBP, &ebp);
			if (err != UC_ERR_OK) {
				fprintf(stderr, "could not set EBP\n");
				ret = -1;
				goto exit_loop;
			}

			if (setup_segment_registers() == 0) {
				fprintf(stderr, "error at setting up segment"
						" registers\n");
				ret = -1;
				goto exit_loop;
			}

			DPRINTF_MD5(disposable_mem+i, block_size-i,
					    "checking offset %d\n", i);

			// emulate with 200000 microseconds timeout	
			err =
			    uc_emu_start(uc, BASE_ADDR+i, 0, 200000, 0);
			if (er.gotcha <= -1) {	// callback internal error
				ret = -1;
				goto exit_loop;
			}

			if (er.gotcha == 1) { // found shellcode
				DPRINTF_MD5(p, block_size,
					    "detection at offset %d\n", i);
				threat->payload = malloc(block_size);
				if (!threat->payload) {
					perror("could not allocate memory for malicious payload");
					ret = -1;
					goto exit_loop;
				}
				memcpy(threat->payload, p, block_size);
				threat->length = block_size;
				ret = 1;
				goto exit_loop;
			}

			// In all other emulation errors do nothing
			
			// flush QEMU translations just before the next round

			err = uc_ctl_remove_cache(uc, BASE_ADDR, BASE_ADDR + block_size - 1);
			if (err != UC_ERR_OK) {
				ret = -1;
				goto exit_loop;
			}
		 
		}	// for-loop for offsets
	}		// while-loop for blocks

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
	const void *raw_data;
	char *path = DLL_DIR "/kernel32.dll";

	// Initialize engine
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not open unicorn engine in x86 mode\n");
		return 0;
	}

	disposable_mem = mmap(NULL, HEAP_BASE + HEAP_SIZE - BASE_ADDR, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (disposable_mem == MAP_FAILED) {
		perror("could not allocate disposable emulation memory");
		goto err_mmap;
	}

	err = uc_mem_map_ptr(uc, BASE_ADDR, HEAP_BASE + HEAP_SIZE - BASE_ADDR, UC_PROT_ALL, disposable_mem);
	if (err != UC_ERR_OK) {
		perror("could not map host disposable memory to emulator");
		goto err_uc_mem_map_ptr;
	}

	// Parsing kernel32.dll
	pe_err_e err_loading = pe_load_file(&ctx, path);
	// if we don't find the file in the standard place, search 
	// a local directory (this is useful when trying out things from
	// a non-installed version)
	if (err_loading == LIBPE_E_OPEN_FAILED) {
		path = "./DLL/windows-x86/system32/kernel32.dll";
		err_loading = pe_load_file(&ctx, path);
	}
	if (err_loading != LIBPE_E_OK) {
		pe_error_print(stderr, err_loading);
		goto err_pe_load_file;
	}

	// parse the loaded PE file(e.g. kernel32.dll) from previous step
	err_loading = pe_parse(&ctx);
	if (err_loading != LIBPE_E_OK) {
		pe_error_print(stderr, err_loading);
		goto err_pe_parse;
	}
	// Pointer to raw data of PE file
	raw_data = ctx.map_addr;
	//Size of PE file
	raw_pe_size = ctx.map_size;

	// Save globally the exported functions from the previous parsed PE file
	pe_exported_functions = pe_exports(&ctx);

	// Load parsed file in memory
	// size of memory block; MUST be 4 KB (4 * 1024) aligned (size=1,2,… otherwise will cause fail) --> In our case raw_pe_size

	err = uc_mem_map(uc, DLL_BASE, align4k(raw_pe_size), UC_PROT_READ | UC_PROT_EXEC);
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not create space for loaded DLLs\n");
		goto err_uc_mem_map_dll;
	}

	err = uc_mem_write(uc, DLL_BASE, raw_data, raw_pe_size);
	if (err != UC_ERR_OK) {
		fprintf(stderr,
			"could not write DLL data to emulator memory\n");
		goto err_uc_mem_write_dll;
	}

	err = uc_mem_map(uc, DLL_META, DLL_META_SZ, UC_PROT_READ);
	if (err != UC_ERR_OK) {
		fprintf(stderr, "could not map memory for DLL metadata\n");
		goto err_uc_mem_map_dll_meta;
	}

	// Creating the LDR_Module struct for the DLL
	if (create_LDR_Module(uc, ctx, DLL_BASE, DLL_META) == 0) {
		fprintf(stderr, "failed to create LDR module\n");
		goto err_create_ldr_module;
	}

	if (setup_PEB_LDR(uc) == 0) {
		fprintf(stderr, "failed to setup PEB and LDR\n");
		goto err_setup_peb_ldr;
	}

	if (create_PEB_TEB(uc) == 0) {
		fprintf(stderr, "failed to create PEB and TEB\n");
		goto err_create_peb_teb;
	}

	if (create_GDT(uc) == 0) {
		fprintf(stderr, "failed to create GDT\n");
		goto err_create_gdt;
	}

	// we don't pe_unload as we need the structures (functions) 
	// exported by libpe for later
	return 1;

  err_create_gdt:
	uc_mem_unmap(uc, TEB_ADDR, align4k(sizeof(TEB)));
	uc_mem_unmap(uc, PEB_ADDR, align4k(sizeof(PEB)));
  err_create_peb_teb:
	uc_mem_unmap(uc, PEB_LDR_ADDR, align4k(sizeof(PEB_LDR_DATA)));
  err_setup_peb_ldr:
  err_create_ldr_module:
  	uc_mem_unmap(uc, DLL_META, DLL_META_SZ);
  err_uc_mem_map_dll_meta:
  err_uc_mem_write_dll:
	uc_mem_unmap(uc, DLL_BASE, align4k(raw_pe_size));
  err_uc_mem_map_dll:
  err_pe_parse:
	pe_unload(&ctx);
  err_pe_load_file:
	uc_mem_unmap(uc, BASE_ADDR, HEAP_BASE + HEAP_SIZE - BASE_ADDR);
  err_uc_mem_map_ptr:
	munmap(disposable_mem, HEAP_BASE + HEAP_SIZE - BASE_ADDR);
  err_mmap:
	uc_close(uc);
	return 0;
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
	uc_mem_unmap(uc, DLL_META, DLL_META_SZ);
	munmap(disposable_mem, HEAP_BASE + HEAP_SIZE - BASE_ADDR);
	uc_mem_unmap(uc, PEB_LDR_ADDR, align4k(sizeof(PEB_LDR_DATA)));
	uc_mem_unmap(uc, PEB_ADDR, align4k(sizeof(PEB)));
	uc_mem_unmap(uc, TEB_ADDR, align4k(sizeof(TEB)));
	uc_mem_unmap(uc, GDT_BASE, GDT_SIZE);
	uc_mem_unmap(uc, DLL_BASE, align4k(raw_pe_size));
	pe_unload(&ctx);
	uc_close(uc);
	return;
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
