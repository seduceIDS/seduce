#include <unicorn/unicorn.h>
#include "detection_engine.h"
#include <unicorn/x86.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "utils.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include "windows_helper_functions/windows_LDR_struct_Modules.h" // Include this before "PEB_TEB.h"
#include "windows_helper_functions/create_LDR_Module.c"
#include "windows_helper_functions/setup_PEB_LDR.c"
#include "windows_helper_functions/create_PEB_TEB.c"
#include "libpe/include/libpe/pe.h"
#include "windows_helper_functions/create_GDT.c"

typedef struct {
	int gotcha; // 1: detected, 0: no luck, -1: allocation error
	Threat *threat;
} EmulationResult;

static uc_engine *uc;

/* prototypes of functions related to the detection engine API */

static int uni_engine_init(void);
static int uni_engine_process(char *, size_t, Threat *);
static void uni_engine_reset(void);
static void uni_engine_destroy(void);

size_t align(size_t size) {
    size_t alignment = 0x1000;
    size_t mask = ((size_t)-1) & -alignment;
    return (size + (alignment - 1)) & mask;
}
size_t alloc_heap(uint64_t heap_curr_addr, size_t size) {
    uint32_t result = heap_curr_addr;
    heap_curr_addr += size;
    return result;
}
pe_exports_t *pe_exported_functions;

DetectionEngine uni_windows_x86_engine = {
	.name = "windowsx86",
	.descr = "Unicorn-based Windows x86 Detection Engine",
	.init = &uni_engine_init,
	.destroy = &uni_engine_destroy,
	.reset = &uni_engine_reset,
	.process = &uni_engine_process
};


static void hook_mem(uc_engine *uc, uc_mem_type type, uint32_t address,
                     int size, int32_t value, void *user_data)
{
    uint32_t r_regEBX;
    uint32_t r_regESP;
    uint32_t r_regEBP;
    uc_reg_read(uc, UC_X86_REG_EBX, &r_regEBX);
    uc_reg_read(uc, UC_X86_REG_ESP, &r_regESP);
    uc_reg_read(uc, UC_X86_REG_EBP, &r_regEBP);
    switch (type) {
    case UC_MEM_WRITE:
        //printf("mem write at 0x%" PRIx64 ", size = %u, value = 0x%" PRIx64 "\n", (uint64_t)address, size, value);
        break;
    case UC_MEM_READ_UNMAPPED:
        printf("*** EBX = %08x ***:", r_regEBX);
        break;
    case UC_MEM_WRITE_UNMAPPED:
        printf("mem write at %08x, size = %u, value = %08x \n", address, size, value);
        printf("*** ESP = %08x ***:", r_regESP);
        printf("*** EBP = %08x ***:", r_regEBP);
        break;
    default:
        break;
    }
}


typedef struct {
   uint32_t size_of_code;
} HookData;
uint32_t sizePreviousIntr;
uint64_t previousAddress;
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data)
{
    int r_eip;
    uint32_t r_regCS;
    uint32_t r_regFS;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    HookData *data = (HookData *)user_data;

    //printf("\nExecuting at 0x%08llx, ilen = 0x%x\n", address, size);
    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    uc_reg_read(uc, UC_X86_REG_CS, &r_regCS);
    uc_reg_read(uc, UC_X86_REG_FS, &r_regFS);
    
    
    for(int i=0; i< pe_exported_functions->functions_count; i++){
        uint32_t funcAddress = (uint32_t)pe_exported_functions->functions[i].address;
        uint32_t currentAddress = (uint32_t)address;
        
        if(funcAddress == currentAddress){
            
            printf("SYSTEM CALL: ---> %s\n", pe_exported_functions->functions[i].name);
            uint32_t nextInstruction = (uint32_t)previousAddress+size;
            uc_reg_write(uc, UC_X86_REG_EIP, &nextInstruction);
            uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
            break;
        }
        
    }
    
    sizePreviousIntr = size;
    previousAddress = address;
    // csh handle;
    // cs_insn *insn;
    // cs_err err8;

    // err8 = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
    // if (err8 != CS_ERR_OK) {
    //     printf("Error initializing Capstone: %s\n", cs_strerror(err8));
    //     uc_emu_stop(uc);
    // }

    // size = MIN1(sizeof(tmp), size);
    // if (!uc_mem_read(uc, address, tmp, size)) {
    //     size_t count = cs_disasm(handle, tmp, size, 0, 0, &insn);
    //     if (count > 0) {
    //         for (size_t j = 0; j < count; j++) {
    //             printf("Assembly Instruction:  %s %s\n", insn[j].mnemonic, insn[j].op_str);
    //         }
    //         cs_free(insn, count);
    //     }
    //     uint32_t i;
    //     printf("Disassembled Instruction: ");
    //     for (i = 0; i < size; i++) {
    //         printf("%x ", tmp[i]);
    //     }
    //     printf("\n");
    // }
    uint32_t ad = (uint32_t)address;
    uint32_t bd = (uint32_t)data->size_of_code-1;
    if (ad == bd) {
        printf("Reached the end of the code. Stopping the emulator.\n");
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
	uc_err err;
	setup_PEB_LDR(uc);
    create_PEB_TEB(uc);
    create_GDT(uc);
    
	uc_hook hook2, hook3;
    uint32_t addr_start_exec =  ADDRESS;
    uint32_t addr_stack = STACK_BASE;
    uint32_t STACK_ADDRESS = addr_stack - 0x10000;
    
    //const uint8_t code[] = "\x50\x53\x51\x52\x56\x57\x55\x89\xE5\x83\xEC\x18\x31\xF6\x56\x6A\x63\x66\x68\x78\x65\x68\x57\x69\x6E\x45\x89\x65\xFC\x31\xF6\x64\x8B\x5E\x30\x8B\x5B\x0C\x8B\x5B\x14\x8B\x1B\x8B\x1B\x8B\x5B\x10\x89\x5D\xF8\x31\xC0\x8B\x43\x3C\x01\xD8\x8B\x40\x78\x01\xD8\x8B\x48\x24\x01\xD9\x89\x4D\xF4\x8B\x78\x20\x01\xDF\x89\x7D\xF0\x8B\x50\x1C\x01\xDA\x89\x55\xEC\x8B\x50\x14\x31\xC0\x8B\x7D\xF0\x8B\x75\xFC\x31\xC9\xFC\x8B\x3C\x87\x01\xDF\x66\x83\xC1\x08\xF3\xA6\x74\x0A\x40\x39\xD0\x72\xE5\x83\xC4\x26\xEB\x3F\x8B\x4D\xF4\x8B\x55\xEC\x66\x8B\x04\x41\x8B\x04\x82\x01\xD8\x31\xD2\x52\x68\x2E\x65\x78\x65\x68\x63\x61\x6C\x63\x68\x6D\x33\x32\x5C\x68\x79\x73\x74\x65\x68\x77\x73\x5C\x53\x68\x69\x6E\x64\x6F\x68\x43\x3A\x5C\x57\x89\xE6\x6A\x0A\x56\xFF\xD0\x83\xC4\x46\x5D\x5F\x5E\x5A\x59\x5B\x58\xc3";
    uint8_t code[strlen(data)];
    for (int i=0; i< strlen(data); i++){
        code[i] = (uint8_t)data[i];
    }
	err = uc_mem_map(uc, addr_start_exec, align(sizeof(code)), UC_PROT_ALL);
    err = uc_mem_write(uc, addr_start_exec, code, sizeof(code));
    uc_assert_success(err);
    
    err = uc_reg_write(uc, UC_X86_REG_EIP, &addr_start_exec);
    err = uc_mem_map(uc, STACK_ADDRESS, align(STACK_SIZE), UC_PROT_ALL);
    err = uc_reg_write(uc, UC_X86_REG_ESP, &addr_stack);
    static HookData hookdata;
    hookdata.size_of_code = addr_start_exec + sizeof(code) - 1;
    uc_hook_add(uc, &hook2, UC_HOOK_CODE, hook_code, &hookdata, addr_start_exec, sizeof(code));

    err = uc_hook_add(uc, &hook3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem, NULL,
                      (uint64_t)1, (uint64_t)0);
    uc_assert_success(err);
    

    err = uc_emu_start(uc, addr_start_exec, addr_start_exec + sizeof(code), 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
        err, uc_strerror(err));
    }
    UC_ERR_CHECK(err);
    //uint64_t rax = 0x114514;
    //UC_ERR_CHECK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    uc_assert_success(err);
	fprintf(stderr, "success\n");
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
static int uni_engine_init(void)
{
	
    pe_ctx_t ctx;
    uc_err err;
    uint64_t DLL_CURR_ADDRESS = DLL_BASE;
    uint64_t HEAP_CUR = HEAP_BASE;
    // Initialize engine
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    uc_assert_success(err);
    // Allocate heap memory in unicorn
    err = uc_mem_map(uc, HEAP_BASE, 0x10000, UC_PROT_ALL);
    // Parsing DLL files
    char path[] = "./x86_windows/System32";
    char resolved_path[4096];
    struct dirent *de;
    //char cwd[1024];
    //getcwd(cwd, sizeof(cwd));
    //printf("here %s", cwd);
    DIR *dr = opendir(path);
    if (dr == NULL) {
        printf("Could not open the directory");
        return 1;
    }
    while ((de = readdir(dr)) != NULL) {
        realpath(path, resolved_path);
        if (strlen(de->d_name) > 4 && strcmp(de->d_name + strlen(de->d_name) - 4, ".dll") == 0) {
            if(strcmp(de->d_name, "kernel32.dll") == 0){
                char *full_path = malloc(strlen(resolved_path) + strlen(de->d_name) + 2); // +2 for the null terminator and the directory separator
                if (full_path == NULL) {
                    printf("Memory allocation failed");
                    return 1;
                }
                strcpy(full_path, resolved_path);
                strcat(full_path, "/");
                strcat(full_path, de->d_name);
                printf("Found DLL file: %s\n", full_path);
                // load PE file e.g. kernel32.dll
                pe_err_e err_loading = pe_load_file(&ctx, full_path);

                if (err_loading != LIBPE_E_OK) {
                    pe_error_print(stderr, err_loading);
                    return 1;
                }

                // parse the loaded PE file(e.g. kernel32.dll) from previous step
                err_loading = pe_parse(&ctx);
                if (err_loading != LIBPE_E_OK) {
                    pe_error_print(stderr, err_loading);
                    return 1;
                }
                
                // Pointer to raw data of PE file
                const void* raw_data = ctx.map_addr;
                //Size of PE file
                size_t raw_size = ctx.map_size;

                // Save globally the exported functions from the previous parsed PE file
                pe_exported_functions = pe_exports(&ctx);

                // Load parsed files in memory
                // size of memory block; MUST be 4 KB (4 * 1024) aligned (size=1,2,… otherwise will cause fail) --> In our case raw_size
                raw_size = align(raw_size);
                err = uc_mem_map(uc, DLL_CURR_ADDRESS, raw_size, UC_PROT_ALL);
                uc_assert_success(err);
                err = uc_mem_write(uc, DLL_CURR_ADDRESS, raw_data, raw_size);
                uc_assert_success(err);
                
                // Creating the LDR_Module struct for the dll
                LDR_MODULE _dataDLL = create_LDR_Module(uc, ctx, DLL_CURR_ADDRESS, &HEAP_CUR);
                DLL_CURR_ADDRESS += raw_size;
                // Unload PE file
                // pe_err_e err_unloading = pe_unload(&ctx);
                // if (err_unloading != LIBPE_E_OK) {
                //     pe_error_print(stderr, err_unloading);
                //     return 1;
                // }
                // Use full_path for further processing
                free(full_path); // Free the memory when no longer needed
            }
        }
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
	// uc_mem_unmap(uc, MEM_LOW, MEM_SPACE);
	// uc_close(uc);
	// munmap(emu_memory, MEM_SPACE);
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

