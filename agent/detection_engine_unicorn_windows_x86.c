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
#include <libpe/pe.h>
#include "winternl.h"

#define DLL_BASE 0x70000000
#define HEAP_BASE 0xD50000
#define PEB_LDR_ADDR 0x77dff000
#define TEB_ADDR 0x00b7d000
#define PEB_ADDR 0x00b2f000
#define ADDRESS 0x400000
#define STACK_BASE 0x00d00000
#define STACK_SIZE 0x10000
#define GDT_BASE 0x80000000
#define GDT_SIZE  0x1000

static pe_exports_t *pe_exported_functions;

#define uc_assert_err(expect, err)                                             \
    do {                                                                       \
        uc_err __err = err;                                                    \
        if (__err != expect) {                                                 \
            fprintf(stderr, "%s", uc_strerror(__err));                         \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#define uc_assert_success(err) uc_assert_err(UC_ERR_OK, err)

static uc_err _uc_err_check(uc_err err, const char* expr)
{
    if (err) {
        fprintf(stderr, "Failed on %s with error: %s\n", expr, uc_strerror(err)); exit(1);
    }
    else {
        // fprintf(stderr, "Succeeded on %s\n", expr);
    }
    return err;
}

#define UC_ERR_CHECK(x) _uc_err_check(x, #x)

size_t align(size_t size) {
    size_t alignment = 0x1000;
    size_t mask = ((size_t)-1) & -alignment;
    return (size + (alignment - 1)) & mask;
}

static void create_LDR_Module(uc_engine *uc, pe_ctx_t ctx, 
		       uint64_t dll_base_address, uint64_t heap_address)
{
    uc_err err;
    uint64_t heap2write = heap_address;
    
    // Align function addresses based on DLL Base address
    for(int i=0; i< pe_exported_functions->functions_count; i++){
        pe_exported_functions->functions[i].address += dll_base_address;
    }
    
    // Creating LDR_MODULE structs for all dlls
    
    const char* dll_name = strrchr(ctx.path, '/') + 1;
    size_t base_dll_name_len = strlen(dll_name); // length of the narrow character string
    const char* directory_path = "C:\\Windows\\System32\\";
    size_t directory_length = strlen(directory_path);
    char tempString [directory_length + base_dll_name_len + 1];  
    strcpy(tempString, directory_path);
    strcat(tempString, dll_name);
    const char* full_dll_name = tempString;
    
    size_t full_dll_name_len = strlen(full_dll_name); // length of the narrow character string
    uint16_t* wideString_base_dll_name = (uint16_t*)malloc((base_dll_name_len + 1) * sizeof(uint16_t));
    uint16_t* wideString_full_dll_name = (uint16_t*)malloc((full_dll_name_len + 1) * sizeof(uint16_t));
    // Convert the narrow strings to a wide string
    for (size_t i = 0; i < base_dll_name_len; i++) {
        wideString_base_dll_name[i] = (uint16_t) dll_name[i];
    }
    wideString_base_dll_name[base_dll_name_len] = 0;
    for (size_t i = 0; i < full_dll_name_len; i++) {
        wideString_full_dll_name[i] = (uint16_t)full_dll_name[i];
    }
    wideString_full_dll_name[full_dll_name_len] = 0;
    
    size_t base_dll_name_wide_len = (base_dll_name_len) * sizeof(uint16_t); // size of the wide character string in bytes
    size_t full_dll_name_wide_len = (full_dll_name_len) * sizeof(uint16_t); // size of the wide character string in bytes
    
    LDR_MODULE _dataDLL;
    memset(&_dataDLL, 0, sizeof(LDR_MODULE));

    _dataDLL.BaseAddress = (uint32_t) dll_base_address;
    _dataDLL.EntryPoint = (uint32_t) ctx.pe.entrypoint;
    _dataDLL.SizeOfImage = (uint32_t) ctx.map_size;
    _dataDLL.FullDllName.Length = (uint16_t) full_dll_name_wide_len;
    _dataDLL.FullDllName.MaximumLength = (uint16_t) full_dll_name_wide_len + 2;
    _dataDLL.FullDllName.Buffer = heap_address + sizeof(_dataDLL);
    _dataDLL.BaseDllName.Length = (uint16_t) base_dll_name_wide_len;
    _dataDLL.BaseDllName.MaximumLength = (uint16_t) base_dll_name_wide_len + 2;
    _dataDLL.BaseDllName.Buffer =  heap_address + sizeof(_dataDLL) + _dataDLL.FullDllName.MaximumLength;
    
    _dataDLL.InInitializationOrderModuleList.Flink = (uint32_t) PEB_LDR_ADDR + 0xc;
    _dataDLL.InInitializationOrderModuleList.Blink = (uint32_t) PEB_LDR_ADDR + 0xc;
    _dataDLL.InMemoryOrderModuleList.Flink = (uint32_t) PEB_LDR_ADDR + 0x14;
    _dataDLL.InMemoryOrderModuleList.Blink = (uint32_t) PEB_LDR_ADDR + 0x14;
    _dataDLL.InInitializationOrderModuleList.Flink = (uint32_t) PEB_LDR_ADDR + 0x1c;
    _dataDLL.InInitializationOrderModuleList.Blink = (uint32_t) PEB_LDR_ADDR + 0x1c;
    err = uc_mem_write(uc, _dataDLL.FullDllName.Buffer, wideString_full_dll_name, full_dll_name_wide_len);
    uc_assert_success(err);
    err = uc_mem_write(uc, _dataDLL.BaseDllName.Buffer, wideString_base_dll_name, base_dll_name_wide_len);
    uc_assert_success(err);
    err = uc_mem_write(uc, heap2write, &_dataDLL, sizeof(_dataDLL));
    uc_assert_success(err);
    free(wideString_full_dll_name);
    free(wideString_base_dll_name);
}

static void setup_PEB_LDR(uc_engine *uc){
    uc_err err;

    PEB_LDR_DATA _dataPEB_LDR;
    memset(&_dataPEB_LDR, 0, sizeof(PEB_LDR_DATA));
    _dataPEB_LDR.InInitializationOrderModuleList.Flink = (uint32_t) HEAP_BASE;
    _dataPEB_LDR.InInitializationOrderModuleList.Blink = (uint32_t) HEAP_BASE;
    _dataPEB_LDR.InMemoryOrderModuleList.Flink = (uint32_t) HEAP_BASE + 0x8;
    _dataPEB_LDR.InMemoryOrderModuleList.Blink = (uint32_t) HEAP_BASE + 0x8;
    _dataPEB_LDR.InInitializationOrderModuleList.Flink = (uint32_t) HEAP_BASE + 0x10;
    _dataPEB_LDR.InInitializationOrderModuleList.Blink = (uint32_t) HEAP_BASE + 0x10;
    size_t size = align(sizeof(_dataPEB_LDR));
    err = uc_mem_map(uc, PEB_LDR_ADDR, size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, PEB_LDR_ADDR, &_dataPEB_LDR, sizeof(_dataPEB_LDR));
    uc_assert_success(err);
}

static void create_PEB_TEB(uc_engine *uc){
    uc_err err;
    PEB _PEB;
    TEB _TEB;

    memset(&_PEB, 0,sizeof(PEB));
    memset(&_TEB, 0, sizeof(TEB));
    _PEB.ImageBaseAddress = (uint32_t) ADDRESS;
    _PEB.Ldr = (uint32_t) PEB_LDR_ADDR;
    _PEB.ProcessHeap = (uint32_t) HEAP_BASE;
    _TEB.NtTib.StackBase = (uint32_t) STACK_BASE;
    _TEB.NtTib.StackLimit = (uint32_t) STACK_BASE - (uint32_t) STACK_SIZE;
    _TEB.NtTib.Self = (uint32_t) TEB_ADDR;
    _TEB.ThreadLocalStoragePointer = (uint32_t) TEB_ADDR;
    _TEB.ProcessEnvironmentBlock = (uint32_t) PEB_ADDR;

    size_t size = align(sizeof(_PEB));
    err = uc_mem_map(uc, PEB_ADDR, size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, PEB_ADDR, &_PEB, size);
    uc_assert_success(err);
    
    size = align(sizeof(_TEB));
    err = uc_mem_map(uc, TEB_ADDR, size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, TEB_ADDR, &_TEB, size);
    uc_assert_success(err);
}

static void create_GDT(uc_engine *uc){
    uc_x86_mmr gdtr;
    uc_err err;

    err = uc_mem_map(uc, GDT_BASE, GDT_SIZE, UC_PROT_ALL);
    
    gdtr.base = 2147483648;
    gdtr.flags = 0;
    gdtr.limit = 4096;
    gdtr.selector = 0;
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    uc_assert_success(err);
    const uint8_t a []= "\xff\xff\x00\x00\x00\xfb\xcf\x00";
    
    err = uc_mem_write(uc, gdtr.base + 4 * 8, a, sizeof(a));
    int b = 35;
    err = uc_reg_write(uc, UC_X86_REG_CS, &b);

    const uint8_t a1 []= "\xff\xff\x00\x00\x00\xf3\xcf\x00";
    
    err = uc_mem_write(uc, gdtr.base + 5 * 8, a1, sizeof(a1));
    int b1 = 43;
    err = uc_reg_write(uc, UC_X86_REG_DS, &b1);
    err = uc_reg_write(uc, UC_X86_REG_ES, &b1);
    err = uc_reg_write(uc, UC_X86_REG_GS, &b1);

    const uint8_t a2 []= "\xff\xff\x00\x00\x00\x97\xcf\x00";
    
    int b2 = 48;
    err = uc_mem_write(uc, gdtr.base + 6 * 8, a2, sizeof(a2));
    err = uc_reg_write(uc, UC_X86_REG_SS, &b2);

    const uint8_t a3 []= "\xff\x0f\x00\xd0\xb7\xf3\x40\x00";
    
    err = uc_mem_write(uc, gdtr.base + 10 * 8, a3, sizeof(a3));
    int b3 = 83;
    err = uc_reg_write(uc, UC_X86_REG_FS, &b3);
}


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

DetectionEngine uni_windows_x86_engine = {
	.name = "windows_x86",
	.descr = "Unicorn-based Windows x86 Detection Engine",
	.init = &uni_engine_init,
	.destroy = &uni_engine_destroy,
	.reset = &uni_engine_reset,
	.process = &uni_engine_process
};

/*
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
*/

typedef struct {
   uint32_t size_of_code;
   int gotcha; // 1: detected, 0: no luck
} HookData;

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
    HookData *data = (HookData *) user_data;

    //printf("\nExecuting at 0x%08llx, ilen = 0x%x\n", address, size);
    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    uc_reg_read(uc, UC_X86_REG_CS, &r_regCS);
    uc_reg_read(uc, UC_X86_REG_FS, &r_regFS);
    
    
    for(int i=0; i< pe_exported_functions->functions_count; i++){
        uint32_t funcAddress = (uint32_t)pe_exported_functions->functions[i].address;
        uint32_t currentAddress = (uint32_t)address;
        
        if(funcAddress == currentAddress){
            
            printf("DLL CALL: ---> %s\n", pe_exported_functions->functions[i].name);
            uint32_t nextInstruction = (uint32_t) previousAddress+size;
            uc_reg_write(uc, UC_X86_REG_EIP, &nextInstruction);
            uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
            break;
        }
    }
    
    previousAddress = address;
    uint32_t ad = (uint32_t)address;
    uint32_t bd = (uint32_t)data->size_of_code-1;
    if (ad == bd) {
        printf("Reached the end of the code. Stopping the emulator.\n");
        uc_emu_stop(uc);            
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
static int uni_engine_process(char *data, size_t len, Threat *threat)
{
    uc_err err;
    uc_hook hook2, hook3;

    if ((data == NULL) || (len == 0))
	    return 0;

    uint32_t addr_start_exec =  ADDRESS;
    uint32_t addr_stack = STACK_BASE;
    uint32_t STACK_ADDRESS = addr_stack - 0x10000;
    
    err = uc_mem_map(uc, addr_start_exec, align(len), UC_PROT_ALL);
    err = uc_mem_write(uc, addr_start_exec, data, len);
    uc_assert_success(err);
    
    err = uc_reg_write(uc, UC_X86_REG_EIP, &addr_start_exec);
    err = uc_mem_map(uc, STACK_ADDRESS, align(STACK_SIZE), UC_PROT_ALL);
    err = uc_reg_write(uc, UC_X86_REG_ESP, &addr_stack);
    static HookData hookdata;
    hookdata.size_of_code = addr_start_exec + len - 1;
    uc_hook_add(uc, &hook2, UC_HOOK_CODE, hook_code, &hookdata, addr_start_exec, sizeof(code));

    /*
    err = uc_hook_add(uc, &hook3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem, NULL,
                      (uint64_t)1, (uint64_t)0);
    uc_assert_success(err);
    */

    err = uc_emu_start(uc, addr_start_exec, addr_start_exec + len, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
        err, uc_strerror(err));
    }
    UC_ERR_CHECK(err);
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

    // Parsing kernel32.dll
    char path[] = DLL_DIR "/kernel32.dll";
    pe_err_e err_loading = pe_load_file(&ctx, path);
    if (err_loading != LIBPE_E_OK) {
        pe_error_print(stderr, err_loading);
        return 0;
    }

    // parse the loaded PE file(e.g. kernel32.dll) from previous step
    err_loading = pe_parse(&ctx);
    if (err_loading != LIBPE_E_OK) {
       pe_error_print(stderr, err_loading);
       return 0;
    }
                
    // Pointer to raw data of PE file
    const void* raw_data = ctx.map_addr;
    //Size of PE file
    size_t raw_size = ctx.map_size;

    // Save globally the exported functions from the previous parsed PE file
    pe_exported_functions = pe_exports(&ctx);

    // Load parsed file in memory
    // size of memory block; MUST be 4 KB (4 * 1024) aligned (size=1,2,… otherwise will cause fail) --> In our case raw_size
    raw_size = align(raw_size);
    err = uc_mem_map(uc, DLL_CURR_ADDRESS, raw_size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, DLL_CURR_ADDRESS, raw_data, raw_size);
    uc_assert_success(err);
                
    // Creating the LDR_Module struct for the dll
    create_LDR_Module(uc, ctx, DLL_CURR_ADDRESS, &HEAP_CUR);
    DLL_CURR_ADDRESS += raw_size;

    setup_PEB_LDR(uc);
    create_PEB_TEB(uc);
    create_GDT(uc);

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

