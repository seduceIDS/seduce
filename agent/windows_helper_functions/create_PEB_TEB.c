//#include <unicorn/unicorn.h>
#include "../libpe/include/libpe/pe.h"
#include "windows_LDR_struct_Modules.h"
#include "../utils-windows-x68.h"

#define uc_assert_err(expect, err)                                             \
    do {                                                                       \
        uc_err __err = err;                                                    \
        if (__err != expect) {                                                 \
            fprintf(stderr, "%s", uc_strerror(__err));                         \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#define uc_assert_success(err) uc_assert_err(UC_ERR_OK, err)

extern size_t align(size_t size);

void create_PEB_TEB(uc_engine *uc){
    
    uc_err err;

    PEB _PEB;
    TEB _TEB;
    _PEB.ImageBaseAddress = (uint32_t)ADDRESS;
    _PEB.Ldr = (uint32_t)PEB_LDR_ADDR;
    _PEB.ProcessHeap = (uint32_t)HEAP_BASE;
    
    _TEB.NtTib.StackBase = (uint32_t)STACK_BASE;
    _TEB.NtTib.StackLimit = (uint32_t)STACK_BASE - (uint32_t)STACK_SIZE;
    _TEB.NtTib.Self = (uint32_t)TEB_ADDR;
    _TEB.ThreadLocalStoragePointer = (uint32_t)TEB_ADDR;
    _TEB.ProcessEnvironmentBlock = (uint32_t)PEB_ADDR;

    size_t size = align(sizeof(_PEB));
    err = uc_mem_map(uc, PEB_ADDR, size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, PEB_ADDR, &_PEB, size);
    uc_assert_success(err);

    
    // Read and print memory contents
    uint8_t readData2[sizeof(_PEB)];
    err = uc_mem_read(uc, PEB_ADDR, readData2, sizeof(readData2));
    size = align(sizeof(_TEB));
    err = uc_mem_map(uc, TEB_ADDR, size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, TEB_ADDR, &_TEB, size);
    uc_assert_success(err);
    // Read and print memory contents
    uint8_t readData3[sizeof(_TEB)];
    err = uc_mem_read(uc, TEB_ADDR, readData3, sizeof(readData3));
}