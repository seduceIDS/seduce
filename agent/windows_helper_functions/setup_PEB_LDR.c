#include <unicorn/unicorn.h>
#include "../libpe/include/libpe/pe.h"
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

void setup_PEB_LDR(uc_engine *uc){
    uc_err err;

    PEB_LDR_DATA _dataPEB_LDR;
    _dataPEB_LDR.InInitializationOrderModuleList.Flink = (uint32_t)HEAP_BASE;
    _dataPEB_LDR.InInitializationOrderModuleList.Blink = (uint32_t)HEAP_BASE;
    _dataPEB_LDR.InMemoryOrderModuleList.Flink = (uint32_t)HEAP_BASE + 0x8;
    _dataPEB_LDR.InMemoryOrderModuleList.Blink = (uint32_t)HEAP_BASE + 0x8;
    _dataPEB_LDR.InInitializationOrderModuleList.Flink = (uint32_t)HEAP_BASE + 0x10;
    _dataPEB_LDR.InInitializationOrderModuleList.Blink = (uint32_t)HEAP_BASE + 0x10;

    size_t size = align(sizeof(_dataPEB_LDR));
    err = uc_mem_map(uc, PEB_LDR_ADDR, size, UC_PROT_ALL);
    uc_assert_success(err);
    err = uc_mem_write(uc, PEB_LDR_ADDR, &_dataPEB_LDR, sizeof(_dataPEB_LDR));
    uc_assert_success(err);
}