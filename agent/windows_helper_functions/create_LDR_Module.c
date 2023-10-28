#include <unicorn/unicorn.h>
#include "../utils-windows-x68.h"
#include "../libpe/include/libpe/pe.h"
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
extern size_t alloc_heap(uint64_t heap_curr_addr, size_t size);
extern pe_exports_t *pe_exported_functions;


LDR_MODULE create_LDR_Module(uc_engine *uc, pe_ctx_t ctx, uint64_t dll_base_address, uint64_t *heap_address){
    
    uc_err err;
    uint64_t heap2write = *heap_address;
    
    // Align functions' address based on DLL Base address
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
        wideString_base_dll_name[i] = (uint16_t)dll_name[i];
    }
    wideString_base_dll_name[full_dll_name_len] = 0;
    for (size_t i = 0; i < full_dll_name_len; i++) {
        wideString_full_dll_name[i] = (uint16_t)full_dll_name[i];
    }
    wideString_full_dll_name[full_dll_name_len] = 0;

    
    size_t base_dll_name_wide_len = (base_dll_name_len) * sizeof(uint16_t); // size of the wide character string in bytes
    size_t full_dll_name_wide_len = (full_dll_name_len) * sizeof(uint16_t); // size of the wide character string in bytes
    
    LDR_MODULE _dataDLL;
    //alloc_heap(sizeof(_dataDLL));
    _dataDLL.BaseAddress = (uint32_t)dll_base_address;
    _dataDLL.EntryPoint = (uint32_t)ctx.pe.entrypoint;
    _dataDLL.SizeOfImage = (uint32_t)ctx.map_size;
    _dataDLL.FullDllName.Length = (uint16_t)full_dll_name_wide_len;
    _dataDLL.FullDllName.MaximumLength = (uint16_t)full_dll_name_wide_len + 2;
    _dataDLL.FullDllName.Buffer = *heap_address + sizeof(_dataDLL);
    _dataDLL.BaseDllName.Length = (uint16_t)base_dll_name_wide_len;
    _dataDLL.BaseDllName.MaximumLength = (uint16_t)base_dll_name_wide_len + 2;
    _dataDLL.BaseDllName.Buffer =  *heap_address + sizeof(_dataDLL) + _dataDLL.FullDllName.MaximumLength;
    
    _dataDLL.InInitializationOrderModuleList.Flink = (uint32_t)PEB_LDR_ADDR + 0xc;
    _dataDLL.InInitializationOrderModuleList.Blink = (uint32_t)PEB_LDR_ADDR + 0xc;
    _dataDLL.InMemoryOrderModuleList.Flink = (uint32_t)PEB_LDR_ADDR + 0x14;
    _dataDLL.InMemoryOrderModuleList.Blink = (uint32_t)PEB_LDR_ADDR + 0x14;
    _dataDLL.InInitializationOrderModuleList.Flink = (uint32_t)PEB_LDR_ADDR + 0x1c;
    _dataDLL.InInitializationOrderModuleList.Blink = (uint32_t)PEB_LDR_ADDR + 0x1c;

    err = uc_mem_write(uc, _dataDLL.FullDllName.Buffer, wideString_full_dll_name, sizeof(wideString_full_dll_name));
    uc_assert_success(err);
    err = uc_mem_write(uc, _dataDLL.BaseDllName.Buffer, wideString_base_dll_name, sizeof(wideString_base_dll_name));
    uc_assert_success(err);
    err = uc_mem_write(uc, heap2write, &_dataDLL, sizeof(_dataDLL));
    uc_assert_success(err);
    free(wideString_full_dll_name);
    free(wideString_base_dll_name);
    return _dataDLL;
}