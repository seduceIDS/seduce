#ifndef UTILS_WINDOWS
#define UTILS_WINDOWS

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
size_t align(size_t size);

#endif