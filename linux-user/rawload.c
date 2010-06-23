#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "qemu.h"
#include "../cpu-all.h"

unsigned long setup_stack(void)
{
    target_ulong stack_base, size, mem;

    /* Create enough stack to hold everything.  If we don't use
     * it for args, we'll use it for something else...
     */
    size = x86_stack_size;

    mem = target_mmap(0, 
                        size + qemu_host_page_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
    if (mem == -1) {
        perror("error while creating target stack with mmap");
        exit(-1);
    }
    /* we reserve one extra page at the top of the stack as guard */
    target_mprotect(mem + size, qemu_host_page_size, PROT_NONE);

    stack_base = mem + size;

    return stack_base;
}

int load_raw_binary(void *data, size_t len, struct image_info * info, target_ulong stack_base)
{
    // Text segment
    info->start_code  = (unsigned long) data;
    info->end_code    = info->start_code + len;
    // Data segment
    info->start_data  = info->end_code;
    info->end_data    = info->end_code;
    // Heap segment
    info->start_brk   = info->end_code;
    info->brk         = info->end_code;
    // Entry point
    info->entry       = info->start_code;

    info->start_mmap  = 0x80000000;
    info->mmap        = 0;
    info->personality = 0;
    info->rss = 0;

    // Stack segment - since the %esp for network payloads
    // is somewhere within the program's stack I simulate
    // this by bringing the stack bottom a page over the
    // the real start of the stack.
    info->start_stack = stack_base - qemu_host_page_size;

    return 0;
}
