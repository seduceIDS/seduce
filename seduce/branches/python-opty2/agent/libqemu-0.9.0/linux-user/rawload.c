#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "qemu.h"

int load_raw_binary(void *data, size_t len, struct image_info * info, unsigned long stack_base)
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

    // Stack segment
    info->start_stack = stack_base;

    return 0;
}

