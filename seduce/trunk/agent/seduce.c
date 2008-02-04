#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

#include "qemu.h"

char *getBlock(char *, size_t, int);
extern unsigned long x86_stack_size;

sigjmp_buf env;

void *data = "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2"
			 "\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff"
			 "\x68\x65\x6c\x6c\x6f\x00";

void handler(int signum);
void handler(int signum)
{
    printf("To epiasa!!\n"); 
    siglongjmp(env, 100);
}

int main(int argc, char **argv)
{
	int ret, i, l = 0, fd;
    char *block;
    void *addr;
    void *buff;
    struct stat st;
    unsigned long fsize = 0;
    struct itimerval value;
    struct itimerval ovalue;
    struct timeval time_interval;
    struct timeval time_value;
    struct sigaction new_action;
    int blocksize;
    unsigned long stack_base;
    CPUX86State *cpu;

    new_action.sa_handler = handler;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    sigaction (SIGVTALRM, &new_action, NULL);

    time_interval.tv_sec = 0;
    time_interval.tv_usec = 500000;

    time_value.tv_sec = 0;
    time_value.tv_usec = 500000;

    value.it_interval = time_interval;
    value.it_value = time_value;

    ovalue.it_interval = time_interval;
    ovalue.it_value = time_value;

    if (argc < 2)
    {
        printf("usage %s file\n",argv[0]);
        _exit(-1);
    }

    fd = open(argv[1],0);
    fstat(fd,&st);
    fsize = st.st_size;
    buff = malloc(fsize + 1);
    memset(buff, 0, fsize + 1);
    read(fd, buff, fsize);
    close(fd);
/*
    l = 0;
    while ((block = getBlock(buff, fsize + 1, 30)) != NULL)
    {
        l++;
        printf("%d address %x size %d\n",l,block,strlen(block));
    }
    return 0;
*/
    setitimer(ITIMER_VIRTUAL, &value, &ovalue);
    l = 0;
    cpu = malloc(sizeof(CPUX86State));
    stack_base = setup_stack();
    while ((block = getBlock(buff, fsize + 1, 5)) != NULL)
    {
        /*
        if (l == 14)
        {
            FILE *fp;
            fp = fopen("data1","w");
            fwrite(block,strlen(block),1,fp);
            fclose(fp);
        }
        else if (l > 14)
            return;
        */
        l++;
        blocksize = strlen(block);
        addr = malloc(blocksize + 1);
        if (addr == NULL)
        {
            printf("malloc failed\n");
            _exit(-1);
        }
        memset(addr, 0, blocksize + 1);

        for (i = 0; i < blocksize; i++)
        {
            if (sigsetjmp(env,1) == 100)
            {
                printf("return from signal so continue\n");
                continue;
            }
            memcpy(addr, block, blocksize);
            printf("block %d - byte %.2d - ", l, i);
            fflush(stdout);
            //printf("size=%d\n",strlen(addr+i));
            ret = qemu_exec(addr + i, strlen(addr + i), stack_base, cpu);
            switch(ret) 
            {
                case SYSTEM_CALL:
                    printf("syscall   - %d\n",cpu->regs[R_EAX]);
                    break;
                case EXCEPTION_INTERRUPT:
                    printf("exception - INTERRUPT\n");
                    break;
                case EXCEPTION_NOSEG:
                    printf("exception - NOSEG\n");
                    break;
                case EXCEPTION_STACK:
                    printf("exception - Stack Fault\n");
                    break;
                case EXCEPTION_GPF:
                    printf("exception - General Protection Fault\n");
                    break;
                case EXCEPTION_PAGE:
                    printf("exception - Page Fault\n");
                    break;
                case EXCEPTION_DIVZ:
                    printf("exception - Division by Zero\n");
                    break;
                case EXCEPTION_SSTP:
                    printf("exception - SSTP\n");
                    break;
                case EXCEPTION_INT3:
                    printf("exception - INT3\n");
                    break;
                case EXCEPTION_INTO:
                    printf("exception - INTO\n");
                    break;
                case EXCEPTION_BOUND:
                    printf("exception - BOUND\n");
                    break;
                case EXCEPTION_ILLOP:
                    printf("exception - Illegal Operation\n");
                    break;
                case EXCEPTION_DEBUG:
                    printf("exception - DEBUG\n");
                    break;
                default:
                    printf("unknown exception\n");
            }
        }
        free(addr);
    }
    free(cpu);

    if (munmap((void *)stack_base, x86_stack_size)==-1)
    {
        perror("munmap");
        _exit(-1);
    }

    free(buff);
    _exit(0);
}

char *getBlock(char *data, size_t len, int min)
{
    assert(data[len - 1] == '\0');

    static char *p = NULL;
    if (p == NULL) p = data;
    char *last;
    
    for (last = p; p < data + len; p++)
    {
        if (!*p)
        {
            if (p - last < min)
                last = p + 1;
            else
            {
                p++;
                return last;
            }
        }
    }
    return NULL;
}

