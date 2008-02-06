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
#include "exec-all.h"

char *getBlock(char *, size_t, int);
void free_struct_entries(void);
void handler(int signum);
extern unsigned long x86_stack_size;
extern spinlock_t tb_lock;

sigjmp_buf env;

void *data = "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2"
			 "\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff"
			 "\x68\x65\x6c\x6c\x6f\x00";

void handler(int signum)
{
    tb_lock = SPIN_LOCK_UNLOCKED;
    siglongjmp(env, 100);
}

void free_struct_entries(void)
{
    int c;
    for (c = 1; c < 24; c++)
    {
        free(struct_entries[c].field_offsets[0]);
        free(struct_entries[c].field_offsets[1]);
    }
    memset(struct_entries, 0, sizeof(StructEntry) * 128);
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
    struct itimerval zvalue;
    struct sigaction new_action;
    int blocksize;
    unsigned long stack_base;
    CPUX86State *cpu;

    new_action.sa_handler = handler;
    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    sigaction (SIGVTALRM, &new_action, NULL);

    value.it_interval.tv_usec = value.it_value.tv_usec = 1000;
    value.it_interval.tv_sec = value.it_value.tv_sec = 0;

    zvalue.it_interval.tv_sec = 
    	zvalue.it_interval.tv_usec = 
	zvalue.it_value.tv_sec = 
	zvalue.it_value.tv_usec = 0;

    if (argc < 2)
    {
        fprintf(stderr,"usage %s file\n",argv[0]);
        return -1;
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
        fprintf(stderr,"%d address %x size %d\n",l,block,strlen(block));
    }
    return 0;
*/
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
        addr = calloc(1, blocksize + 1);
        if (addr == NULL)
        {
            fprintf(stderr,"malloc failed\n");
            return -1;
        }

        for (i = 0; i < blocksize; i++)
        {
            memcpy(addr, block, blocksize);
            fprintf(stderr, "block %d - byte %.2d - ", l, i);
            //printf("size=%d\n",strlen(addr+i));
	    if (sigsetjmp(env,1) == 100)
            {
                fprintf(stderr, "Endless Loop detected!\n");
		setitimer(ITIMER_VIRTUAL, &zvalue, (struct itimerval*) NULL);
                continue;
            }

    	    setitimer(ITIMER_VIRTUAL, &value, (struct itimerval*) NULL);
            ret = qemu_exec(addr + i, strlen(addr + i), stack_base, cpu);
	    setitimer(ITIMER_VIRTUAL, &zvalue, (struct itimerval*) NULL);

            switch(ret) 
            {
                case SYSTEM_CALL:
                    fprintf(stderr,"syscall   - %d\n",cpu->regs[R_EAX]);
                    break;
                case EXCEPTION_INTERRUPT:
                    fprintf(stderr,"exception - INTERRUPT\n");
                    break;
                case EXCEPTION_NOSEG:
                    fprintf(stderr,"exception - NOSEG\n");
                    break;
                case EXCEPTION_STACK:
                    fprintf(stderr,"exception - Stack Fault\n");
                    break;
                case EXCEPTION_GPF:
                    fprintf(stderr,"exception - General Protection Fault\n");
                    break;
                case EXCEPTION_PAGE:
                    fprintf(stderr,"exception - Page Fault\n");
                    break;
                case EXCEPTION_DIVZ:
                    fprintf(stderr,"exception - Division by Zero\n");
                    break;
                case EXCEPTION_SSTP:
                    fprintf(stderr,"exception - SSTP\n");
                    break;
                case EXCEPTION_INT3:
                    fprintf(stderr,"exception - INT3\n");
                    break;
                case EXCEPTION_INTO:
                    fprintf(stderr,"exception - INTO\n");
                    break;
                case EXCEPTION_BOUND:
                    fprintf(stderr,"exception - BOUND\n");
                    break;
                case EXCEPTION_ILLOP:
                    fprintf(stderr,"exception - Illegal Operation\n");
                    break;
                case EXCEPTION_DEBUG:
                    fprintf(stderr,"exception - DEBUG\n");
                    break;
                default:
                    fprintf(stderr,"unknown exception\n");
            }
        }
        free(addr);
    }
    free(cpu);
    free_struct_entries();

    if (munmap((void *)stack_base - x86_stack_size, x86_stack_size) == -1)
    {
        perror("munmap");
        return -1;
    }

    free(buff);
    return 0;
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

