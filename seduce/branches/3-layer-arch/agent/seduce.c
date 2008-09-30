#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "detect_engine.h"
#include "detect_engine_qemu.h"


void *load_file(const char *filename, unsigned long *fsize)
{
    int fd;
    void *buff;
    struct stat st;

    if ((fd = open(filename, 0)) == -1) {
        perror("open");
        exit(-1);
    }
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        exit(-1);
    }
    *fsize = st.st_size;
    buff = calloc(1, *fsize + 1);
    if (buff == NULL) {
        fprintf(stderr,"calloc failed\n");
        exit(-1);
    }
    if (read(fd, buff, *fsize) == -1) {
        perror("read");
        exit(-1);
    }
    close(fd);
    return buff;
}

int main(int argc, char **argv)
{
    void *buff;
    unsigned long fsize;
    struct sigaction sa;
    int ret;

    if (argc < 2) {
        fprintf(stderr,"usage %s file\n", argv[0]);
        return -1;
    }

    sa.sa_handler = sigvtalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGVTALRM, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(-1);
    }

    buff = load_file(argv[1], &fsize);

    qemu_engine_init();
    ret = qemu_engine_process(buff, fsize + 1);
    qemu_engine_destroy();
    free(buff);

    if (ret == 1)
    {
        Threat t;
        qemu_engine_get_threat(&t);
        printf("Threat detected - %s\n", t.msg);
        free(t.msg);
    } else if (ret == 0)
        printf("No threat detected\n");
    else
        printf("Unknown return code\n");
    
    return 0;
}

