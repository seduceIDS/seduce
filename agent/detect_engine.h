#ifndef _DETECT_ENGINE_H
#define _DETECT_ENGINE_H

#include <stdio.h>

#define WORK_DONE 1
#define NEED_NEXT 2
#define NEED_PREV 3
#define THREAT_DETECTED 4

int execute_work(char *data, size_t len);
#endif /* _DETECT_ENGINE_H */
