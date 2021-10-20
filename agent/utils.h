#ifndef _UTILS_H
#define _UTILS_H

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "md5.h"

#ifdef _DEBUG

#define DPRINTF(fmt, ...) do { \
	fprintf(stderr, "%d: %s: " fmt, getpid(), __func__, ##__VA_ARGS__); \
} while(0)

#define DPRINTF_MD5(data, len, fmt, ...) do { \
	char md5str[33]; \
	compute_md5(data, len, md5str); \
	fprintf(stderr, "%d: %s: [%i bytes] [%s] " fmt, \
		getpid(), __func__, len, md5str, ##__VA_ARGS__); \
} while(0)

#else

#define DPRINTF(...)
#define DPRINTF_MD5(data, len, fmt, ...)

#endif /* _DEBUG */

void compute_md5(const void *data, int data_len, char md5str[33]);

#endif /* _UTILS_H */

