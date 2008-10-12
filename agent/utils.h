#ifndef _UTILS_H
#define _UTILS_H 	1

#include <stdio.h>
#include "md5.h"

#ifdef _DEBUG
	#define DPRINTF(...) do {\
		fprintf(stderr,"%s:\t",__func__); \
		fprintf(stderr, __VA_ARGS__); \
	} while(0)

	#define DPRINTF_MD5(data, len, fmt, ...) do {\
		char md5str[33]; \
		compute_md5(data, len, md5str); \
		fprintf(stderr, "%s:\t[%i bytes] [%s] " fmt, \
			__func__, len, md5str, __VA_ARGS__); \
	} while(0)
#else
	#define DPRINTF(...)
	#define DPRINTF_MD5(data, len, fmt, ...)
#endif

void compute_md5(void *data, int data_len, char md5str[33]);

#endif /* _UTILS_H */

