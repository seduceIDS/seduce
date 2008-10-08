#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>

#ifdef _DEBUG
	#define DPRINTF(...) do {\
		fprintf(stderr,"%s:\t",__func__); \
		fprintf(stderr, __VA_ARGS__); \
	} while(0)
#else
	#define DPRINTF(...)
#endif

void compute_md5(void *buffer, int len, char md5str[33]);

#endif /* _UTILS_H */

