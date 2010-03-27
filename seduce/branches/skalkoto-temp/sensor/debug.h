#ifndef _ERRORS_H
#define _ERRORS_H

#include <stdio.h> /* for fprintf */


#ifdef _DEBUG
	#define DPRINTF(...) do {\
		fprintf(stderr, __VA_ARGS__); \
		} while (0)
#else
	#define DPRINTF(...)
#endif


#endif
