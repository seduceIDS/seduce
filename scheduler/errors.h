#ifndef _ERRORS_H
#define _ERRORS_H

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define err_abort(code,text,...) do { \
	fprintf(stderr, text"\n",##__VA_ARGS__); \
	fprintf(stderr,"\"%s\":%d: %s\n",__FILE__, __LINE__, strerror (code)); \
	abort (); \
} while (0)

#define errno_abort(text,...) do { \
	fprintf(stderr, text"\n",##__VA_ARGS__); \
	fprintf(stderr,"\"%s\":%d: %s\n",__FILE__, __LINE__, strerror (errno)); \
	abort (); \
} while (0)

#define err_cont(code,text,...) do { \
	fprintf(stderr, text"\n",##__VA_ARGS__); \
	fprintf(stderr,"\"%s\":%d: %s\n",__FILE__, __LINE__, strerror (code)); \
} while (0)

#define errno_cont(text,...) do { \
	fprintf(stderr, text"\n",##__VA_ARGS__); \
	fprintf(stderr,"\"%s\":%d: %s\n",__FILE__, __LINE__, strerror (errno)); \
} while (0)

#endif /* _ERRORS_H */

		
