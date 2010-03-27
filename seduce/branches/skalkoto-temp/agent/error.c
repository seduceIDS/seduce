#include "error.h"
#include <stdlib.h>

void critical_error(int rc, char *fmt, ...)
{
	va_list argp;

	fprintf(stderr, "Critical Error: ");
	va_start(argp, fmt);
	vfprintf(stderr, fmt, argp);
	va_end(argp);
	
	fprintf(stderr, ". Quitting...\n");
	exit(rc);
}

void proto_violation(char *fmt, ...)
{
	va_list argp;

	fprintf(stderr, "Protocol Violation: ");
	va_start(argp, fmt);
	vfprintf(stderr, fmt, argp);
	va_end(argp);

	fprintf(stderr, "\n");
}
