#ifndef _ERROR_H
#define _ERROR_H

#include <stdio.h>
#include <stdarg.h>

void critical_error(int rc, char *fmt, ...);
void proto_violation(char *fmt, ...);

#endif /* _ERROR_H */
