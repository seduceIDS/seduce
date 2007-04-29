#ifndef _ERRORS_H
#define _ERRORS_H

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef _DEBUG
# define DPRINTF(arg) printf  arg
#else
# define DPRINTF(arg)
#endif


#endif
