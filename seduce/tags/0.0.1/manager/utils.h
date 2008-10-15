#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <netinet/in.h> /* for struct in_addr */

#ifdef _DEBUG
	#define DPRINTF(...) do {\
		fprintf(stderr,"%s:\t",__func__); \
		fprintf(stderr, __VA_ARGS__); \
	} while(0)
#else
	#define DPRINTF(...)
#endif

#undef  MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#undef	MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#undef	YES
#define YES (1==1)
#undef	NO
#define NO (!YES)

/* Function Declarations */
unsigned short find_first_zero(u_int8_t);
unsigned int get_rand(void);

ssize_t readline(int, void *, size_t);
ssize_t writen(int, const void *, size_t);

int str2num(const char *);
int addrtok(char *buf, struct in_addr *addr, unsigned short *port);
int get_empty_line(int sock);

#endif
