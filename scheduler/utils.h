#ifndef _UTILS_H
#define _UTILS_H

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

#define YES (1==1)
#define NO (!TRUE)

/* Functions Declaration */
unsigned short find_first_zero(u_int8_t);
unsigned int get_rand(void);

#endif
