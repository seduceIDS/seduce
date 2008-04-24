#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"

/*
 * find the position of the first 0 in a 8-bit array
 */
inline unsigned short find_first_zero(u_int8_t bit_array)
{
	if ((bit_array = ~bit_array) == 0)
		return 8;

	return (unsigned short)(log(bit_array & -bit_array)/log(2));
}


/*
 * Create a random unsigned integer
 */
inline unsigned int get_rand(void)
{
	unsigned int seed;

	seed = (unsigned int) time(NULL);
	srandom(seed);
	return (unsigned int) random();
}

/*
 * Thread Safe readline! Thank you Mr. Stevens....
 */

#define MAXLINE 128

static pthread_key_t r1_key;
static pthread_once_t r1_once = PTHREAD_ONCE_INIT;

static void readline_destructor(void *ptr)
{
	free(ptr);
}

static void readline_once(void)
{
	/* Well..I admit it! I don't check for errors */
	(void) pthread_key_create(&r1_key, readline_destructor);
}

typedef struct {
	int r1_cnt;
	char *r1_bufptr;
	char r1_buf[MAXLINE];
} Rline;

static ssize_t my_read(Rline *tsd, int fd, char *ptr)
{
	if(tsd->r1_cnt <= 0) {
again:
		if((tsd->r1_cnt = read(fd, tsd->r1_buf, MAXLINE)) < 0) {
			if(errno == EINTR)
				goto again;
			return -1;
		} else if(tsd->r1_cnt == 0)
			return 0;
		tsd->r1_bufptr = tsd->r1_buf;
	}
	tsd->r1_cnt--;
	*ptr = *tsd->r1_bufptr++;
	return 1;
}

ssize_t readline(int fd, void *vptr, size_t maxlen)
{
	int n,rc;
	char c, *p;
	Rline *tsd;

	if(pthread_once(&r1_once, readline_once))
		return -2;

	if((tsd = pthread_getspecific(r1_key)) == NULL) {
		tsd = calloc(1, sizeof(Rline));
		if(tsd == NULL)
			return -2;

		if(pthread_setspecific(r1_key, tsd))
			return -2;
	}
	p = vptr;
	for(n = 1; n < maxlen; n++) {
		if((rc = my_read(tsd, fd, &c)) == 1) {
			*p++ = c;
			if(c == '\n') {
				break;
			}
		} else if (rc == 0) {
			if (n == 1)
				return 0;
			else 
				break;
		} else
			return -1;
	}

	*p = 0;
	return n;
}

ssize_t writen(int sock, const void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	const char *p;

	p = vptr;
	nleft = n;

	while(nleft > 0) {
		if((nwritten = write(sock, p, nleft)) <= 0) {
			if(errno == EINTR)
				nwritten = 0;
			else
				return -1;
		}
		nleft -= nwritten;
		p += nwritten;
	}
	return n;
}

int str2num(const char *str)
{
	unsigned long int num = 0;
	unsigned int digits = 0;
	const char *p;

	p = str;
	for(p = str; isspace(*p); p++)
		;

	for(; isdigit(*p); p++) {
		digits++;
		num *= 10;
		num += (*p - '0');
	}

	for(; isspace(*p); p++)
		;

	/* Is the string format ___dddddd...___ ? */
	if(*p != '\0')
		return -1;

	/* Does it contain a n number, or is it only whitespaces? */
	if(digits == 0)
		return -2;


	if(digits > 10) // How many digits do we allow?
		return -2;

	return num;
}

int addrtok(char *buf, struct in_addr *addr, unsigned short *port)
{
	char *p;
	int digits;
	unsigned int tmp = 0;

	p = buf;
	while((*p != '\0') && (*p != ':'))
		p++;

	if(*p == ':')
		*p++ = 0;
	else
		return 0;

	if(!inet_aton(buf, addr))
		return 0;

	/* port */
	for(digits = 0; isdigit(*p); digits++, p++) {
		tmp *= 10;
		tmp += (*p - '0');
	}

	while(isspace(*p))
		p++;

	if(*p != '\0')
		return 0;
	if(digits < 1 || digits > 5)
		return 0;
	if(tmp < 1 || tmp > 65535) /* valid port range */
		return 0;

	*port = (unsigned short) tmp;

	return 1;
}
