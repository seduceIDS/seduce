#include <assert.h>

#include "base64.h"

static const char base64_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode_step(const unsigned char *in, size_t len, char *out,
		          int *state, int *save)
{
	char *outptr;
	const unsigned char *inptr;
  
	if(len == 0)
		return 0;
  
	inptr = in;
	outptr = out;
  
	if (len + ((char *) save) [0] > 2) {
		const unsigned char *inend = in + len - 2;
		int c1, c2, c3;
		int already;

		already = *state;
		
		switch (((char *) save) [0]) {
		case 1:
			c1 = ((unsigned char *) save) [1];
			goto skip1;
		case 2:
			c1 = ((unsigned char *) save) [1];
			c2 = ((unsigned char *) save) [2];
			goto skip2;
		}

		/* 
		 * yes, we jump into the loop, no i'm not going to change it, 
		 * it's beautiful! 
		 */

		while (inptr < inend) {
			c1 = *inptr++;
skip1:
			c2 = *inptr++;
skip2:
			c3 = *inptr++;
			*outptr++ = base64_alphabet [ c1 >> 2 ];
			*outptr++ = base64_alphabet [ c2 >> 4 |
				((c1&0x3) << 4) ];
			*outptr++ = base64_alphabet [ ((c2 &0x0f) << 2) | 
				(c3 >> 6) ];
			*outptr++ = base64_alphabet [ c3 & 0x3f ];
			/* this is a bit ugly ... */
			if ((++already) >= 19) {
				*outptr++ = '\n';
				already = 0;
			}
		}

		((char *)save)[0] = 0;
		len = 2 - (inptr - inend);
		*state = already;
	}

	if(len > 0) {
		char *saveout;

		/* points to the slot for the next char to save */
		saveout = & (((char *)save)[1]) + ((char *)save)[0];

		/* len can only be 0 1 or 2 */
		switch(len) {
		case 2:
			*saveout++ = *inptr++;
		case 1:
			*saveout++ = *inptr++;
		}
		((char *)save)[0] += len;
	}

	return outptr - out;
}

size_t base64_encode_close(char *out, int *state, int *save)
{
	int c1, c2;
	char *outptr = out;
	
	c1 = ((unsigned char *) save) [1];
	c2 = ((unsigned char *) save) [2];
	
	switch (((char *) save) [0]) {
	case 2:
		outptr [2] = base64_alphabet[ ( (c2 & 0x0f) << 2 ) ];
		assert(outptr [2] != 0);
		goto skip;
	case 1:
		outptr[2] = '=';
skip:
		outptr [0] = base64_alphabet [c1 >> 2];
		outptr [1] = base64_alphabet [c2 >> 4 | ((c1 & 0x3) << 4)];
		outptr [3] = '=';
		outptr += 4;
		break;
	}
	
	*outptr++ = '\n';
	
	*save = 0;
	*state = 0;
	
	return outptr - out;
}

