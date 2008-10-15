#ifndef _BASE64_ENCODER_H
#define _BASE64_ENCODER_H

#include <stddef.h> /* for size_t */

size_t base64_encode_step(const unsigned char *in, size_t len, char *out,
							int *state, int *save);

size_t base64_encode_close(char * out, int *state, int *save);

#endif /* _BASE64_ENCODER_H */
