#include <stdlib.h>
#include <time.h>
#include <math.h>

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

