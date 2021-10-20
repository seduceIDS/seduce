#include "utils.h"
#include "md5.h"

void compute_md5(const void *data, int len, char md5str[33])
{
	char md5res[16];
	struct md5_ctx tmp_hash;
	int i;

	md5_init_ctx(&tmp_hash);
	md5_process_bytes(data, len, &tmp_hash);
	md5_finish_ctx(&tmp_hash, md5res);

	for(i = 0; i < sizeof(md5res); i++)
		sprintf(&md5str[i*2], "%.2hhx", md5res[i]);
}
