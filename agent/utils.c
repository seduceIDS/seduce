#include "utils.h"
#include "md5.h"

void compute_md5(void *buffer, int len, char md5str[33]){
	char md5res[17];
	struct md5_ctx tmp_hash;
	int i;

	md5_init_ctx(&tmp_hash);
	md5_process_bytes(buffer, len, &tmp_hash);
	md5_finish_ctx(&tmp_hash, md5res);
	md5res[16] = '\0';

	for(i=0; md5res[i] != '\0'; i++){
		sprintf(&md5str[i*2], "%.2hhx", md5res[i]);
	}

}
