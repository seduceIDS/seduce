#include <malloc.h>

#include "oom_handler.h"
#include "utils.h"
#include "manager.h"
#include "job.h"

pthread_mutex_t oom_mutex;
pthread_cond_t oom_cond;

void init_oom_handler(void)
{
	mutex_init(&oom_mutex);
	cond_init(&oom_cond);
}

void print_mem_usage(struct mallinfo *info)
{
	DPRINTF("MALLINFO\n");
	DPRINTF("Arena: %d\n", info->arena);
	DPRINTF("Ordblks: %d\n", info->ordblks);
	DPRINTF("Smblks: %d\n", info->smblks);
	DPRINTF("Hblks: %d\n", info->hblks);
	DPRINTF("Hblkhd: %d\n", info->hblkhd);
	DPRINTF("Usmblks: %d\n", info->usmblks);
	DPRINTF("Fsmblks: %d\n", info->fsmblks);
	DPRINTF("Uordblks: %d\n", info->uordblks);
	DPRINTF("Fordblks: %d\n", info->fordblks);
	DPRINTF("Keepcost: %d\n", info->keepcost);
}

int free_memory(void)
{
	struct mallinfo info;
	unsigned long occupied_mem;
	int ret;

	do {
		ret = execute_job(destroy_data, NULL);
		if(ret == -1) /* joblist is empty */
			break;

		info = mallinfo();
		/* occupied memory = malloc + mmap */
		occupied_mem = info.uordblks + info.hblkhd;

	} while(occupied_mem > pv.mem_softlimit);

	info = mallinfo();
	occupied_mem = info.uordblks + info.hblkhd;

	return (occupied_mem <= pv.mem_softlimit) ? 1 : 0;
}


void *oom_handler(void)
{
	struct mallinfo info;
	unsigned long occupied_mem;

	for(;;) {
		mutex_lock(&oom_mutex);		
		cond_wait(&oom_cond, &oom_mutex);
		mutex_unlock(&oom_mutex);

		info = mallinfo();
		print_mem_usage(&info);		
		occupied_mem = info.uordblks + info.hblkhd;

		if(occupied_mem > pv.mem_hardlimit)
			free_memory();
	}
}
