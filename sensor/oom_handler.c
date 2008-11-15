#include <malloc.h>

#include "oom_handler.h"
#include "sensor.h"
#include "data.h"
#include "utils.h"

pthread_mutex_t oom_mutex;
pthread_cond_t oom_cond;

void init_oom_handler(void)
{
	mutex_init(&oom_mutex);
	cond_init(&oom_cond);
}

static inline void print_mem_usage(struct mallinfo *info)
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

static unsigned long compute_mem_usage(void)
{
	struct mallinfo info;

	info = mallinfo();
	print_mem_usage(&info);

	/* occupied memory = malloc + mmap */
	return info.uordblks + info.hblkhd;
}

static int free_memory(int limit_to_reach)
{
	unsigned long mem;

	DPRINTF("Freeing memory");

	do {
		int ret = consume_group(destroy_datagroup, NULL);
		if(ret == -1) {
			/* joblist is empty, couldn't delete enough data */
			return 0;
		}

		mem = compute_mem_usage();

	} while(mem > limit_to_reach);

	return 1;
}


void *oom_handler(void)
{
	unsigned long occupied_mem;

	for(;;) {
		mutex_lock(&oom_mutex);
		cond_wait(&oom_cond, &oom_mutex);
		mutex_unlock(&oom_mutex);

		occupied_mem = compute_mem_usage();

		if(occupied_mem > pv.mem_hardlimit)
			free_memory(pv.mem_softlimit);
	}
}
