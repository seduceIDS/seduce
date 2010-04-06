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
		int ret = consume_job(destroy_datagroup, NULL);
		if(ret == -1) {
			/* joblist is empty, couldn't delete enough data */
			return 0;
		} else if(ret == 2) {
			/* 
			 * TODO: this is really important!!! I need to destroy
			 * a sensor but I don't know which. I think I cannot
			 * avoid searching the hole sensor list to find the one
			 * that has sessionlist_head == NULL & is_connected = NO
			 */
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

		if(occupied_mem > mpv.mem_hardlimit)
			free_memory(mpv.mem_softlimit);
	}
}
