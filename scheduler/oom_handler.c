#include <malloc.h>

#include "oom_handler.h"
#include "utils.h"

pthread_mutex_t oom_mutex;
pthread_cond_t oom_cond;

void init_oom_handler(void)
{
	mutex_init(&oom_mutex);
	cond_init(&oom_cond);
}


void *oom_handler(void)
{
	struct mallinfo info;

	for(;;) {
		mutex_lock(&oom_mutex);		
		cond_wait(&oom_cond, &oom_mutex);
		mutex_unlock(&oom_mutex);

		info = mallinfo();
		DPRINTF("MALLINFO\n");
		DPRINTF("Arena: %d\n", info.arena);
		DPRINTF("Ordblks: %d\n", info.ordblks);
		DPRINTF("Smblks: %d\n", info.smblks);
		DPRINTF("Hblks: %d\n", info.hblks);
		DPRINTF("Hblkhd: %d\n", info.hblkhd);
		DPRINTF("Usmblks: %d\n", info.usmblks);
		DPRINTF("Fsmblks: %d\n", info.fsmblks);
		DPRINTF("Uordblks: %d\n", info.uordblks);
		DPRINTF("Fordblks: %d\n", info.fordblks);
		DPRINTF("Keepcost: %d\n", info.keepcost);
	}
}
