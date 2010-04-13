#include <stdio.h>
#include <stdlib.h>

#include "sensor.h"
#include "sniffer.h"

#ifdef TWO_TIER_ARCH
#include "../manager/manager.h"
#endif

extern void fill_progvars(int, char **);

/* GLOBALS */
SPV spv;

int main(int argc, char *argv[])
{
	fill_progvars(argc,argv);

	if (!init_sniffer())
		exit(1);

#ifdef TWO_TIER_ARCH
	if(!start_manager())
		exit(1);
#endif
	start_sniffer();

	/* never reached */
	return 0;
}
