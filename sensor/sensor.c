#include <stdio.h>
#include <stdlib.h>

#include "sensor.h"
#include "sniffer.h"

extern void fill_progvars(int, char **);

/* GLOBALS */
PV pv;

int main(int argc, char *argv[])
{
	fill_progvars(argc,argv);

	if (!init_sniffer())
		exit(1);

	start_sniffer();

	/* never reached */
	return 0;
}	
