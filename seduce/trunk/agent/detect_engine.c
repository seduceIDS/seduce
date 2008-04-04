#include "detect_engine.h"
#include <stdlib.h>

void destroy_threat(Threat *t)
{
	if(t->length)
		free(t->payload);

	if(t->msg)
		free(t->msg);
}
