#ifndef _AGENT_H
#define _AGENT_H

#include "detect_engine.h"
#include "server_contact.h"

typedef struct _ProgVars {
	const char *prog_name;/* program name */
	int no_work_wait;    /* Seconds to wait when no work available */
	DetectEngine *detect_engine;
	ServerSession *server_session;
} ProgVars;

#endif /* _AGENT_H */
