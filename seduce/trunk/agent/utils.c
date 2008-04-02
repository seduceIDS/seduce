#include <string.h>
#include "utils.h"

#include "agent.h"		/* for pv */
#include "server_contact.h"	/* for PROTO_PWD_SIZE */

inline void copy_password(char *buf)
{
	strncpy(buf, pv.password, MAX_PWD_SIZE);
}
