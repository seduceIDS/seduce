#ifndef _HASH_H
#define _HASH_H

#include <glib.h>
#include "data.h"

GHashTable *new_hash_table(void);
void destroy_hash_table(GHashTable *);

Session *hash_session_insert(unsigned id);
Session *hash_session_lookup(unsigned id);
int      hash_session_remove(unsigned id);


int             hash_agent_insert (GHashTable *, uint32_t, unsigned short);
unsigned short *hash_agent_lookup (GHashTable *, uint32_t);
int             hash_agent_remove (GHashTable *, uint32_t);

#endif /* _HASH_H */
