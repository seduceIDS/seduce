#ifndef _HASH_H
#define _HASH_H

#include <glib.h>
#include "data.h"

GHashTable *new_hash_table(void);
void destroy_hash_table(GHashTable *);

Sensor *hash_sensor_insert(GHashTable *, unsigned int);
Sensor *hash_sensor_lookup(GHashTable *, unsigned int);
int     hash_sensor_remove(GHashTable *, unsigned int);

Session *hash_session_insert(GHashTable *, unsigned int);
Session *hash_session_lookup(GHashTable *, unsigned int);
int      hash_session_remove(GHashTable *, unsigned int);


int             hash_agent_insert (GHashTable *, u_int32_t, unsigned short);
unsigned short *hash_agent_lookup (GHashTable *, u_int32_t);
int             hash_agent_remove (GHashTable *, u_int32_t);


#endif /* _HASH_H */
