/*
 * This file contains the hash table functions
 */

#include <stdio.h>
#include <glib.h>
#include "data.h"
#include "errors.h"

GHashTable *new_hash_table(void)
{
	return g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
									g_free);
}

void destroy_hash_table (GHashTable *hash)
{
	g_hash_table_destroy(hash);
}

		/* Session functions */
Session *hash_session_insert(unsigned id)
{
	Session *new_session;

	new_session = g_try_new(Session, 1);
	if (new_session)
		g_hash_table_insert(sensor.hash, GUINT_TO_POINTER(id),
								new_session);
	else
		errno_cont("g_try_new");

	return new_session;
}

Session * hash_session_lookup(unsigned id)
{
	return g_hash_table_lookup(sensor.hash, GUINT_TO_POINTER(id));
}

int hash_session_remove(unsigned id)
{
	gboolean ret;

	ret = g_hash_table_remove(sensor.hash, GUINT_TO_POINTER(id));

	return (ret == TRUE) ? 1 : 0;
}

		/* Agent functions */
int hash_agent_insert(GHashTable *hash, uint32_t id, unsigned short index)
{
	unsigned short *value;

	value = g_try_new(unsigned short, 1);
	if (value) {
		*value = index;
		g_hash_table_insert(hash, GUINT_TO_POINTER(id), value);
		return 1;
	} else
		errno_cont("g_try_new");

	return 0;
}

unsigned short *hash_agent_lookup(GHashTable *hash, u_int32_t id)
{
       return g_hash_table_lookup(hash, GUINT_TO_POINTER(id));
}

int hash_agent_remove(GHashTable *hash, u_int32_t id)
{
	gboolean ret;

	ret = g_hash_table_remove(hash, GUINT_TO_POINTER(id));

	return (ret == TRUE) ? 1 : 0;
}
