/*
 * Functions for manipulating and accessing the data stored in the manager.
 */

#include <strings.h>
#include <stdlib.h>

#include "sensor.h"
#include "data.h"
#include "errors.h"
#include "hash.h"
#include "utils.h"
#include "oom_handler.h"


/* The Sensor */
Sensor sensor;

/*
 * Function: init_datalists()
 *
 * Purpose: Initialize the sensor struct
 */
void init_datalists(void)
{
	sensor.sessionlist_head = NULL;
	sensor.sessionlist_tail = NULL;

	mutex_init (&sensor.mutex);

	sensor.hash = new_hash_table();
	if (sensor.hash == NULL) {
		fprintf(stderr,"Can't create sensor hash table\n");
		abort();
	}
}

/*
 * Function: find_session(unsigned)
 *
 * Purpose: Find a sensor session identified by a stream_id.
 * 	ATTENTION: The stream_id is not the same as the session_id. This
 * 	function is supposed to be used only by the sensor_contact threads. If
 * 	you know the session_id just use hash_session_lookup to find a session.
 *
 * Arguments:  id=> A stream id
 *
 * Returns: Pointer to a session on success, NULL on error
 */
Session *find_session(unsigned id)
{
	unsigned int correct_id;

	correct_id = id + sensor.id_start;
	return hash_session_lookup(correct_id);
}


/*
 * Function: add_session(Sensor *, unsigned int, struct tuple4 *, int)
 *
 * Purpose: Add a new session to a sensor's sessions list.
 *
 * Arguments: sensor=> Pointer to a sensor struct
 *            id=> stream ID of the session we are about to add
 *            addr=> sessions address info (server's and client's IP and ports)
 *            proto=> IP protocol IPPROTO_TCP for TCP and IPPROTO_UDP for UDP
 *
 * Returns: Pointer to the newly added session on success, NULL on error
 */
Session *add_session(unsigned id, const struct tuple4 *addr, int proto)
{
	Session *new_session;
	unsigned int correct_id; 
	
	correct_id = id + sensor.id_start;
	new_session = hash_session_insert(correct_id);

	if (new_session == NULL) {
		fprintf(stderr, "Can't add the new session\n");
		return NULL;
	}

	/* Fill the Data */
	new_session->addr = *addr;
	new_session->proto = proto;
	new_session->data_head.udp = NULL; /* same as new_session.tcp */
	new_session->data_tail.udp = NULL;
	new_session->next = NULL;
	new_session->id = correct_id;
	new_session->is_active = YES;
	new_session->next_data_id = 1;

	if (sensor.sessionlist_head == NULL) {
		sensor.sessionlist_head = new_session;
		sensor.sessionlist_tail = new_session;
		new_session->prev = NULL;
	} else {
		sensor.sessionlist_tail->next = new_session;
		new_session->prev = sensor.sessionlist_tail;
		sensor.sessionlist_tail = new_session;
	}
	return new_session ;
}


/*
 * Function: destroy_session(Sensor *, Session *)
 *
 * Purpose: destroy a session by removing it from the hash table (which also
 *          frees the allocated memory for the session) and removing it from
 *          the session list it belongs to. 
 *
 * Arguments: sensor=> Pointer to a sensor struct
 *            session=> Pointer to a session struct 
 *
 * Returns: 0=> An error occured
 *          1=> Session is removed
 *          2=> Session is removed but it's also safe to remove the sensor too
 */
int destroy_session(Session *session)
{
	int ret;

	if (sensor.sessionlist_head != session)
		session->prev->next = session->next;
	else
		sensor.sessionlist_head = session->next;

	if (sensor.sessionlist_tail != session)
		session->next->prev = session->prev;
	else 
		sensor.sessionlist_tail = session->prev;


	ret = hash_session_remove(session->id);
	if(!ret)
		return 0;

	return 1;
}


/*
 * Function: close_session(Sensor *, unsigned int)
 *
 * Purpose: closes a session (turns session's is_active flag to NO)
 *
 * Arguments: id=> stream ID of the session we are about to add
 *
 * Returns: 1=> exit on success, 0=>exit on error
 */
int close_session(unsigned id)
{
	Session *session;

	session = find_session(id);
	if (!session)
		return 0;

	session->is_active = NO;

	if (!session->data_head.tcp) /* session is empty. Remove it */
		destroy_session(session);
	return 1;
}


static TCPData *add_tcpdata(Session *session, void *payload, size_t len)
{
	TCPData *data_struct;

	data_struct = malloc(sizeof(TCPData));
	if (data_struct == NULL) {
		errno_cont("Error in malloc");
		return NULL;
	}

	if (!session->data_head.tcp) {
		session->data_head.tcp = data_struct;
		data_struct->prev = NULL;
	} else {
		session->data_tail.tcp->next = data_struct;
		data_struct->prev = session->data_tail.tcp;
	}

	data_struct->next = NULL;
	data_struct->id = session->next_data_id++;
	data_struct->length = len;
	data_struct->payload = payload;
	session->data_tail.tcp = data_struct;

	return data_struct;
}


static UDPData *add_udpdata(Session *session, void *payload, size_t len)
{
	UDPData *data_struct;

	data_struct = malloc(sizeof(UDPData));
	if (data_struct == NULL) {
		errno_cont("Error in malloc");
		return NULL;
	}

	session->data_head.udp = session->data_tail.udp = data_struct;
	data_struct->payload = payload;
	data_struct->length = len;

	return data_struct;
}


/*
 * Function: add_data(Session *, const void *, int)
 *
 * Purpose: Add new data under a session
 *
 * Arguments: session=> Pointer to a session struct
 *            data=> Pointer to data's payload
 *            length=> Payload's length
 *
 * Returns: Pointer to newly added data on success, NULL on error
 */

#define OOM_WAKEUP_THRESHOLD	10

void *add_data(Session *session, void *payload, size_t len)
{
	static int cnt = 0;
	void * ret;

	if (!session)
		return NULL;

	/* sanity check */
	if (session->is_active == NO)
		return NULL;

	switch (session->proto) {
	case IPPROTO_TCP:
		ret = add_tcpdata(session, payload, len);
		break;

	case IPPROTO_UDP:
		ret = add_udpdata(session, payload, len);
		break;

	default:
		ret = NULL;
	}

	if(ret)
		cnt++;
	if(cnt >= OOM_WAKEUP_THRESHOLD) {
		cnt = 0;
		mutex_lock(&oom_mutex);
		cond_signal(&oom_cond);
		mutex_unlock(&oom_mutex);
	}

	return ret;
}

inline TCPData *get_next_data(const TCPData *data)
{
	if(!data->next)
		return NULL;

	return (data->next->id == (data->id + 1)) ? data->next : NULL;
}

/*
 * Function: destroy_data(Sensor *, unsigned int, unsigned int)
 *
 * Purpose: Deallocates the memory allocated for the data, removes data from the
 *          session's data list, and calls remove_session if it's safe.
 *
 * Arguments: d=> Pointer to the struct containing info 
 *                about the data we want to remove
 *
 * Returns: 0=> An error occured
 *          1=> Data have been removed, maybe session too
 *          2=> Data have been removed, session too and it's safe to remove the
 *              the sensor too.
 */
int destroy_data(DataInfo *d)
{
	TCPData *data;

	DPRINTF("\n");
	/* UDP Data */
	if(d->session->proto == IPPROTO_UDP) {
		free(d->data.udp->payload);
		free(d->data.udp);
		return destroy_session(d->session);
	}


	/* TCP Data */
	data = d->data.tcp;

	/* remove data from the list */
	if(data->prev)
		data->prev->next = data->next;
	else
		d->session->data_head.tcp = data->next;

	if(data->next)
		data->next->prev = data->prev;
	else
		d->session->data_tail.tcp = data->prev;

	/* free data */
	free(data->payload);
	free(data);

	/* destroy session if needed */
	if ((!d->session->data_head.tcp) && (d->session->is_active == NO))
		return destroy_session(d->session);

	return 1;
}


/*
 * Function: destroy_datagroup(DataInfo *)
 *
 * Purpose: Destroy a whole group of data.
 *
 * Arguments: d=> Pointer to the struct containing info about
 *                the heading data of the datagroup we want to remove
 *
 * Returns: 0=> An error occured
 *          1=> Group of data have been removed, maybe session too
 *          2=> Group of data have been removed, session too and it's safe to
 *          remove the the sensor too.
 */
int destroy_datagroup(DataInfo *d)
{
	TCPData *grp_start;
	TCPData *grp_end;
		
	DPRINTF("\n");
	if(!d)
		return 0;

	/* UDP Data */
	if(d->session->proto == IPPROTO_UDP) {
		free(d->session->data_head.udp->payload);
		free(d->session->data_head.udp);
		return destroy_session(d->session);
	}

	/* TCP Data */
	grp_start = d->data.tcp;

	/* find the group end */
	grp_end = d->data.tcp;
	while(grp_end->next) {
		if(grp_end->next->id == (grp_end->id + 1)) {
			grp_end = grp_end->next;
			continue;
		}
		break;
	}

	/* remove group from the list */
	if(grp_start->prev)
		grp_start->prev->next = grp_end->next;
	else
		d->session->data_head.tcp = grp_end->next;

	if(grp_end->next)
		grp_end->next->prev = grp_start->prev;
	else
		d->session->data_tail.tcp = grp_start->prev;


	/* free group data */
	while(grp_start != grp_end) {
		grp_start = grp_start->next;
		free(grp_start->prev->payload);
		free(grp_start->prev);
	}

	free(grp_end->payload);
	free(grp_end);

	/* destroy session if needed */
	if((!d->session->data_head.tcp) && (d->session->is_active == NO))
		return destroy_session(d->session);

	return 1;
}

