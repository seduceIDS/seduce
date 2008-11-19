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
#include "thread.h"


/* The Sensor */
Sensor sensor;

/* The grouplist (not to be viewed outside the file) */
static GroupList grouplist;

#define MEASURED_TIMES	1000
struct timeval measured_times[MEASURED_TIMES];

/*
 * Function: init_datalists()
 *
 * Purpose: Initialize the sensor struct
 */
void init_datalists(void)
{
	int i;
	for (i = 0; i < MEASURED_TIMES; i++)
		timerclear(&measured_times[i]);

	/* Initialize the Sensor struct */
	sensor.sessionlist_head = NULL;
	sensor.sessionlist_tail = NULL;

	mutex_init (&sensor.mutex);

	sensor.hash = new_hash_table();
	if (sensor.hash == NULL) {
		fprintf(stderr,"Can't create sensor hash table\n");
		abort();
	}

	/* clear_sensor_stats */
	memset(&sensor.in, '\0', sizeof(StatUnit));
	memset(&sensor.out, '\0', sizeof(StatUnit));
	memset(&sensor.oom_lost, '\0', sizeof(StatUnit));
	memset(&sensor.proto_lost, '\0', sizeof(StatUnit));

	/* Initialize the Group list */
	grouplist.head = grouplist.tail = NULL;
	grouplist.cnt = 0;

	mutex_init (&grouplist.mutex);
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
	unsigned correct_id;

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
	unsigned correct_id; 
	
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

	/* Before returning update the statistics....*/
	sensor.in.pcks += 1;
	sensor.in.bytes += len;

	return ret;
}


/*
 * Function: add_(int (*)(), void *)
 *
 * Purpose: Removes the oldest group of the list and exetute the function passed
 *          as argument on the heading data of the group just removed.
 *
 * Arguments: func=> Pointer to a function which will be aplied on the data.  
 *            params=> Optional parameter for the function func points to.
 *
 * Returns: Whatever the function returns or -1 if an error occures before the
 *          function is applied.
 */

#define SAMPLE_NUM	100

static void new_sample(const struct timeval *start)
{
	static int i = 0;
	static int cnt = 0;

	struct timeval end;

	if (gettimeofday(&end, NULL) != 0)
		errno_abort("Error in gettimeofday\n");

	timersub(&end, start, &end);
	timeradd(&measured_times[i], &end, &measured_times[i]);

	if(++cnt == SAMPLE_NUM) {
		cnt = 0;
		i++;
	}
}


/*
 * Function: consume_group(int (*)(), void *)
 *
 * Purpose: Removes the oldest group of the list and exetute the function passed
 *          as argument on the heading data of the group just removed.
 *
 * Arguments: func=> Pointer to a function which will be aplied on the data.  
 *            params=> Optional parameter for the function func points to.
 *
 * Returns: Whatever the function returns or -1 if an error occures before the
 *          function is applied.
 */

int consume_group(int (*func)(), void *params, int add_sample)
{
	int ret;
	Group *group_to_remove;

	DPRINTF("\n");
	mutex_lock (&grouplist.mutex);

	while (grouplist.cnt == 0) {
		DPRINTF("No Groups available...\n");
		mutex_unlock (&grouplist.mutex);
		return -1;
	}

	/* Remove the Group from the list...*/
	DPRINTF("Removing the group...\n");
	group_to_remove = grouplist.head;
	grouplist.head = grouplist.head->next;

	grouplist.cnt--;
	if (grouplist.cnt == 0)
		grouplist.tail = NULL;
	else
		grouplist.head->prev = NULL;
	
	mutex_unlock (&grouplist.mutex);

	if (add_sample)
		new_sample(&group_to_remove->start);

	/* Executing the Group */
	mutex_lock(&sensor.mutex);

	DPRINTF("Execute the Group...\n");
	DPRINTF("Session ID: %u\n",group_to_remove->grouphead.session->id);

	/* Those data are the heading data of a group */
	group_to_remove->grouphead.is_grouphead = 1;

	/* Execute the function on this group */
	if (params)
		ret = (*func) (params, &group_to_remove->grouphead);
	else
		ret = (*func) (&group_to_remove->grouphead);
	
	DPRINTF("Group executed\n");

	mutex_unlock(&sensor.mutex);

	free(group_to_remove);
	return ret;
}

/*
 * Function: add_group(Session *, void *)
 *
 * Purpose: Add a new group to the grouplist
 *
 * Arguments: this_session=> The session the data belong to.
 *            data=> TCP or UDP data.
 *            ATTENTION: the void pointer should be TCPData* or UDPDATA* and
 *                       nothing else...
 *
 * Returns: 0=> An error occured
 *          1=> Data have been successfully added
 */
int add_group(Session *this_session, void *data)
{
	Group *group_to_add;

	DPRINTF("\n");
	group_to_add = malloc(sizeof(Group));
	if (group_to_add == NULL) {
		errno_cont("Error in malloc\n");
		return 0;
	}

	group_to_add->grouphead.session = this_session;

	if (this_session->proto == IPPROTO_TCP)
		group_to_add->grouphead.data.tcp = data;
	else
		group_to_add->grouphead.data.udp = data;


	/*
	 * If I put the timestamp after the mutex_lock it will be more
	 * accurate, but I don't want to enter kernel mode with locked mutexes.
	 */
	if (gettimeofday(&group_to_add->start, NULL) != 0)
		errno_abort("Error in gettimeofday\n");


	DPRINTF("Adding Group for Session: %u\n",this_session->id);
	/* Now put it in the group list...*/
	mutex_lock (&grouplist.mutex);

	group_to_add->prev = grouplist.tail;
	group_to_add->next = NULL;

	if (grouplist.tail != NULL) {
		grouplist.tail->next = group_to_add;
		grouplist.tail = group_to_add;
	} else
		grouplist.head = grouplist.tail = group_to_add;

	grouplist.cnt++;

	mutex_unlock (&grouplist.mutex);

	DPRINTF("Finished Adding....\n");

	return 1;
}

inline TCPData *get_next_data(const TCPData *data)
{
	if(!data->next)
		return NULL;

	return (data->next->id == (data->id + 1)) ? data->next : NULL;
}

/*
 * Function: destroy_data(DataInfo *)
 *
 * Purpose: Deallocates the memory allocated for the data, removes data from the
 *          session's data list, and calls remove_session if it's safe.
 *
 * Arguments: d=> Pointer to the struct containing info 
 *                about the data we want to remove
 *
 * Returns: 0=> An error occured
 *          1=> Data have been removed, maybe session too
 */
int destroy_data(StatUnit *log, DataInfo *d)
{
	TCPData *data;

	DPRINTF("\n");

	log->pcks += 1;

	/* UDP Data */
	if(d->session->proto == IPPROTO_UDP) {
		
		log->bytes += d->data.udp->length;

		free(d->data.udp->payload);
		free(d->data.udp);
		return destroy_session(d->session);
	}

	log->bytes += d->data.tcp->length;


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
 * Arguments:	log
 * 		d=> Pointer to the struct containing info about
 *                the heading data of the datagroup we want to remove
 *
 * Returns: 0=> An error occured
 *          1=> Group of data have been removed, maybe session too
 *          2=> Group of data have been removed, session too and it's safe to
 *          remove the the sensor too.
 */
int destroy_datagroup(StatUnit *log, DataInfo *d)
{
	TCPData *grp_start;
	TCPData *grp_end;
		
	DPRINTF("\n");
	if(!d)
		return 0;

	/* UDP Data */
	if(d->session->proto == IPPROTO_UDP) {
		/* log for statistical purposes */
		log->pcks += 1;
		log->bytes += d->session->data_head.udp->length;

		/* destroy data */
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

		/* log for statistical purposes */
		log->pcks += 1;
		log->bytes += grp_start->prev->length;

		/* destroy data */
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

