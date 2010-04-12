/*
 * Functions for manipulating and accessing the data stored in the manager.
 */

#include <strings.h>
#include <stdio.h>

#include "manager.h"
#include "data.h"
#include "errors.h"
#include "hash.h"
#include "utils.h"
#include "oom_handler.h"

/* The grouplist (not to be viewed outside the file) */
static GroupList grouplist;

#ifdef TWO_TIER_ARCH

Sensor default_sensor;

void init_datalists(void)
{
	/* Initialize the default sensor */

	default_sensor.id_start = get_rand();

	mutex_init (&default_sensor.mutex);

	default_sensor.hash = new_hash_table();
	if (default_sensor.hash == NULL) {
		fprintf(stderr,
			"Couldn't initialize the hash tabe of the sensor\n");
		exit(1);
	}

	/* Initialize the Group list */
	grouplist.head = grouplist.tail = NULL;
	grouplist.cnt = 0;

	mutex_init (&grouplist.mutex);
}

#else /* TREE_TIER_ARCH */

/* The Sensor List */
SensorList sensorlist;

/*
 * Function: init_datalists()
 *
 * Purpose: Initialize the sensorlist and the grouplist struncts
 */
void init_datalists(void)
{
	sensorlist.head = NULL;
	sensorlist.tail = NULL;
	sensorlist.cnt = 0;

	mutex_init (&sensorlist.mutex);

	sensorlist.hash = new_hash_table();
	if (sensorlist.hash == NULL) {
		fprintf(stderr,"Can't create sensorlist hash table\n");
		abort();
	}

	/* Initialize the Group list */
	grouplist.head = grouplist.tail = NULL;
	grouplist.cnt = 0;

	mutex_init (&grouplist.mutex);
}

/*
 * Function: add_sensor(struct in_addr, unsigned short, Sensor **)
 *
 * Purpose: Add a new sensor in the sensors table
 *
 * Arguments:  ip=> IP address of the new sensor
 *             port=> Port number of the new sensor
 *             sensor_ptr=> pointer to the newly added sensor
 *
 * Returns: 0=> Sensor successfully added
 *          1=> Sensor not added because MAXSENSORS value is reached
 *          2=> Sensor not added because of error occurance 
 */
int add_sensor (struct in_addr ip,
		u_int16_t port,
		Sensor **sensor_ptr)
{
	Sensor *new_sensor;
	unsigned int id;

	if (sensorlist.cnt >= mpv.max_sensors)
		return 1;

	/* Create a unique id */
	do {
		id = get_rand();
		if (id == 0)
			continue;
	} while (hash_sensor_lookup(sensorlist.hash, id));

	new_sensor = hash_sensor_insert(sensorlist.hash, id);
	if ( new_sensor == NULL )
		return 2;

	if (sensorlist.cnt)
		sensorlist.tail->next = new_sensor;
	else	sensorlist.head = new_sensor;
	
	sensorlist.tail = new_sensor;
	sensorlist.cnt++;

	new_sensor->id = id;
	new_sensor->next = NULL;
	new_sensor->ip = ip;
	new_sensor->port = port;
	new_sensor->start = time(NULL);
	new_sensor->stop = ((time_t) -1);
	new_sensor->is_connected = YES;
	new_sensor->sessionlist_head = NULL;
	new_sensor->sessionlist_tail = NULL;
	new_sensor->id_start = get_rand();

	mutex_init (&new_sensor->mutex);

	new_sensor->hash = new_hash_table();
	if (new_sensor->hash == NULL)
		return 2;

	*sensor_ptr = new_sensor;

	return 0;
}

static void close_all_sessions(Sensor *);

/*
 * Function: close_sensor(Sensor *)
 *
 * Purpose: Set the "is_connected" flag of a sensor to NO
 *          and then close all sessions added by this sensor
 *
 * Arguments:  sensor=> pointer to a Sensor struct
 *
 * Returns: 1=> Sensor closed
 *          2=> Sensor closed and should be removed because it is empty
 */
int close_sensor(Sensor *sensor)
{
	close_all_sessions(sensor);

	/* 
	 * This is critical I think. We must first close the sessions
	 * and then close the sensor. 
	 */ 
	sensor->is_connected = NO;
	sensor->stop = time(NULL);

	if (!sensor->sessionlist_head) 
		/* Sensor is empty and should be destroyed */
		return 2;

	return 1;
}


/*
 * Function: destroy_sensor(Sensor *)
 *
 * Purpose: Deallocate the memory reserved for a sensor and
 *          remove the sensor from the sersorlist
 *
 * Arguments:  this_sensor=> Pointer to a sensor struct
 *
 * Returns: 1=> Sensor successfully removed
 *          0=> An error occured while removing the sensor
 */
int destroy_sensor(Sensor *this_sensor)
{
	Sensor *prev_sensor = NULL;

	/* I need to check. This may happen in a really rare condition */
	if(this_sensor->is_connected == YES)
		return 0;

	if (sensorlist.head == this_sensor)
		sensorlist.head = this_sensor->next;
	else {
		for(prev_sensor = sensorlist.head;
		    		prev_sensor->next != this_sensor;
						prev_sensor = prev_sensor->next)
			/* empty body */;
		prev_sensor->next = this_sensor->next;
	}

	if (sensorlist.tail == this_sensor)
		sensorlist.tail = prev_sensor;

	sensorlist.cnt--;

	mutex_destroy (&this_sensor->mutex);
		
	destroy_hash_table(this_sensor->hash);
	return	hash_sensor_remove(sensorlist.hash, this_sensor->id);
}

#endif /* THREE_TIER_ARCH */

/*
 * Function: find_session(Sensor *, unsigned int)
 *
 * Purpose: Find a sensor session identified by a stream_id.
 * 	ATTENTION: The stream_id is not the same as the session_id. This
 * 	function is supposed to be used only by the sensor_contact threads. If
 * 	you know the session_id just use hash_session_lookup to find a session.
 *
 * Arguments:  this_sensor=> Pointer to a sensor struct
 *
 * Returns: Pointer to a session on success, NULL on error
 */
Session *find_session(Sensor *sensor, unsigned int stream_id)
{
	unsigned int correct_id;

	correct_id = stream_id + sensor->id_start;
	return hash_session_lookup(sensor->hash, correct_id);
}


/*
 * Function: add_session(Sensor *, unsigned int, struct tuple4 *, int)
 *
 * Purpose: Add a new session to a sensor's sessions list.
 *
 * Arguments: sensor=> Pointer to a sensor struct
 *            stream_id=> stream ID of the session we are about to add
 *            addr=> sessions address info (server's and client's IP and ports)
 *            proto=> IP protocol IPPROTO_TCP for TCP and IPPROTO_UDP for UDP
 *
 * Returns: Pointer to the newly added session on success, NULL on error
 */
Session *add_session(Sensor *sensor, unsigned int stream_id,
		     		const struct tuple4 *addr, int proto)
{
	Session *new_session;
	unsigned int correct_id; 
	
	correct_id = stream_id + sensor->id_start;
	new_session = hash_session_insert(sensor->hash, correct_id);

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

	if (sensor->sessionlist_head == NULL) {
		sensor->sessionlist_head = new_session;
		sensor->sessionlist_tail = new_session;
		new_session->prev = NULL;
	} else {
		sensor->sessionlist_tail->next = new_session;
		new_session->prev = sensor->sessionlist_tail;
		sensor->sessionlist_tail = new_session;
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
int destroy_session(Sensor *sensor, Session *session)
{
	int ret;

	if (sensor->sessionlist_head != session)
		session->prev->next = session->next;
	else
		sensor->sessionlist_head = session->next;

	if (sensor->sessionlist_tail != session)
		session->next->prev = session->prev;
	else 
		sensor->sessionlist_tail = session->prev;


	ret = hash_session_remove(sensor->hash, session->id);
	if(!ret)
		return 0;
#ifndef TWO_TIER_ARCH
	/* Do we need to remove the sensor too? */
	if((!sensor->sessionlist_head) && (sensor->is_connected == NO))
		return 2;
#endif
	return 1;
}


/*
 * Function: close_session(Sensor *, unsigned int)
 *
 * Purpose: closes a session (turns sessions is_active flag to NO)
 *
 * Arguments: sensor=> Pointer to a sensor struct
 *            stream_id=> stream ID of the session we are about to add
 *
 * Returns: 1=> exit on success, 0=>exit on error
 */
int close_session(Sensor *sensor, unsigned int stream_id)
{
	Session *session;

	session = find_session(sensor, stream_id);
	if (!session)
		return 0;

	session->is_active = NO;

	if (!session->data_head.tcp) /* session is empty. Remove it */
		destroy_session(sensor, session);
	return 1;
}


/*
 * closes all sessions of a sensor
 */
static void close_all_sessions(Sensor *sensor)
{
	Session *this_session;
	Session *next_session;

	this_session = sensor->sessionlist_head;

	while(this_session) {
		this_session->is_active = NO;
		next_session = this_session->next;
		if (!this_session->data_head.tcp) /* session is empty*/
				destroy_session(sensor, this_session);
		this_session = next_session;
	}
}


static TCPData *add_tcpdata(Session *session, void *data, size_t length)
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
	data_struct->length = length;
	data_struct->payload = data;
	session->data_tail.tcp = data_struct;

	return data_struct;
}


static UDPData *add_udpdata(Session *session, void *data, size_t length)
{
	UDPData *data_struct;

	data_struct = malloc(sizeof(UDPData));
	if (data_struct == NULL) {
		errno_cont("Error in malloc");
		return NULL;
	}

	session->data_head.udp = session->data_tail.udp = data_struct;
	data_struct->payload = data;
	data_struct->length = length;

	return data_struct;
}


/*
 * Function: add_data(Session *, void *, size_t)
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

void *add_data(Session *session, void *data, size_t length)
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
		ret = add_tcpdata(session, data, length);
		break;

	case IPPROTO_UDP:
		ret = add_udpdata(session, data, length);
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

int consume_group(int (*func)(), void *params)
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

	/* Executing the Group */
	mutex_lock(&group_to_remove->grouphead.sensor->mutex);

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

	mutex_unlock(&group_to_remove->grouphead.sensor->mutex);

	free(group_to_remove);
	return ret;
}

/*
 * Function: add_group(Sensor *, Session *, void *)
 *
 * Purpose: Add a new group to the grouplist
 *
 * Arguments: this_sensor=> The sensor that sended the data.
 *            this_session=> The session the data belong to.
 *            data=> TCP or UDP data.
 *            ATTENTION: the void pointer should be TCPData* or UDPDATA* and
 *                       nothing else...
 *
 * Returns: 0=> An error occured
 *          1=> Data have been successfully added
 */
int add_group(Sensor *this_sensor, Session *this_session, void *data)
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

	group_to_add->grouphead.sensor = this_sensor;

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
		return destroy_session(d->sensor, d->session);
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
		return destroy_session(d->sensor, d->session);

	return 1;
}


/*
 * Function: destroy_datagroup(Sensor *, unsigned int, unsigned int)
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
		return destroy_session(d->sensor, d->session);
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
		return destroy_session(d->sensor, d->session);

	return 1;
}
