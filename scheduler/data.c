/*
 * This file contains the functions for accessing the data stored in the
 * scheduler.
 */
#include <strings.h>

#include "data.h"
#include "errors.h"
#include "hash.h"
#include "utils.h"


/* The Sensor List */
SensorList sensorlist;

/*
 * Clears the Sensors Table
 */
void init_sensorlist(void)
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
		
}


Session *find_session(Sensor *this_sensor, unsigned int id)
{
	unsigned int correct_id;

	correct_id = id + this_sensor->id_start;
	return hash_session_lookup(this_sensor->hash, correct_id);
}


/* 
 * This function adds a new session detected by a sensor
 * Returns the new session on success and NULL if an error occurs
 */
Session *add_session(Sensor *this_sensor,
		     unsigned int id,
		     struct tuple4 *addr,
		     IPProtocol proto)
{
	Session *new_session;
	unsigned int correct_id; 
	
	correct_id = id + this_sensor->id_start;
	new_session = hash_session_insert(this_sensor->hash, correct_id);

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

	if (this_sensor->sessionlist_head == NULL) {
		this_sensor->sessionlist_head = this_sensor->sessionlist_tail = new_session;
		new_session->prev = NULL;
	} else {
		this_sensor->sessionlist_tail->next = new_session;
		new_session->prev = this_sensor->sessionlist_tail;
		this_sensor->sessionlist_tail = new_session;
	}
	return new_session ;
}

/* 
 * This function closes a session (turns the is_active flag to NO)
 * but does not deallocate the space.
 */
int close_session(Sensor *this_sensor, unsigned int id)
{
	Session *this_session;

	this_session = find_session(this_sensor, id);
	if (this_session == NULL)
		return 0;

	this_session->is_active = NO;
	return 1;
}

static void close_all_sessions(Sensor *this_sensor)
{
	Session *current_session;

	current_session = this_sensor->sessionlist_head;

	while(current_session) {
		current_session->is_active = NO;

		current_session = current_session->next;
	}
}

/* 
 * Carefull when destroying a session with this function.
 * Don't forget to remove the hash entry too. We do not free
 * the allocated Session space. It's done automatically when
 * removing the hash entry.
 */
static void destroy_session_data(Session *this_session) 
{
	if (this_session->proto == TCP) {
		TCPData *data; 
		TCPData *next_data;

		data = this_session->data_head.tcp;
		while (data != NULL) {
			next_data = data->next;

			free(data->payload);
			free(data);

			data = next_data;
		}

	} else { /* UDP */
		UDPData * data = this_session->data_head.udp;

		if(data) {
			free(data->payload);
			free(data);
		}
	}

}

/*
 * Destroy a sessions, frees the memory of the data
 * by calling destroy_session_data and removes the hash entry
 * returns 1 on sucess, 0 if an error occurs
 */

int destroy_session(Sensor *this_sensor, unsigned int id)
{
	Session *this_session;

	this_session = find_session(this_sensor, id);
	if (this_session == NULL)
		return 0;

	/* fix the broken link in the list */
	if (this_sensor->sessionlist_head != this_session)
		this_session->prev->next = this_session->next;
	else
		this_sensor->sessionlist_head = this_session->next;

	if (this_sensor->sessionlist_tail != this_session)
		this_session->next->prev = this_session->prev;
	else 
		this_sensor->sessionlist_tail = this_session->prev;

	destroy_session_data(this_session);
	return hash_session_remove(this_sensor->hash, id);
}


static TCPData *add_tcpdata(Session *this_session, char *data, int length)
{
	TCPData *data_struct;

	data_struct = malloc(sizeof(TCPData));
	if (data_struct == NULL) {
		errno_cont("Error in malloc");
		return NULL;
	}

	if (this_session->data_head.tcp == NULL) {
		this_session->data_head.tcp = data_struct;
		data_struct->prev = NULL;
	} else {
		this_session->data_tail.tcp->next = data_struct;
		data_struct->prev = this_session->data_tail.tcp;
	}

	data_struct->next = NULL;
	data_struct->id = this_session->next_data_id++;
	data_struct->length = length;
	data_struct->payload = data;
	this_session->data_tail.tcp = data_struct;

	return data_struct;
}

static UDPData *add_udpdata(Session *this_session, char *data, int length)
{
	UDPData *data_struct;

	data_struct = malloc(sizeof(UDPData));
	if (data_struct == NULL) {
		errno_cont("Error in malloc");
		return NULL;
	}

	this_session->data_head.udp = this_session->data_tail.udp = data_struct;
	data_struct->payload = data;
	data_struct->length = length;

	return data_struct;
}

void *add_data(Sensor *this_sensor,
		unsigned int id,
		IPProtocol proto,
		char *data,
		int length)
{
	Session *this_session;

	this_session = find_session(this_sensor, id);
	if (this_session == NULL)
		return NULL;

	/* sanity check */
	if (proto != this_session->proto)
		return NULL;
	if (this_session->is_active == NO)
		return NULL;

	switch (proto) {
		case TCP:
			return add_tcpdata(this_session, data, length);
		case UDP:
			return add_udpdata(this_session, data, length);
	}
	
	return NULL;
}

TCPData * find_data(Session *this_session, const unsigned int id)
{
	TCPData *data;

	if(this_session == NULL)
		return NULL;

	if(this_session->proto == UDP)
		return NULL;

	data = this_session->data_head.tcp;
	while (data != NULL && data->id < id)
		data = data->next;

	if (!data)
		return NULL;

	return (data->id == id)?data:NULL;
}



/*
 *  Adds a new Sensor in the sensor table.
 *  Returns:
 *  0 if everything is OK
 *  1 if MAXSENSORS value is reached
 *  2 if another error occured
 */
int add_sensor (struct in_addr ip,
		u_int16_t port,
		Sensor **sensor_ptr)
{
	Sensor *new_sensor;
	unsigned int id;

	if (sensorlist.cnt >= MAXSENSORS)
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

/*
 * Closes the sensor but does not deallocate the space.
 * We may need the sensor info to alert if we find something
 */ 
void close_sensor(Sensor *this_sensor)
{
	this_sensor->is_connected = NO;
	this_sensor->stop = time(NULL);

	close_all_sessions(this_sensor);
}

/* 
 * Deallocates the memory reserved for the sensor info
 * All sernsor info is lost
 */ 
void destroy_sensor(Sensor *this_sensor)
{
	unsigned int session_id;
	Sensor *prev = NULL;
	Session *this_session = NULL;

	if (sensorlist.head == this_sensor)
		sensorlist.head = this_sensor->next;
	else {
		for(prev = sensorlist.head; prev->next != this_sensor; prev = prev->next)
			;
		prev->next = this_sensor->next;
	}

	if (sensorlist.tail == this_sensor)
		sensorlist.tail = prev;

	sensorlist.cnt--;

	mutex_destroy (&this_sensor->mutex);


	/* If I destroy a sensor, I need to destroy the sessions too */
	this_session = this_sensor->sessionlist_head;
	while (this_session != NULL) {
		session_id = this_session->id;
		destroy_session_data(this_session);
		this_session = this_session->next;
		hash_session_remove(this_sensor->hash, session_id);
	}
	
	destroy_hash_table(this_sensor->hash);
	hash_sensor_remove(sensorlist.hash, this_sensor->id);
}
