#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "sensor_contact.h"
#include "errors.h"
#include "data.h"
#include "utils.h"
#include "thread.h"

int new_tcp(unsigned id, const struct tuple4 *addr)
{
	Session * new_session;

	DPRINTF("Stream ID %u\n", id);
	DPRINT_TUPLE4(addr);
	
	mutex_lock(&sensor.mutex);

	new_session = add_session(id, addr, IPPROTO_TCP);
	
	mutex_unlock(&sensor.mutex);

	return (new_session)?1:0;
}


int close_tcp(unsigned id)
{
	int ret;

	DPRINTF("\n");
	DPRINTF("TCP Connection with stream ID %u has Closed\n", id);
	
	mutex_lock(&sensor.mutex);

	ret = close_session(id);

	mutex_unlock(&sensor.mutex);

	return ret;
}


int tcp_data(unsigned id, const void *payload, size_t len)
{
	Session *this_session;
	TCPData *new_data = NULL;
	void *payload_copy;
	unsigned int new_id, last_id;
	int add_new_group; /* Do we add the new data in the grouplist? */

	DPRINTF("\n");
	DPRINTF("DATA for TCP with stream ID %u\n", id);
	DPRINTF("DATA length is %u\n", len);

	//We need a copy of the payload to save it in the storage engine...
	payload_copy = malloc(len);
	if(payload_copy == NULL) {
		errno_cont("Error in malloc\n");
		return 0;
	}
	memcpy(payload_copy, payload, len);

	// Now add the data...
	mutex_lock(&sensor.mutex);

	this_session = find_session(id);
	if (this_session)
		new_data = add_data(this_session, payload_copy, len);
	
	if(new_data == NULL) {
		mutex_unlock(&sensor.mutex);
		return 0;
	}

	/* If the new data have an ID that is equal to previous data ID + 1
	 * we don't add them in the grouplist.*/

	new_id  = new_data->id;
	last_id = (new_data->prev) ? new_data->prev->id : 0;
	
	mutex_unlock(&sensor.mutex);

	add_new_group = (last_id) && (new_id == last_id + 1) ? 0 : 1;
	if(add_new_group)
		return add_group(this_session, new_data);

	return 1;
}

int tcp_break(unsigned id)
{
	Session *this_session;

	DPRINTF("\n");	
	DPRINTF("Stream ID: %u\n", id);

	this_session = find_session(id);
	if (!this_session)
		return 0;

	mutex_lock(&sensor.mutex);

	/* 
	 * Increase data id counter. This way we can assure 
	 * that the next data will not be continuous with the last.
	 */
	this_session->next_data_id++;

	mutex_unlock(&sensor.mutex);

	return 1;
}


int udp_data(const struct tuple4 *addr, const void *payload, size_t len,
								unsigned id)
{
	int no_errors = 0;
	
	Session *new_session = NULL;
	UDPData *new_data = NULL;
	void *payload_copy;

	DPRINTF("\n");
	DPRINTF("ID %u\n", id);
	DPRINT_TUPLE4(addr);
	DPRINTF("Data Length %u\n", len);

	//We need a copy of the payload to save it in the storage engine...
	payload_copy = malloc(len);
	if(payload_copy == NULL) {
		perror("malloc");
		return 0;
	}
	memcpy(payload_copy, payload, len);


	// Now do the job....
	mutex_lock(&sensor.mutex);

	/* Open a new session */
	DPRINTF("Adding a new Session...\n");
	new_session = add_session (id, addr, IPPROTO_UDP);
	
	/* Add the data */
	if (new_session) {
		DPRINTF("Session added, adding new Data...\n");
		new_data = add_data (new_session, payload_copy, len);
	}

	/* Close the session */
	if (new_data != NULL) {
		DPRINTF("Data Added, closing the session...\n");
		no_errors = close_session(id);
	}

	mutex_unlock(&sensor.mutex);

	if (no_errors)
		return add_group(new_session, new_data);
	else
		return 0;
}

