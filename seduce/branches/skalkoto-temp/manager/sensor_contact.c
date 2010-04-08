#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "sensor_contact.h"
#include "errors.h"
#include "job.h"
#include "data.h"
#include "utils.h"

extern SensorList sensorlist;


#define STARTING_HDR_SIZE  8
#define MAX_MAIN_HDR_SIZE 16

typedef struct {
	char header[MAX_MAIN_HDR_SIZE]; /* Main Header Buffer		*/
	unsigned char *data;		/* Data Pointer 		*/
	int data_len;			/* Data Lenght 			*/
	int socket;			/* Sensor's Socket		*/
	struct in_addr ip;		/* Sensor's IP Address		*/
	unsigned short port;		/* Sensor's Port		*/
	Sensor *my_sensor;		/* Pointer to the Sensor struct	*/
} SensorPacket;

static int pck_sensor_connect(SensorPacket *);
static int pck_sensor_disconnect(SensorPacket *);
static int pck_new_tcp(SensorPacket *);
static int pck_close_tcp(SensorPacket *);
static int pck_tcp_data(SensorPacket *);
static int pck_tcp_break(SensorPacket *);
static int pck_udp_data(SensorPacket *);

/* Protocol Table */
const struct {
	int hdr_len;
	int data; /* TRUE | FALSE */
	int (*handler)(SensorPacket *);
}
proto_tbl[] = {
/*  Type    Header Size		Data		Handler           */
/*----------------------------------------------------------------*/
{/*   0   */	8,		NO,		pck_sensor_connect},
{/*   1   */	8,		NO,		pck_sensor_disconnect},
{/*   2   */	24,		NO,		pck_new_tcp},
{/*   3   */	12,		NO,		pck_close_tcp},
{/*   4   */	12,		YES,		pck_tcp_data},
{/*   5   */	12,		NO,		pck_tcp_break},
{/*   6   */	24,		YES,		pck_udp_data}
/*-----------------------------------------------------------------*/
};
#define MAX_TYPE 6

/* 
 * Sensor Packet:
 *
 * |-STARTING_HEADER-|
 * 0_________________8_________________________
 * |  size  | packet | MAIN_HEADER |    DATA   |
 * |________|__type__|_____________|___________|
 *
 */

void *sensor_contact(SensorData *sensor_data)
{
	unsigned int size, type;
	SensorPacket pck;
	int header_len;
	ssize_t numbytes;
	struct msghdr msg;
	struct iovec iov[2];

	pck.socket = sensor_data->connfd;
	pck.ip = sensor_data->sensor_ip;
	pck.port = sensor_data->sensor_port;
	pck.my_sensor = NULL;
	free(sensor_data);

	msg.msg_iov = iov;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	for(;;) {
	/* 
	 * First get the starting header to find out 
	 * the size and type of the packet
	 */
		pck.data = NULL;
		pck.data_len =0;

		iov[0].iov_base = &size;
		iov[0].iov_len = sizeof(u_int32_t);
		iov[1].iov_base = &type;
		iov[1].iov_len = sizeof(u_int32_t);
		msg.msg_iovlen = 2;	
		msg.msg_flags = 0;

		/* MSG_WAITALL: Block until we have all the needed data */
		numbytes = recvmsg(pck.socket, &msg, MSG_WAITALL);
		if(numbytes == -1)
			goto err1;
		else if (numbytes == 0) {
			DPRINTF("Connection has closed\n");
			goto err2;
		}
		else if (numbytes != STARTING_HDR_SIZE)
			goto err2;

		size = ntohl(size);
		type = ntohl(type);

		if(type > MAX_TYPE) /* Do we have a sane type? */
			goto err2;

	/* 
	 * We have the size and type of the packet. Find out
	 * the main header and data size and receive them.
	 */
		/* MAIN_HEADER_SIZE = HEADER_SIZE - STARTING_HEADER_SIZE */
		header_len = proto_tbl[type].hdr_len - STARTING_HDR_SIZE;

		/* DATA_SIZE = PACKET_SIZE - HEADER_SIZE */
		pck.data_len = size - proto_tbl[type].hdr_len;

		/* size sanity check */
		if((( proto_tbl[type].data) && (pck.data_len <= 0 )) ||
		   ((!proto_tbl[type].data) && (pck.data_len != 0 ))) {
			DPRINTF("Package Size Error");
			goto err2;
		}

		msg.msg_iovlen = 0;

		if(header_len) {
			iov[0].iov_base = pck.header;
			iov[0].iov_len = header_len;
			msg.msg_iovlen = 1;
		}

		if(pck.data_len) {
			pck.data = malloc(pck.data_len);
			if(pck.data == NULL) {
				errno_cont("malloc");
				goto err2;
			}
			iov[1].iov_base = pck.data;
			iov[1].iov_len = pck.data_len;
			msg.msg_iovlen = 2;
		}

		msg.msg_flags = 0;

		if(msg.msg_iovlen) {
			numbytes = recvmsg(pck.socket, &msg, MSG_WAITALL);
			if(numbytes == -1)
				goto err1;

			else if (numbytes == 0) {
				DPRINTF("Connection has closed\n");
				goto err2;
			} else if (numbytes != header_len + pck.data_len)
				goto err2;
		}

		/* We got the Packet, now call the proper handler */
		if (proto_tbl[type].handler(&pck) == 0)
			goto err2;	
	}

err1:
	errno_cont("recvmsg");
err2:
	if(pck.data)
		free(pck.data);
	pck_sensor_disconnect(&pck);

	/* Never Called */
	return NULL;
}


static int pck_sensor_connect(SensorPacket *p)
{
	int reply;
	const char *connreply[] = {
			"\x0\x0\x0\x8\x0\x0\x0\x0", /* Connected... */
			"\x0\x0\x0\x8\x0\x0\x0\x1", /* Too many connections */
			"\x0\x0\x0\x8\x0\x0\x0\x2", /* Undefined error */
	/*		|----size----|---reply---| */
	};

	DPRINTF("\n");

	/* trying to add the sensor */
	mutex_lock(&sensorlist.mutex);

	reply = add_sensor(p->ip, p->port, &p->my_sensor);

	mutex_unlock(&sensorlist.mutex);

	DPRINTF("Sent for reply: %d\n",reply);

	if (send(p->socket,connreply[reply],8,0) == -1) {
		perror("send");
		return 0;
	}

	return (reply != 0) ? 0 : 1;
}


static int pck_sensor_disconnect(SensorPacket *p)
{
	int ret = 0;

	DPRINTF(("\n"));
	close(p->socket);
	if (p->my_sensor != NULL) {
		mutex_lock(&p->my_sensor->mutex);
		
		ret = close_sensor(p->my_sensor);

		mutex_unlock(&p->my_sensor->mutex);
	}

	if (ret == 2) {/* sensor should be destroyed */
		mutex_lock(&sensorlist.mutex);

		destroy_sensor(p->my_sensor);

		mutex_unlock(&sensorlist.mutex);
	}


	/* terminate the thread */
	pthread_exit(NULL);

	/* Never Called...*/
	return 1;
}

int new_tcp(Sensor *s, unsigned id, const struct tuple4 *addr)
{
	Session *new_session;

	DPRINTF("Stream ID %u\n", id);
	DPRINT_TUPLE4(addr);
	
	mutex_lock(&s->mutex);

	new_session = add_session(s, id, addr, IPPROTO_TCP);
	
	mutex_unlock(&s->mutex);

	return (new_session)?1:0;

}

static int pck_new_tcp(SensorPacket *p)
{
	unsigned int id;
	struct tuple4 addr;

	id = ntohl(   *(u_int32_t *)((*p).header + 0));
	addr.s_port = *(u_int16_t *)((*p).header + 4);
	addr.d_port = *(u_int16_t *)((*p).header + 6);
	addr.s_addr = *(u_int32_t *)((*p).header + 8);
	addr.d_addr = *(u_int32_t *)((*p).header + 12);


	return new_tcp(p->my_sensor, id, &addr);
}


int close_tcp(Sensor *s, unsigned id)
{
	int ret;

	DPRINTF("\n");	
	DPRINTF("TCP Connection with stream ID %u has Closed\n", id);
	
	mutex_lock(&s->mutex);

	ret = close_session(s, id);

	mutex_unlock(&s->mutex);

	return ret;
}

static int pck_close_tcp(SensorPacket *p)
{
	unsigned id = htonl(*((u_int32_t *)(*p).header));
	
	return close_tcp(p->my_sensor, id);
}


int tcp_data(Sensor *s, unsigned id, void *payload, size_t len)
{
	Session *this_session;
	TCPData *new_data = NULL;
	unsigned int new_id, last_id;
	int add_in_joblist; /* Do we add the new data in the joblist? */

	DPRINTF("\n");
	DPRINTF("DATA for TCP with stream ID %u\n", id);
	DPRINTF("DATA length is %u\n", len);
	
	mutex_lock(&s->mutex);

	this_session = find_session(s, id);
	if (this_session)
		new_data = add_data(this_session, payload, len);
	
	if(new_data == NULL) {
		mutex_unlock(&s->mutex);
		return 0;
	}

	/* If the new data have an ID that is equal to previous data ID + 1
	 * we don't add them in the joblist.*/

	new_id  = new_data->id;
	last_id = (new_data->prev) ? new_data->prev->id : 0;

	mutex_unlock(&s->mutex);

	add_in_joblist = (last_id) && (new_id == last_id + 1) ? 0 : 1;
	
	if(add_in_joblist)
		return add_job(s, this_session, new_data);

	return 1;
}

static int pck_tcp_data(SensorPacket *p)
{
	unsigned stream_id = ntohl(*((u_int32_t *)(*p).header));
	
	return tcp_data(p->my_sensor, stream_id, p->data, p->data_len);
}

int tcp_break(Sensor *s, unsigned id)
{
	Session *this_session;

	DPRINTF("\n");	
	DPRINTF("TCP Connection with Stream ID %u had a break\n", id);

	this_session = find_session(s, id);
	if (!this_session)
		return 0;

	mutex_lock(&s->mutex);

	/* 
	 * Increase data id counter. This way we can assure 
	 * that the next data will not be continuous with the last.
	 */
	this_session->next_data_id++;

	mutex_unlock(&s->mutex);

	return 1;
}

static int pck_tcp_break(SensorPacket *p)
{
	unsigned int stream_id;


	stream_id = htonl(*((u_int32_t *)(*p).header));

	return tcp_break(p->my_sensor, stream_id);
}

int udp_data(Sensor *s, const struct tuple4 *addr, void *payload, 
		size_t len, unsigned id)
{
	int no_errors = 0;
	Session *new_session = NULL;
	UDPData *new_data = NULL;

	DPRINTF("\n");
	DPRINTF("ID %u\n", id);
	DPRINT_TUPLE4(addr);
	DPRINTF("Data Length %u\n",len);

	mutex_lock(&s->mutex);

	/* Open a new session */
	DPRINTF("Adding a new Session...\n");
	new_session = add_session(s, id, addr, IPPROTO_UDP);
	
	/* Add the data */
	if (new_session) {
		DPRINTF("Session added, adding new Data...\n");
		new_data = add_data (new_session, payload, len);
	}

	/* Close the session */
	if (new_data != NULL) {
		DPRINTF("Data Added, closing the session...\n");
		no_errors = close_session(s, id);
	}

	mutex_unlock(&s->mutex);

	if (no_errors)
		return add_job(s, new_session, new_data);
	else
		return 0;
}

static int pck_udp_data(SensorPacket *p)
{
	struct tuple4 addr;
	unsigned int id;

	DPRINTF("\n");
	id = ntohl(*((u_int32_t *)(*p).header));
	addr.s_port = *(u_int16_t *) ((*p).header + 4);
	addr.d_port = *(u_int16_t *) ((*p).header + 6);
	addr.s_addr = *(u_int32_t *) ((*p).header + 8);
	addr.d_addr = *(u_int32_t *) ((*p).header + 12);

	return udp_data(p->my_sensor, &addr, p->data, p->data_len, id);	
}

