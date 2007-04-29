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
	char *data;			/* Data Pointer 		*/
	int data_len;			/* Data Lenght 			*/
	int socket;			/* Sensor's Socket		*/
	struct in_addr ip;		/* Sensor's IP Address		*/
	u_int16_t port;			/* Sensor's Port		*/
	Sensor *my_sensor;		/* Pointer to the Sensor struct	*/
} SensorPacket;

static int sensor_connect(SensorPacket *);
static int sensor_disconnect(SensorPacket *);
static int new_tcp(SensorPacket *);
static int tcp_close(SensorPacket *);
static int tcp_data(SensorPacket *);
static int udp_data(SensorPacket *);

/* Protocol Table */
const struct {
	int hdr_len;
	int data; /* TRUE | FALSE */
	int (*handler)(SensorPacket *);
}
proto_tbl[] = {
/*  Type    Header Size		Data		Handler           */
/*----------------------------------------------------------------*/
/*   0   */	8,		NO,		sensor_connect,
/*   1   */	8,		NO,		sensor_disconnect,
/*   2   */	24,		NO,		new_tcp,
/*   3   */	12,		NO,		tcp_close,
/*   4   */	12,		YES,		tcp_data,
/*   5   */	24,		YES,		udp_data,
/*-----------------------------------------------------------------*/
};

#define MAX_TYPE 5
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

		/* Revert the collected data to host byte order */
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
	} /* loop for ever */

err1:
	errno_cont("recvmsg");
err2:
	if(pck.data)
		free(pck.data);
	sensor_disconnect(&pck);

	/* Never Called */
	return NULL;
}


static int sensor_connect(SensorPacket *p)
{
	int reply;
	const unsigned char *connreply[] = {
			"\x0\x0\x0\x8\x0\x0\x0\x0", /* Connected... */
			"\x0\x0\x0\x8\x0\x0\x0\x1", /* Too many connections */
			"\x0\x0\x0\x8\x0\x0\x0\x2", /* Undefined error */
	/*		|----size----|---reply---| */
	};

	DPRINTF("\n");
	mutex_lock(&sensorlist.mutex);

	/* trying to add the sensor */
	reply = add_sensor(p->ip, p->port, &p->my_sensor);

	mutex_unlock(&sensorlist.mutex);

	DPRINTF("Sent for reply: %d\n",reply);

	if (send(p->socket,connreply[reply],8,0) == -1) {
		perror("send");
		return 0;
	}

	return (reply != 0) ? 0 : 1;
}


static int sensor_disconnect(SensorPacket *p)
{
	DPRINTF(("\n"));
	close(p->socket);
	if (p->my_sensor != NULL) {
		mutex_lock(&p->my_sensor->mutex);

		close_sensor(p->my_sensor);

		mutex_unlock(&p->my_sensor->mutex);
	}

	/* terminate the thread */
	pthread_exit(NULL);

	/* Never Called...*/
	return 1;
}

#ifdef _DEBUG
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
#endif

static int new_tcp(SensorPacket *p)
{
	unsigned int id;
	struct tuple4 addr;
	Session * new_session;

	id = ntohl(   *(u_int32_t *)((*p).header + 0));
	addr.s_port = *(u_int16_t *)((*p).header + 4);
	addr.d_port = *(u_int16_t *)((*p).header + 6);
	addr.s_addr = *(u_int32_t *)((*p).header + 8);
	addr.d_addr = *(u_int32_t *)((*p).header + 12);
	DPRINTF("Stream ID %u\n", id);
	DPRINTF("Source: %s:%u\n",int_ntoa(addr.s_addr), ntohs(addr.s_port));
	DPRINTF("Destin: %s:%u\n",int_ntoa(addr.d_addr), ntohs(addr.d_port));
	
	mutex_lock(&p->my_sensor->mutex);

	new_session = add_session(p->my_sensor, id, &addr, TCP);
	
	mutex_unlock(&p->my_sensor->mutex);

	return (new_session)?1:0;
}


static int tcp_close(SensorPacket *p)
{
	int ret;
	unsigned int id; 

	DPRINTF("\n");	
	id = htonl(*((unsigned int *)(*p).header));
	DPRINTF("TCP Connection with stream ID %u has Closed\n", id);
	
	mutex_lock(&p->my_sensor->mutex);

	ret = close_session(p->my_sensor, id);

	mutex_unlock(&p->my_sensor->mutex);

	return ret;
}


static int tcp_data(SensorPacket *p)
{
	Session *this_session;
	TCPData *new_data = NULL;
	unsigned int stream_id;

	DPRINTF("\n");
	stream_id = ntohl(*((unsigned int *)(*p).header));
	DPRINTF("DATA for TCP with stream ID %u\n",stream_id);
	DPRINTF("DATA length is %u\n", p->data_len);
	
	mutex_lock(&p->my_sensor->mutex);

	this_session = find_session(p->my_sensor,stream_id);
	if (this_session != NULL)
		new_data = add_data(p->my_sensor, stream_id, TCP, 
			            p->data, p->data_len);
			
	mutex_unlock(&p->my_sensor->mutex);

	if (new_data != NULL)
		return add_job(p->my_sensor, this_session, new_data);
	else return 0;
}


static int udp_data(SensorPacket *p)
{
	int no_errors = 0;
	struct tuple4 addr;
	unsigned int id;
	Session *new_session = NULL;
	UDPData *new_data = NULL;

	DPRINTF("\n");
	id = ntohl(*((u_int32_t *)(*p).header));
	addr.s_port = *(u_int16_t *) ((*p).header + 4);
	addr.d_port = *(u_int16_t *) ((*p).header + 6);
	addr.s_addr = *(u_int32_t *) ((*p).header + 8);
	addr.d_addr = *(u_int32_t *) ((*p).header + 12);
	DPRINTF("ID %u\n", id);
	DPRINTF("Source: %s:%u\n",int_ntoa(addr.s_addr), ntohs(addr.s_port));
	DPRINTF("Destin: %s:%u\n",int_ntoa(addr.d_addr), ntohs(addr.d_port));
	DPRINTF("Data Length %u\n",p->data_len);

	mutex_lock(&p->my_sensor->mutex);

	/* Open a new session */
	DPRINTF("Adding a new Session...\n");
	new_session = add_session (p->my_sensor, id, &addr, UDP);
	
	/* Add the data */
	if (new_session != NULL) {
		DPRINTF("Session added, adding new Data...\n");
		new_data = add_data (p->my_sensor, id, UDP,
				     p->data, p->data_len);
	}

	/* Close the session */
	if (new_data != NULL) {
		DPRINTF("Data Added, closing the session...\n");
		no_errors = close_session(p->my_sensor, id);
	}

	mutex_unlock(&p->my_sensor->mutex);

	if (no_errors)
		return add_job(p->my_sensor, new_session, new_data);
	else return 0;
}


#if 0
static void size_error(Packet *p)
{
	fprintf(stderr, "Package Size Error\n");
	sensor_disconnect(p);
}

void *serve_the_client(struct client_thread_data *c_data)
{
	enum {  BEGINNING,
		STARTING_HEADER,
		MAIN_HEADER,
		DATA
	} part;

	/* The Starting Header */
	struct {
		unsigned int size;
		unsigned int type;
	} s_hdr;

	
	char buffer[MAXBUFFERSIZE];
	Packet p;
	char *buf_ptr = NULL,*section_end = NULL;
	int bytes_left, bytes_needed = 0;

	part = BEGINNING;

	p.socket = c_data->connfd;
	p.sensor_ip = c_data->sensor_ip;
	p.sensor_port = c_data->sensor_port;
	p.my_sensor = NULL;
	free(c_data);

	while ((bytes_left = recv(p.socket, buffer, MAXBUFFERSIZE, 0)) != -1) {

		if (bytes_left == 0) 
			sensor_disconnect(&p); /* Connection has closed */
		
		DPRINTF("I just received %d bytes\n",bytes_left);
		buf_ptr = buffer;

		again:
		switch(part) {
			case BEGINNING:
				part = STARTING_HEADER;

				bytes_needed = sizeof(s_hdr);
				section_end = ((char *)&s_hdr) + bytes_needed;

			case STARTING_HEADER:
				for(; (bytes_needed > 0) && (bytes_left > 0); bytes_left--)
					*(section_end - bytes_needed--) = *buf_ptr++;
				if(bytes_needed)
					continue;
				part = MAIN_HEADER;

				s_hdr.size = ntohl(s_hdr.size);
				s_hdr.type = ntohl(s_hdr.type);

				/* Size Sanity check */
				if (pt_tbl[s_hdr.type].data) {
					if (s_hdr.size <= pt_tbl[s_hdr.type].header_size)
						size_error(&p);
				} else if (s_hdr.size != pt_tbl[s_hdr.type].header_size)
					size_error(&p);

				bytes_needed = pt_tbl[s_hdr.type].header_size - sizeof(s_hdr);
				section_end = p.header + bytes_needed;

			case MAIN_HEADER:
				for(; (bytes_needed > 0) && (bytes_left > 0); bytes_left--)
					*(section_end - bytes_needed--) = *buf_ptr++;
				if(bytes_needed)
					continue;
				part = DATA;

				if (pt_tbl[s_hdr.type].data) {
					bytes_needed = s_hdr.size - pt_tbl[s_hdr.type].header_size;
					p.data_length = bytes_needed;
					if((p.data = malloc(p.data_length)) == NULL) {
						perror("malloc");
						sensor_disconnect(&p);
					}
					section_end = p.data + bytes_needed;
				}

			case DATA:
				for(; (bytes_needed > 0) && (bytes_left > 0); bytes_left--)
					*(section_end - bytes_needed--) = *buf_ptr++;
				if(bytes_needed)
					continue;
				part = BEGINNING;

				/* We got the Packet, now call the proper function */
				if (pt_tbl[s_hdr.type].function(&p) == 0)
					sensor_disconnect(&p);
		}
		goto again;
	}
	perror("recv");
	sensor_disconnect(&p);

	/* Never Called */
	return NULL;
}
#endif
