#ifndef _AGENT_CONTACT_H
#define _AGENT_CONTACT_H

#include <glib.h>
#include <stdlib.h>

#include "manager.h"
#include "data.h"


typedef struct _AgentInfo {
	u_int32_t id; /* The agent ID	*/

	u_int32_t seq; /* Seq.Num. of the last packet send */

	struct sockaddr_in addr; /* Agent's address info	*/

	DataInfo history; /* Struct with info about the last data sent */

	time_t timestamp;
} AgentInfo;

typedef struct _Agents {
	AgentInfo *table; /* A table of Agent Info structs    */

	u_int8_t *map; /* A bit map of used entries in the table */

	size_t map_size; /* Map's size in bytes */

	int max; /* The max number of agent connections allowed */

	GHashTable *hash; /* Hash table associating Agent ID's with table
			   * entries */
} Agents;

typedef struct _UDPPacket {
	unsigned int size;
	unsigned int seq;
	unsigned int type;
	unsigned int id;
	struct sockaddr_in addr;
	char pwd[MAX_PWD_SIZE];
} UDPPacket;

		/* UDP Communication */
/* receive */
#define UDP_NEW_AGENT	1
#define UDP_NEW_WORK	2
#define UDP_GET_NEXT	3
#define UDP_QUIT	4


/* send */
#define UDP_CONNECTED		1
#define UDP_NOT_CONNECTED	2
#define UDP_DATA		3
#define UDP_NOT_FOUND		4

/*
 * RECV PACKET:
 * ________ ________ ________ ________ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
 *|  size  |  type  |  seq   |   ID   |			PASSWORD	    |
 *|________|________|________|________|_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|
 *0        4        8        12       16
 *
 * SEND PACKET:
 *  ________ ________ ________ ________
 *|  size  |  type  |  seq   |   ID   |
 *|________|________|________|________|
 *0        4        8        12       16
 *
 * ________ ________ ________ ________ ________ ____ ____ ________ ________ _ _
 *|  size  |  type  |  seq   |   ID   |protocol| sp | dp | s_addr | d_addr |pay
 *|________|________|________|________|________|____|____|________|________|load
 *0        4        8        12       16       20   22   24       28       32
 *
 *|--------------main_msg-------------|----------------addr----------------|
 */

#define UDP_PCK_SIZE 16
#define TCP_PCK_SIZE 20
#define MAX_WAIT 5

#endif /*_AGENT_CONTACT_H */
