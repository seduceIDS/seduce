#ifndef _AGENT_CONTACT_H
#define _AGENT_CONTACT_H

#include <glib.h>
#include <stdlib.h>

typedef struct _AgentsContactData {
	unsigned short port;
	int max_conns;
} AgentsContactData;

void *agents_contact(AgentsContactData *);


typedef struct _AgentInfo {
	u_int32_t id; /* The agent ID	*/

	u_int32_t sec; /* Seq.Num. of the last packet send */

	struct sockaddr_in addr; /* Agent's address info	*/

	int tcp_socket;	 /* Agent's TCP communication socket */

	struct { /* Struct with info about the last data send. This
		  * is usefull only if the data where from TCP
		  * session */
		unsigned int sensor;/* Sensor  ID */
		unsigned int session;/* Session ID */
		unsigned int data;/* Data    ID */
	} history;
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
	unsigned int sec;
	unsigned int type;
	unsigned int id;
	struct sockaddr_in addr;
	char pwd[16];
} UDPPacket;

		/* UDP Communication */
/* receive */
#define UDP_NEW_AGENT 1
#define UDP_NEW_WORK  2
#define UDP_GET_NEXT  3
#define UDP_GET_PREV  4
#define UDP_QUIT      5


/* send */
#define UDP_CONNECTED 1
#define UDP_NOT_CONN  2
#define UDP_DATA      3
#define UDP_NOT_FOUND 4

/*
 * RECV PACKET:
 * ________ ________ ________ ________ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
 *|  size  |  type  |  sec   |   ID   |			PASSWORD	    |
 *|________|________|________|________|_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _|
 *0        4        8        12       16
 *
 * SEND PACKET:
 *  ________ ________ ________ ________
 *|  size  |  type  |  sec   |   ID   |
 *|________|________|________|________|
 *0        4        8        12       16
 *
 * ________ ________ ________ ________ ________ ____ ____ ________ ________ _ _
 *|  size  |  type  |  sec   |   ID   |protocol| sp | dp | s_addr | d_addr |pay
 *|________|________|________|________|________|____|____|________|________|load
 *0        4        8        12       16       20   22   24       28       32
 *
 *|--------------main_msg-------------|----------------addr----------------|
 */

#define UDP_PCK_SIZE 16
#define TCP_PCK_SIZE 20
#define PASSWORD "password"
#define MAX_WAIT 5

#endif /*_AGENT_CONTACT_H */
