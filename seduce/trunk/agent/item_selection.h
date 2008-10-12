#ifndef _SENSOR_CHOICE_H
#define _SENSOR_CHOICE_H	1

typedef enum { ROUND_ROBIN, RANDOM } ElectionType;
typedef void *(*ElectionMethod)(int, void *);

/* round robin sensor election */
void *round_robin_election(int num_servers, void *servers);

/* random sensor election */
void *random_election(int num_servers, void *sensors);

#endif
