#ifndef _MANAGER_H
#define _MANAGER_H

typedef struct _ProgVars {
	char *prog_name;
	int sensor_port;
	int agent_port;
	int max_agents;
	int max_sensors;
	int mem_softlimit;
	int mem_hardlimit;
	char *password;
} PV;

extern PV pv;

#define MAX_PWD_SIZE	16

#endif /* _MANAGER_H */
 
