#ifndef _MANAGER_H
#define _MANAGER_H

typedef struct _ManagerProgVars {
	char *prog_name;
#ifndef TWO_TIER_ARCH
	int sensor_port;
	int max_sensors;
#endif
	int agent_port;
	int max_agents;
	int mem_softlimit;
	int mem_hardlimit;
	char *password;
} MPV;

extern MPV mpv;

int start_manager(void);

#define MAX_PWD_SIZE	16

#endif /* _MANAGER_H */
 
