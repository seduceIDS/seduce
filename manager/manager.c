#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "manager.h"
#include "options.h"
#include "thread.h"
#include "sensor_contact.h"
#include "errors.h"
#include "utils.h"
#include "data.h"
#include "alert.h"
#include "oom_handler.h"
#include "alert_recv.h"

extern void *agents_contact();

/* Globals */

MPV mpv;

static void start_oom_handler(void)
{
	create_thread(oom_handler, NULL);
}

static void start_alert_thread(void)
{
	create_thread(alert_thread, NULL);
}

static void start_agents_thread(void)
{
	create_thread (agents_contact, NULL);
}

#ifdef TWO_TIER_ARCH
int start_manager(void)
{
	/* Initialization functions */
	init_datalists();
	init_alertlist();
	init_oom_handler();
	init_alert_receiver();

	/* thread starting functions */
	start_alert_thread();
	start_agents_thread();
	start_oom_handler();

	return 0;
}

#else /* THREE_TIER_ARCH */

static void start_sensor_thread(int socket, struct in_addr ip, 
						unsigned short port)
{
	SensorData *data;

	data = malloc(sizeof(SensorData));
	if(!data)
		errno_abort("malloc");

	DPRINTF(("Got a new connection\n"));

	data->connfd = socket;
	data->sensor_ip = ip;
	data->sensor_port = port;

	create_thread ((void *)sensor_contact, data);
}


int start_manager(void)
{
	int sockfd, one;
	int connfd;
	struct sockaddr_in my_addr;
	struct sockaddr_in their_addr;
	socklen_t addr_len;


	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
		errno_abort("socket");

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(mpv.sensor_port);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	memset( &(my_addr.sin_zero), '\0', 8);

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, 
							 sizeof(one)) == -1)
		errno_abort("setsockopt");

	if(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
		errno_abort("bind");

	if (listen(sockfd, 10) == -1)
		errno_abort("listen");

	/* Initialization functions */
	init_datalists();
	init_alertlist();
	init_oom_handler();
	init_alert_receiver();

	/* thread starting functions */
	start_alert_thread();
	start_agents_thread();
	start_oom_handler();

	/* Wait for new sensor connections */
	while (1) {
		addr_len = sizeof(their_addr);
		connfd = accept(sockfd, (struct sockaddr *)&their_addr, 
								&addr_len);
		if (connfd == -1) {
			if (errno == EINTR)
				continue;

			errno_abort("accept");
		}

		start_sensor_thread(connfd, their_addr.sin_addr,
							their_addr.sin_port);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	fill_manager_progvars(argc, argv);

	return start_manager();
}
#endif
