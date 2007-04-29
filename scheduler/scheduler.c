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

#include "thread.h"
#include "agent_contact.h"
#include "sensor_contact.h"
#include "errors.h"
#include "utils.h"
#include "data.h"
#include "job.h"
#include "alert.h"


void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

/* Returns the port on success, 0 on error */
static int get_args(int argc, char *argv[], unsigned short *s_port, unsigned short *a_port)
{
	int c;
	int s_arg = 0, a_arg = 0;
	int port = -1;

	while ((c = getopt (argc, argv, "hs:a:")) != -1) {
		switch (c) {
			case 'h':
				return 0;

			case 's':
				if (s_arg) {
					fprintf(stderr,
						"The -s option should be specified only once\n");
					return 0;
				}
				s_arg = 1;

				port = atoi(optarg);
				if ((port < 1) || (port > 65335)) {
					fprintf(stderr, "Invalid port number.\n");
					return 0;
				}
				*s_port = (unsigned short) port;

				break;

			case 'a':
				if (a_arg) {
					fprintf(stderr,
						"The -a option should be specified only once\n");
					return 0;
				}
				a_arg = 1;

				port = atoi(optarg);
				if ((port < 1) || (port > 65335)) {
					fprintf(stderr, "Invalid port number.\n");
					return 0;
				}
				*a_port = (unsigned short) port;

				break;

			default :
				return 0;
		}
	}
	if (!s_arg || !a_arg) {
		fprintf(stderr, "At -s and -a must be specified.\n");
		return 0;
	}

	return 1;
}

static void printusage(int rc)
{
	fprintf(stderr, "usage: scheduler [-h] -s<port> -a<port>\n\n"
			"  h: Print this message.\n"
			"  s: Specify the port to listen for sensor connections.\n"
			"  a: Specify the port to listen for agent connections.\n\n");
	exit(rc);
}

static void start_alert_thread(void)
{
	create_thread (alert_thread, NULL);
}

#define MAX_AGENT_CONNS	256
static void start_agents_thread(unsigned short port)
{
	AgentsContactData  *data;

	data = malloc(sizeof(AgentsContactData));
	if(!data)
		errno_abort("malloc");

	data->port = port;
	data->max_conns = MAX_AGENT_CONNS;

	create_thread ((void *)agents_contact, data);
}

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


int main(int argc, char *argv[])
{
	int sockfd, connfd;
	struct sockaddr_in my_addr;
	struct sockaddr_in their_addr;
	socklen_t addr_len;
	struct sigaction sa;
	int yes = 1;
	unsigned short s_port, a_port;

	if (!get_args(argc, argv, &s_port, &a_port))
		printusage(1);

	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
		errno_abort("socket");

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) ==-1)
		errno_abort("setsockopt");

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(s_port);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	memset( &(my_addr.sin_zero), '\0', 8);

	if(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1)
		errno_abort("bind");

	if (listen(sockfd, 10) == -1)
		errno_abort("listen");

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		errno_abort("sigaction");

	/* Initialization functions */
	init_sensorlist();
	init_joblist();
	init_alertlist();
	start_alert_thread();
	start_agents_thread(a_port);

	while (1) {
		addr_len = sizeof(their_addr);
		connfd = accept(sockfd, (struct sockaddr *)&their_addr, 
								&addr_len);
		if (connfd == -1) {
			if (errno == EINTR)
				continue;

			errno_abort("accept");
		}

		start_sensor_thread (connfd, their_addr.sin_addr,
							their_addr.sin_port);
	}
	return 0;
}
