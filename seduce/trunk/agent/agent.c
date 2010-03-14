#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "options.h"
#include "worker.h"

int max_workers;
int running_workers;
pid_t *worker_pids;

/* expecting worker's union problems on this one... */
static void kill_all_workers(void)
{
	int i; 
	pid_t pid;
	
        for(i = 0; i < max_workers; i++) {
                if ((pid = worker_pids[i]) != 0) {
                        DPRINTF("sending TERM signal to worker %d\n", pid);
                        kill(pid, SIGTERM);
                }
        }

	while(running_workers > 0)
		pause();
}

static void agent_signal_handler(int signum)
{
	kill_all_workers();
	exit(0);
}

static void worker_reaper(int signum)
{
	int status, i;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status))
			fprintf(stderr, "worker %d exited with status %d\n",
				pid, WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			fprintf(stderr, "worker %d exited with signal %d\n",
				pid, WTERMSIG(status));

		for(i = 0; i < max_workers; i++) {
			if (worker_pids[i] == pid) {
				worker_pids[i] = 0;
				running_workers -= 1;
			}
		}
	}
}

/* returns PID of newly spawned worker or 0 if an error occured */

static pid_t spawn_worker(InputOptions *in)
{
	pid_t pid;

	if ((pid = fork())== -1) {
		perror("error while forking worker process");
		return 0;
	}
	
	if (!pid)  /* child code */
		worker_init(in);

	/* parent code */
	running_workers += 1;
	return pid;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	InputOptions *in;
	int i;
	
	/* get the input options */
	if ((in = fill_inputopts(argc, argv)) == NULL)
		return 1;
	
	max_workers = in->workers;

	if (!(worker_pids = malloc(max_workers * sizeof(pid_t)))) {
		perror("error allocating memory for worker pid array");
		return 1;
	}

	memset(worker_pids, 0, max_workers * sizeof(pid_t));
	running_workers = 0;

	/* initialize handlers for quiting */
	sa.sa_handler = agent_signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("error while registering agent SIGINT handler");
		return 1;
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("error while registering agent SIGTERM handler");
		return 1;
	}

	sa.sa_handler = worker_reaper;
	sa.sa_flags = SA_NOCLDSTOP;

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("error while registering agent SIGCHLD handler");
		return 1;
	}

	for(i = 0; i < max_workers; i++) {
		if (!(worker_pids[i] = spawn_worker(in)))
			goto err;
	}

	while (1) {
		pause();

		/* If we get here, 1 or more workers have died.
		   We thus ressurect them */

		for(i = 0; i < max_workers; i++) {
			if (!worker_pids[i] && !(worker_pids[i] = spawn_worker(in)))
				goto err;
		}

	}

err:
	/* reached only on error */

	kill_all_workers();
	destroy_inputopts(in);
	free(worker_pids);

	return 1;
}
