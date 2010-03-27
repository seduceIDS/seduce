#include "job.h"
#include "errors.h"
#include "utils.h"

static JobList joblist;

void init_joblist(void)
{
	joblist.head = joblist.tail = NULL;
	joblist.cnt = 0;

	mutex_init (&joblist.mutex);
}

/*
 *  Removes the head of the job list (the oldest job) and exetute the
 *  function passed as argument on the Data of the job just removed.
 *  Returns whatever the function returns. 
 */
int consume_job(int (*func)(), void *params)
{
	int ret;
	Job *job_to_remove;

	DPRINTF("\n");
	mutex_lock (&joblist.mutex);

	while (joblist.cnt == 0) {
		DPRINTF("No Jobs available...\n");
		mutex_unlock (&joblist.mutex);
		return -1;
	}

	/* Remove the Job from the list...*/
	DPRINTF("Removing the job...\n");
	job_to_remove = joblist.head;
	joblist.head = joblist.head->next;
	joblist.cnt--;
	if (joblist.cnt == 0)
		joblist.tail = NULL;
	else joblist.head->prev = NULL;
	
	mutex_unlock (&joblist.mutex);

	/* Executing the Job */
	mutex_lock(&job_to_remove->data_info.sensor->mutex);

	DPRINTF("Execute the Job...\n");
	DPRINTF("Session ID: %u\n",job_to_remove->data_info.session->id);

	/* Those data are the heading data of a group */
	job_to_remove->data_info.is_grouphead = 1;

	/* Execute the function on this job */
	if(params)
		ret = (*func) (params, &job_to_remove->data_info);
	else	ret = (*func) (&job_to_remove->data_info);
	DPRINTF("Job executed\n");


	mutex_unlock(&job_to_remove->data_info.sensor->mutex);

	free(job_to_remove);
	return ret;
}

int add_job(Sensor *this_sensor, Session *this_session, void *data)
{
	Job *job_to_add;

	DPRINTF("\n");
	job_to_add = malloc(sizeof(Job));
	if (job_to_add == NULL) {
		errno_cont("Error in malloc\n");
		return 0;
	}

	job_to_add->data_info.session = this_session;

	if (this_session->proto == IPPROTO_TCP)
		job_to_add->data_info.data.tcp = data;
	else job_to_add->data_info.data.udp = data;

	job_to_add->data_info.sensor = this_sensor;

	DPRINTF("Adding Job for Session: %u\n",this_session->id);
	/* Now put it in the job list...*/
	mutex_lock (&joblist.mutex);

	job_to_add->prev = joblist.tail;
	job_to_add->next = NULL;

	if (joblist.tail != NULL) {
		joblist.tail->next = job_to_add;
		joblist.tail = job_to_add;
	}
	else joblist.head = joblist.tail = job_to_add;

	joblist.cnt++;

	
	mutex_unlock (&joblist.mutex);

	DPRINTF("Finished Adding....\n");

	return 1;
}

