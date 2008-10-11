#include "data_group.h"
#include "errors.h"
#include "utils.h"

static GroupList grouplist;

void init_grouplist(void)
{
	grouplist.head = grouplist.tail = NULL;
	grouplist.cnt = 0;

	mutex_init (&grouplist.mutex);
}

/*
 *  Removes the head of the group list (the oldest group) and exetute the
 *  function passed as argument on the Data of the group just removed.
 *  Returns whatever the function returns. 
 */
int consume_group(int (*func)(), void *params)
{
	int ret;
	Group *group_to_remove;

	DPRINTF("\n");
	mutex_lock (&grouplist.mutex);

	while (grouplist.cnt == 0) {
		DPRINTF("No Groups available...\n");
		mutex_unlock (&grouplist.mutex);
		return -1;
	}

	/* Remove the Group from the list...*/
	DPRINTF("Removing the group...\n");
	group_to_remove = grouplist.head;
	grouplist.head = grouplist.head->next;

	grouplist.cnt--;
	if (grouplist.cnt == 0)
		grouplist.tail = NULL;
	else
		grouplist.head->prev = NULL;
	
	mutex_unlock (&grouplist.mutex);

	/* Executing the Group */
	mutex_lock(&sensor.mutex);

	DPRINTF("Execute the Group...\n");
	DPRINTF("Session ID: %u\n",group_to_remove->grouphead.session->id);

	/* Those data are the heading data of a group */
	group_to_remove->grouphead.is_grouphead = 1;

	/* Execute the function on this group */
	if (params)
		ret = (*func) (params, &group_to_remove->grouphead);
	else
		ret = (*func) (&group_to_remove->grouphead);
	
	DPRINTF("Group executed\n");

	mutex_unlock(&sensor.mutex);

	free(group_to_remove);
	return ret;
}

int add_group(Session *this_session, void *data)
{
	Group *group_to_add;

	DPRINTF("\n");
	group_to_add = malloc(sizeof(Group));
	if (group_to_add == NULL) {
		errno_cont("Error in malloc\n");
		return 0;
	}

	group_to_add->grouphead.session = this_session;

	if (this_session->proto == IPPROTO_TCP)
		group_to_add->grouphead.data.tcp = data;
	else
		group_to_add->grouphead.data.udp = data;


	DPRINTF("Adding Group for Session: %u\n",this_session->id);
	/* Now put it in the group list...*/
	mutex_lock (&grouplist.mutex);

	group_to_add->prev = grouplist.tail;
	group_to_add->next = NULL;

	if (grouplist.tail != NULL) {
		grouplist.tail->next = group_to_add;
		grouplist.tail = group_to_add;
	} else
		grouplist.head = grouplist.tail = group_to_add;

	grouplist.cnt++;

	mutex_unlock (&grouplist.mutex);

	DPRINTF("Finished Adding....\n");

	return 1;
}

