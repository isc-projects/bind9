
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/memcluster.h>
#include <isc/task.h>

/*ARGSUSED*/
static boolean_t
my_callback(task_t __attribute__((unused)) task,
	    void *arg,
	    generic_event_t __attribute__((unused)) event)
{
	int i, j;
	char *name = arg;

	j = 0;
	for (i = 0; i < 100000000; i++)
		j += 100;
	printf("task %s: %d\n", name, j);
	
	return (FALSE);
}

/*ARGSUSED*/
static boolean_t
my_shutdown(task_t __attribute__((unused)) task,
	    void *arg,
	    generic_event_t __attribute__((unused)) event)
{
	char *name = arg;

	printf("shutdown %s\n", name);
	return (TRUE);
}

void
main(int argc, char *argv[]) {
	mem_context_t mctx = NULL;
	task_manager_t manager = NULL;
	task_t t1 = NULL, t2 = NULL;
	task_t t3 = NULL, t4 = NULL;
	generic_event_t event;
	unsigned int workers;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(mem_context_create(0, 0, &mctx) == 0);

	INSIST(task_manager_create(mctx, workers, 0, &manager) == workers);

	INSIST(task_create(manager, "1", my_shutdown, 0, &t1));
	INSIST(task_create(manager, "2", my_shutdown, 0, &t2));
	INSIST(task_create(manager, "3", my_shutdown, 0, &t3));
	INSIST(task_create(manager, "4", my_shutdown, 0, &t4));

	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t2, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t3, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t4, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t2, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t3, event);
	event = event_get(mctx, 1, my_callback, sizeof *event);
	task_send_event(t4, event);

	task_detach(&t1);
	task_detach(&t2);
	task_detach(&t3);
	task_detach(&t4);

	printf("destroy\n");
	task_manager_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
