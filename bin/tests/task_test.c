
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "memcluster.h"
#include "task.h"

/*ARGSUSED*/
boolean_t
my_callback(task_t task, void *arg, generic_event_t event) {
	int i, j;
	char *name = arg;

	j = 0;
	for (i = 0; i < 100000000; i++)
		j += 100;
	printf("task %s: %d\n", name, j);
	
	return (FALSE);
}

/*ARGSUSED*/
boolean_t
my_shutdown(task_t task, void *arg, generic_event_t event) {
	char *name = arg;

	printf("shutdown %s\n", name);
	return (TRUE);
}

generic_event_t
event_allocate(mem_context_t mctx, event_type_t type, event_action_t action,
	       size_t size) {
	generic_event_t event;

	if (size < sizeof *event)
		return (NULL);
	event = mem_get(mctx, size);
	if (event == NULL)
		return (NULL);
	event->mctx = mctx;
	event->size = size;
	event->type = type;
	event->action = action;

	return (event);
}

void
main(int argc, char *argv[]) {
	mem_context_t mctx = NULL;
	task_manager_t manager = NULL;
	task_t t1 = NULL, t2 = NULL;
	generic_event_t event;
	unsigned int workers;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(mem_context_create(0, 0, &mctx) == 0);

	INSIST(task_manager_create(mctx, workers, 0, &manager) == workers);

	INSIST(task_allocate(manager, "1", my_shutdown, 0, &t1));
	INSIST(task_allocate(manager, "2", my_shutdown, 0, &t2));
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t2, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t2, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t2, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t1, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(t2, event);

	task_shutdown(t1);
	task_shutdown(t2);
	task_detach(&t1);
	task_detach(&t2);
	printf("destroy\n");
	task_manager_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
