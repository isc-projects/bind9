
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "memcluster.h"
#include "task.h"

boolean_t
my_callback(generic_event_t event) {
	int i;

	printf("my callback, event type %d\n", event->type);
	for (i = 0; i < 1000000; i++);
	return (FALSE);
}

boolean_t
my_shutdown(generic_event_t event) {
	printf("shutdown\n");
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
	event->type = type;
	event->action = action;

	return (event);
}

void
main(void) {
	mem_context_t mctx = NULL;
	task_manager_t manager = NULL;
	task_t task = NULL;
	generic_event_t event;

	INSIST(mem_context_create(0, 0, &mctx) == 0);

	INSIST(task_manager_create(mctx, 2, 0, &manager) == 2);
	INSIST(task_allocate(manager, my_shutdown, 0, &task));

	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(task, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(task, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(task, event);
	event = event_allocate(mctx, 1, my_callback, sizeof *event);
	task_send_event(task, event);

	printf("presleep\n");
	sleep(4);
	printf("postsleep\n");

	task_shutdown(task);
	task_detach(&task);
	task_manager_destroy(&manager);
	
	mem_stats(mctx, stdout);
}
