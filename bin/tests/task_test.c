
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/memcluster.h>
#include <isc/task.h>
#include <isc/thread.h>

mem_context_t mctx = NULL;

/*ARGSUSED*/
static boolean_t
my_callback(task_t __attribute__((unused)) task,
	    task_event_t __attribute__((unused)) event)
{
	int i, j;
	char *name = event->arg;

	j = 0;
	for (i = 0; i < 100000000; i++)
		j += 100;
	printf("task %s: %d\n", name, j);
	
	return (FALSE);
}

/*ARGSUSED*/
static boolean_t
my_shutdown(task_t __attribute__((unused)) task,
	    task_event_t __attribute__((unused)) event)
{
	char *name = event->arg;

	printf("shutdown %s\n", name);
	return (TRUE);
}

/*ARGSUSED*/
static boolean_t
my_tick(task_t __attribute__((unused)) task,
	task_event_t __attribute__((unused)) event)
{
	char *name = event->arg;

	printf("tick %s\n", name);
	return (FALSE);
}

void *
simple_timer_run(void *arg) {
	task_t task = arg;
	task_event_t event;
	int i;
	
	for (i = 0; i < 10; i++) {
		sleep(1);
		printf("sending timer to %p\n", task);
		event = task_event_allocate(mctx, 2, my_tick, "foo",
					    sizeof *event);
		INSIST(event != NULL);
		(void)task_send_event(task, &event);
	}

	task_detach(&task);
	return (NULL);
}

void
simple_timer_init(task_t task) {
	os_thread_t t;
	task_t task_clone;

	task_clone = NULL;
	task_attach(task, &task_clone);
	INSIST(os_thread_create(simple_timer_run, task_clone, &t));
	(void)os_thread_detach(t);
}

void
main(int argc, char *argv[]) {
	task_manager_t manager = NULL;
	task_t t1 = NULL, t2 = NULL;
	task_t t3 = NULL, t4 = NULL;
	task_event_t event;
	unsigned int workers;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(mem_context_create(0, 0, &mctx) == 0);

	INSIST(task_manager_create(mctx, workers, 0, &manager) == workers);

	INSIST(task_create(manager, my_shutdown, "1", 0, &t1));
	INSIST(task_create(manager, my_shutdown, "2", 0, &t2));
	INSIST(task_create(manager, my_shutdown, "3", 0, &t3));
	INSIST(task_create(manager, my_shutdown, "4", 0, &t4));

	simple_timer_init(t1);
	simple_timer_init(t2);
	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);
	sleep(2);

	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "1", sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, "2", sizeof *event);
	task_send_event(t2, &event);
	event = task_event_allocate(mctx, 1, my_callback, "3", sizeof *event);
	task_send_event(t3, &event);
	event = task_event_allocate(mctx, 1, my_callback, "4", sizeof *event);
	task_send_event(t4, &event);
	event = task_event_allocate(mctx, 1, my_callback, "2", sizeof *event);
	task_send_event(t2, &event);
	event = task_event_allocate(mctx, 1, my_callback, "3", sizeof *event);
	task_send_event(t3, &event);
	event = task_event_allocate(mctx, 1, my_callback, "4", sizeof *event);
	task_send_event(t4, &event);

	task_detach(&t1);
	task_detach(&t2);
	task_detach(&t3);
	task_detach(&t4);

	printf("destroy\n");
	task_manager_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
