
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/memcluster.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/timer.h>

mem_context_t mctx = NULL;

static boolean_t
my_callback(task_t task, task_event_t event)
{
	int i, j;
	char *name = event->arg;

	j = 0;
	for (i = 0; i < 100000000; i++)
		j += 100;
	printf("task %s: %d\n", name, j);
	
	return (FALSE);
}

static boolean_t
my_shutdown(task_t task, task_event_t event) {
	char *name = event->arg;

	printf("shutdown %s\n", name);
	return (TRUE);
}

static boolean_t
my_tick(task_t task, task_event_t event)
{
	char *name = event->arg;

	printf("task %p tick %s\n", task, name);
	return (FALSE);
}

void
main(int argc, char *argv[]) {
	task_manager_t manager = NULL;
	task_t t1 = NULL, t2 = NULL;
	task_t t3 = NULL, t4 = NULL;
	task_event_t event;
	unsigned int workers;
	timer_manager_t timgr;
	timer_t ti1, ti2;
	os_time_t absolute, interval;

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

	timgr = NULL;
	INSIST(timer_manager_create(mctx, &timgr) == ISC_R_SUCCESS);
	ti1 = NULL;
	absolute.seconds = 0;
	absolute.nanoseconds = 0;
	interval.seconds = 5;
	interval.nanoseconds = 0;
	INSIST(timer_create(timgr, timer_type_ticker, absolute, interval,
			    t1, my_tick, "foo", &ti1) == ISC_R_SUCCESS);
	ti2 = NULL;
	INSIST(timer_create(timgr, timer_type_ticker, absolute, interval,
			    t2, my_tick, "bar", &ti2) == ISC_R_SUCCESS);

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);
	sleep(2);

	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "1",
				    sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "2",
				    sizeof *event);
	task_send_event(t2, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "3",
				    sizeof *event);
	task_send_event(t3, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "4",
				    sizeof *event);
	task_send_event(t4, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "2",
				    sizeof *event);
	task_send_event(t2, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "3",
				    sizeof *event);
	task_send_event(t3, &event);
	event = task_event_allocate(mctx, main, 1, my_callback, "4",
				    sizeof *event);
	task_send_event(t4, &event);
	task_purge_events(t3, NULL, 0);

	task_detach(&t1);
	task_detach(&t2);
	task_detach(&t3);
	task_detach(&t4);

	printf("destroy\n");
	task_manager_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
