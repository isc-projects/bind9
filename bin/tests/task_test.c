
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/assertions.h>
#include <isc/memcluster.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/timer.h>

isc_memctx_t mctx = NULL;

static isc_boolean_t
my_callback(isc_task_t task, isc_event_t event)
{
	int i, j;
	char *name = event->arg;

	j = 0;
	for (i = 0; i < 1000000; i++)
		j += 100;
	printf("task %s (%p): %d\n", name, task, j);
	
	return (ISC_FALSE);
}

static isc_boolean_t
my_shutdown(isc_task_t task, isc_event_t event) {
	char *name = event->arg;

	printf("shutdown %s (%p)\n", name, task);
	return (ISC_TRUE);
}

static isc_boolean_t
my_tick(isc_task_t task, isc_event_t event)
{
	char *name = event->arg;

	printf("task %p tick %s\n", task, name);
	return (ISC_FALSE);
}

void
main(int argc, char *argv[]) {
	isc_taskmgr_t manager = NULL;
	isc_task_t t1 = NULL, t2 = NULL;
	isc_task_t t3 = NULL, t4 = NULL;
	isc_event_t event;
	unsigned int workers;
	isc_timermgr_t timgr;
	isc_timer_t ti1, ti2;
	struct isc_time absolute, interval;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(isc_memctx_create(0, 0, &mctx) == ISC_R_SUCCESS);

	INSIST(isc_taskmgr_create(mctx, workers, 0, &manager) ==
	       ISC_R_SUCCESS);

	INSIST(isc_task_create(manager, my_shutdown, "1", 0, &t1) ==
	       ISC_R_SUCCESS);
	INSIST(isc_task_create(manager, my_shutdown, "2", 0, &t2) ==
	       ISC_R_SUCCESS);
	INSIST(isc_task_create(manager, my_shutdown, "3", 0, &t3) ==
	       ISC_R_SUCCESS);
	INSIST(isc_task_create(manager, my_shutdown, "4", 0, &t4) ==
	       ISC_R_SUCCESS);

	timgr = NULL;
	INSIST(isc_timermgr_create(mctx, &timgr) == ISC_R_SUCCESS);
	ti1 = NULL;
	absolute.seconds = 0;
	absolute.nanoseconds = 0;
	interval.seconds = 1;
	interval.nanoseconds = 0;
	INSIST(isc_timer_create(timgr, isc_timertype_ticker,
				&absolute, &interval,
				t1, my_tick, "foo", &ti1) == ISC_R_SUCCESS);
	ti2 = NULL;
	INSIST(isc_timer_create(timgr, isc_timertype_ticker,
				&absolute, &interval,
				t2, my_tick, "bar", &ti2) == ISC_R_SUCCESS);

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);
	sleep(2);

	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "1",
				   sizeof *event);
	isc_task_send(t1, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "2",
				   sizeof *event);
	isc_task_send(t2, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "3",
				   sizeof *event);
	isc_task_send(t3, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "4",
				   sizeof *event);
	isc_task_send(t4, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "2",
				   sizeof *event);
	isc_task_send(t2, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "3",
				   sizeof *event);
	isc_task_send(t3, &event);
	event = isc_event_allocate(mctx, (void *)main, 1, my_callback, "4",
				   sizeof *event);
	isc_task_send(t4, &event);
	isc_task_purge(t3, NULL, 0);

	isc_task_detach(&t1);
	isc_task_detach(&t2);
	isc_task_detach(&t3);
	isc_task_detach(&t4);

	sleep(10);
	printf("destroy\n");
	isc_timer_detach(&ti1);
	isc_timer_detach(&ti2);
	isc_timermgr_destroy(&timgr);
	isc_taskmgr_destroy(&manager);
	printf("destroyed\n");
	
	isc_mem_stats(mctx, stdout);
	isc_memctx_destroy(&mctx);
}
