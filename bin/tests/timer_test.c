
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
task_t t1, t2, t3;
timer_t ti1, ti2, ti3;
int tick_count = 0;

static isc_boolean_t
shutdown_task(task_t task, task_event_t event) {
	char *name = event->arg;

	printf("shutdown %s\n", name);
	return (ISC_TRUE);
}

static isc_boolean_t
tick(task_t task, task_event_t event)
{
	char *name = event->arg;

	INSIST(event->type == TIMER_EVENT_TICK);

	printf("task %s (%p) tick\n", name, task);

	tick_count++;
	if (tick_count % 3 == 0)
		timer_touch(ti3);

	if (tick_count == 7) {
		os_time_t expires, interval, now;

		(void)os_time_get(&now);
		expires.seconds = 5;
		expires.nanoseconds = 0;
		os_time_add(&now, &expires, &expires);
		interval.seconds = 4;
		interval.nanoseconds = 0;
		printf("*** resetting ti3 ***\n");
		INSIST(timer_reset(ti3, timer_type_once, expires, interval,
				   ISC_TRUE)
		       == ISC_R_SUCCESS);
	}

	return (ISC_FALSE);
}

static isc_boolean_t
timeout(task_t task, task_event_t event)
{
	char *name = event->arg;
	char *type;

	INSIST(event->type == TIMER_EVENT_IDLE || 
	       event->type == TIMER_EVENT_LIFE);

	if (event->type == TIMER_EVENT_IDLE)
		type = "idle";
	else
		type = "life";
	printf("task %s (%p) %s timeout\n", name, task, type);

	if (strcmp(name, "3") == 0) {
		printf("*** saving task 3 ***\n");
		return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

void
main(int argc, char *argv[]) {
	task_manager_t manager = NULL;
	timer_manager_t timgr = NULL;
	unsigned int workers;
	os_time_t expires, interval, now;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(mem_context_create(0, 0, &mctx) == 0);
	INSIST(task_manager_create(mctx, workers, 0, &manager) == workers);
	INSIST(task_create(manager, shutdown_task, "1", 0, &t1));
	INSIST(task_create(manager, shutdown_task, "2", 0, &t2));
	INSIST(task_create(manager, shutdown_task, "3", 0, &t3));
	INSIST(timer_manager_create(mctx, &timgr) == ISC_R_SUCCESS);

	printf("task 1: %p\n", t1);
	printf("task 2: %p\n", t2);
	printf("task 3: %p\n", t3);

	(void)os_time_get(&now);

	expires.seconds = 0;
	expires.nanoseconds = 0;
	interval.seconds = 2;
	interval.nanoseconds = 0;
	INSIST(timer_create(timgr, timer_type_once, expires, interval,
			    t2, timeout, "2", &ti2) == ISC_R_SUCCESS);
	expires.seconds = 0;
	expires.nanoseconds = 0;
	interval.seconds = 1;
	interval.nanoseconds = 0;
	INSIST(timer_create(timgr, timer_type_ticker, expires, interval,
			    t1, tick, "1", &ti1) == ISC_R_SUCCESS);
	expires.seconds = 10;
	expires.nanoseconds = 0;
	os_time_add(&now, &expires, &expires);
	interval.seconds = 2;
	interval.nanoseconds = 0;
	INSIST(timer_create(timgr, timer_type_once, expires, interval,
			    t3, timeout, "3", &ti3) == ISC_R_SUCCESS);

	task_detach(&t1);
	task_detach(&t2);
	task_detach(&t3);

	sleep(15);
	printf("destroy\n");
	timer_detach(&ti1);
	timer_detach(&ti2);
	timer_detach(&ti3);
	sleep(2);
	timer_manager_destroy(&timgr);
	task_manager_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
