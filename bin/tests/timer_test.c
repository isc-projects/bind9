/*
 * Copyright (C) 1998  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/timer.h>

isc_mem_t *mctx = NULL;
isc_task_t *t1, *t2, *t3;
isc_timer_t *ti1, *ti2, *ti3;
int tick_count = 0;

static void
shutdown_task(isc_task_t *task, isc_event_t *event) {
	char *name = event->arg;

	printf("task %p shutdown %s\n", task, name);
	isc_event_free(&event);
}

static void
tick(isc_task_t *task, isc_event_t *event)
{
	char *name = event->arg;

	INSIST(event->type == ISC_TIMEREVENT_TICK);

	printf("task %s (%p) tick\n", name, task);

	tick_count++;
	if (ti3 != NULL && tick_count % 3 == 0)
		isc_timer_touch(ti3);

	if (ti3 != NULL && tick_count == 7) {
		isc_time_t expires, now;
		isc_interval_t interval;

		(void)isc_time_get(&now);
		isc_interval_set(&interval, 5, 0);
		isc_time_add(&now, &interval, &expires);
		isc_interval_set(&interval, 4, 0);
		printf("*** resetting ti3 ***\n");
		INSIST(isc_timer_reset(ti3, isc_timertype_once, &expires,
				       &interval, ISC_TRUE)
		       == ISC_R_SUCCESS);
	}

	isc_event_free(&event);
}

static void
timeout(isc_task_t *task, isc_event_t *event)
{
	char *name = event->arg;
	char *type;

	INSIST(event->type == ISC_TIMEREVENT_IDLE || 
	       event->type == ISC_TIMEREVENT_LIFE);

	if (event->type == ISC_TIMEREVENT_IDLE)
		type = "idle";
	else
		type = "life";
	printf("task %s (%p) %s timeout\n", name, task, type);

	if (strcmp(name, "3") == 0) {
		printf("*** saving task 3 ***\n");
		isc_event_free(&event);
		return;
	}

	isc_event_free(&event);
	isc_task_shutdown(task);
}

void
main(int argc, char *argv[]) {
	isc_taskmgr_t *manager = NULL;
	isc_timermgr_t *timgr = NULL;
	unsigned int workers;
	isc_time_t expires, now;
	isc_interval_t interval;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	INSIST(isc_taskmgr_create(mctx, workers, 0, &manager) ==
	       ISC_R_SUCCESS);
	INSIST(isc_timermgr_create(mctx, &timgr) == ISC_R_SUCCESS);

	INSIST(isc_task_create(manager, 0, &t1) == ISC_R_SUCCESS);
	INSIST(isc_task_create(manager, 0, &t2) == ISC_R_SUCCESS);
	INSIST(isc_task_create(manager, 0, &t3) == ISC_R_SUCCESS);
	INSIST(isc_task_onshutdown(t1, shutdown_task, "1") == ISC_R_SUCCESS);
	INSIST(isc_task_onshutdown(t2, shutdown_task, "2") == ISC_R_SUCCESS);
	INSIST(isc_task_onshutdown(t3, shutdown_task, "3") == ISC_R_SUCCESS);

	printf("task 1: %p\n", t1);
	printf("task 2: %p\n", t2);
	printf("task 3: %p\n", t3);

	(void)isc_time_get(&now);

	isc_time_settoepoch(&expires);
	isc_interval_set(&interval, 2, 0);
	INSIST(isc_timer_create(timgr, isc_timertype_once, &expires, &interval,
				t2, timeout, "2", &ti2) == ISC_R_SUCCESS);
	isc_time_settoepoch(&expires);
	isc_interval_set(&interval, 1, 0);
	INSIST(isc_timer_create(timgr, isc_timertype_ticker,
				&expires, &interval,
				t1, tick, "1", &ti1) == ISC_R_SUCCESS);
	isc_interval_set(&interval, 10, 0);
	isc_time_add(&now, &interval, &expires);
	isc_interval_set(&interval, 2, 0);
	INSIST(isc_timer_create(timgr, isc_timertype_once, &expires, &interval,
				t3, timeout, "3", &ti3) == ISC_R_SUCCESS);

	isc_task_detach(&t1);
	isc_task_detach(&t2);
	isc_task_detach(&t3);

	sleep(15);
	printf("destroy\n");
	isc_timer_detach(&ti1);
	isc_timer_detach(&ti2);
	isc_timer_detach(&ti3);
	sleep(2);
	isc_timermgr_destroy(&timgr);
	isc_taskmgr_destroy(&manager);
	printf("destroyed\n");
	
	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);
}
