/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/timer.h>
#include <isc/ratelimiter.h>

isc_ratelimiter_t *rlim = NULL;

static void
ltick(isc_task_t *task, isc_event_t *event)
{
	(void) task;
	printf("** ltick **\n");
	isc_event_free(&event);
}

static void
utick(isc_task_t *task, isc_event_t *event)
{
	(void) task;
	printf("utick\n");
	event->action = ltick;
	isc_ratelimiter_enqueue(rlim, &event);
}

#define N 7

int
main(int argc, char *argv[]) {
	isc_mem_t *mctx = NULL;
	isc_taskmgr_t *taskmgr = NULL;
	isc_timermgr_t *timermgr = NULL;
	isc_task_t *task = NULL;
	int times[N] = { 1, 2, 3, 10000, 10001, 10002, 11500 };
	isc_timer_t *timers[N];
	isc_interval_t linterval;
	int i;

	(void) argc;
	(void) argv;
	
	isc_interval_set(&linterval, 1, 0);
	
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 3, 0, &taskmgr) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_timermgr_create(mctx, &timermgr) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_task_create(taskmgr, mctx, 0, &task) ==
		      ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_ratelimiter_create(mctx, timermgr, task, 
					     &rlim) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_ratelimiter_setinterval(rlim, &linterval) ==
		      ISC_R_SUCCESS);
	
	for (i = 0; i < N; i++) {
		isc_interval_t uinterval;
		isc_interval_set(&uinterval, times[i] / 1000,
				 (times[i] % 1000) * 1000000);
		RUNTIME_CHECK(isc_timer_create(timermgr,
					       isc_timertype_once, NULL,
					       &uinterval,
					       task, utick, NULL,
					       &timers[i]) == ISC_R_SUCCESS);
	}
	sleep(15);
	
	printf("destroy\n");

	for (i = 0; i < N; i++) {
		isc_timer_detach(&timers[i]);
	}

	isc_ratelimiter_destroy(&rlim);
	isc_task_destroy(&task);

	isc_timermgr_destroy(&timermgr);
	isc_taskmgr_destroy(&taskmgr);

	sleep(2);
	isc_mem_stats(mctx, stdout);
	
	return (0);
}
