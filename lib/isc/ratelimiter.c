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

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/error.h>
#include <isc/ratelimiter.h>
#include <isc/util.h>

struct isc_ratelimiter {
	isc_mem_t *		mctx;
	isc_mutex_t		lock;
	isc_task_t *		task;
	isc_timer_t *		timer;
	isc_interval_t		interval;
	isc_ratelimiter_state_t	state;
	ISC_LIST(isc_event_t)	pending;
};

static void ratelimiter_tick(isc_task_t *task, isc_event_t *event);

isc_result_t
isc_ratelimiter_create(isc_mem_t *mctx, isc_timermgr_t *timermgr,
		       isc_task_t *task, isc_ratelimiter_t **ratelimiterp)
{
	isc_result_t result;
	isc_ratelimiter_t *rl;
	INSIST(ratelimiterp != NULL && *ratelimiterp == NULL);
	
	rl = isc_mem_get(mctx, sizeof(*rl));
	if (rl == NULL)
		return ISC_R_NOMEMORY;
	rl->mctx = mctx;
	rl->task = task;
	isc_interval_set(&rl->interval, 0, 0);
	rl->timer = NULL;
	rl->state = isc_ratelimiter_worklimited;
	ISC_LIST_INIT(rl->pending);

	result = isc_mutex_init(&rl->lock);
	if (result != ISC_R_SUCCESS)
		goto free_mem;
	result = isc_timer_create(timermgr, isc_timertype_inactive,
				  NULL, NULL, rl->task, ratelimiter_tick,
				  rl, &rl->timer);
	if (result != ISC_R_SUCCESS)
		goto free_mutex;

	*ratelimiterp = rl;
	return (ISC_R_SUCCESS);

free_mutex:
	isc_mutex_destroy(&rl->lock);
free_mem:
	isc_mem_put(mctx, rl, sizeof(*rl));
	return (result);
}

isc_result_t
isc_ratelimiter_setinterval(isc_ratelimiter_t *rl, isc_interval_t *interval)
{
	isc_result_t result = ISC_R_SUCCESS;
	LOCK(&rl->lock);
	rl->interval = *interval;
	/*
	 * If the timer is currently running, change its rate.
	 */
        if (rl->state == isc_ratelimiter_ratelimited) {
		result = isc_timer_reset(rl->timer, isc_timertype_ticker, NULL,
					 &rl->interval, ISC_FALSE);
	}
	UNLOCK(&rl->lock);
	return (result);
}
			    
			
isc_result_t
isc_ratelimiter_enqueue(isc_ratelimiter_t *rl, isc_event_t **eventp)
{
	isc_result_t result = ISC_R_SUCCESS;
	INSIST(eventp != NULL && *eventp != NULL);
	LOCK(&rl->lock);
        if (rl->state == isc_ratelimiter_ratelimited) {
		isc_event_t *ev = *eventp;
                ISC_LIST_APPEND(rl->pending, ev, link);
		*eventp = NULL;
        } else {
		result = isc_timer_reset(rl->timer, isc_timertype_ticker, NULL,
					 &rl->interval, ISC_FALSE);
		if (result == ISC_R_SUCCESS)
			rl->state = isc_ratelimiter_ratelimited;
	}
	UNLOCK(&rl->lock);
	if (*eventp != NULL)
		isc_task_send(rl->task, eventp);
	ENSURE(*eventp == NULL);
	return (result);
}

static void
ratelimiter_tick(isc_task_t *task, isc_event_t *event)
{
	isc_result_t result = ISC_R_SUCCESS;
	isc_ratelimiter_t *rl = (isc_ratelimiter_t *) event->arg;
	isc_event_t *p;
	(void) task; /* Unused */
	LOCK(&rl->lock);
        p = ISC_LIST_HEAD(rl->pending);
        if (p != NULL) {
		/*
		 * There is work to do.  Let's do it after unlocking.
		 */
                ISC_LIST_UNLINK(rl->pending, p, link);
	} else {
		/*
		 * No work left to do.  Stop the timer so that we don't
		 * waste resources by having it fire periodically.
		 */
		result = isc_timer_reset(rl->timer, isc_timertype_inactive,
					 NULL, NULL, ISC_FALSE);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		rl->state = isc_ratelimiter_worklimited;
	}
        UNLOCK(&rl->lock);
	isc_event_free(&event);
	/*
	 * If we have an event, dispatch it.
	 * There is potential for optimization here since
	 * we are already executing in the context of "task".
	 */
	if (p != NULL)
		isc_task_send(rl->task, &p);
	INSIST(p == NULL);
}

void
isc_ratelimiter_destroy(isc_ratelimiter_t **ratelimiterp) 
{
	isc_ratelimiter_t *rl = *ratelimiterp;
	isc_event_t *p;
	(void) isc_timer_reset(rl->timer, isc_timertype_inactive,
			       NULL, NULL, ISC_FALSE);
	isc_timer_detach(&rl->timer);
	while ((p = ISC_LIST_HEAD(rl->pending)) != NULL) {
		ISC_LIST_UNLINK(rl->pending, p, link);
		isc_event_free(&p);
	}
	isc_mutex_destroy(&rl->lock);
	isc_mem_put(rl->mctx, rl, sizeof(*rl));
	*ratelimiterp = NULL;
}
