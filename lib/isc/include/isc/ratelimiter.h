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

#ifndef ISC_RATELIMITER_H
#define ISC_RATELIMITER_H 1

/*****
 ***** Module Info
 *****/

/*
 * A rate limiter is a mechanism for dispatching events at a limited
 * rate.  This is intended to be used when sending zone maintenance 
 * SOA queries, NOTIFY messages, etc.
 */

/***
 *** Imports.
 ***/

#include <isc/task.h>
#include <isc/timer.h>

ISC_LANG_BEGINDECLS

/*****
 ***** Types.
 *****/

typedef struct isc_ratelimiter isc_ratelimiter_t;

typedef enum {
	isc_ratelimiter_ratelimited,
	isc_ratelimiter_worklimited
} isc_ratelimiter_state_t;

/*****
 ***** Functions.
 *****/

isc_result_t
isc_ratelimiter_create(isc_mem_t *mctx, isc_timermgr_t *timermgr,
		       isc_task_t *task, isc_ratelimiter_t **ratelimiterp);
/*
 * Create a rate limiter.  It will execute events in the context
 * of 'task' with a guaranteed minimum interval, initially zero.
 */

isc_result_t
isc_ratelimiter_setinterval(isc_ratelimiter_t *rl, isc_interval_t *interval);
/*
 * Set the mininum interval between event executions.
 * The interval value is copied, so the caller need not preserve it.
 */

isc_result_t
isc_ratelimiter_enqueue(isc_ratelimiter_t *rl, isc_event_t **eventp);
/*
 * Queue an event for rate-limited execution.  This is similar
 * to doing an isc_task_send() to the rate limiter's task, except
 * that the execution may be delayed to achieve the desired rate
 * of execution.
 */

void
isc_ratelimiter_destroy(isc_ratelimiter_t **ratelimiterp);
/*
 * Destroy a rate limiter.  All events that have not yet been
 * dispatched to the task are freed immedately.
 * Does not destroy the task or events already queued on it.
 */

#endif /* ISC_RATELIMITER_H */
