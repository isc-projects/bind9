/*
 * Copyright (C) 1998-2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: condition.c,v 1.14 2000/08/01 01:31:45 tale Exp $ */

#include <config.h>

#include <isc/condition.h>
#include <isc/assertions.h>

#define SIGNAL		0
#define BROADCAST	1

isc_result_t
isc_condition_init(isc_condition_t *cond) {
	HANDLE h;

	REQUIRE(cond != NULL);

	cond->waiters = 0;
	h = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (h == NULL) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	cond->events[SIGNAL] = h;
	h = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (h == NULL) {
		(void)CloseHandle(cond->events[SIGNAL]);
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	cond->events[BROADCAST] = h;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_signal(isc_condition_t *cond) {

	/*
	 * Unlike pthreads, the caller MUST hold the lock associated with
	 * the condition variable when calling us.
	 */
	REQUIRE(cond != NULL);

	if (cond->waiters > 0 &&
	    !SetEvent(cond->events[SIGNAL])) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_broadcast(isc_condition_t *cond) {

	/*
	 * Unlike pthreads, the caller MUST hold the lock associated with
	 * the condition variable when calling us.
	 */
	REQUIRE(cond != NULL);

	if (cond->waiters > 0 &&
	    !SetEvent(cond->events[BROADCAST])) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_destroy(isc_condition_t *cond) {

	REQUIRE(cond != NULL);

	(void)CloseHandle(cond->events[SIGNAL]);
	(void)CloseHandle(cond->events[BROADCAST]);

	return (ISC_R_SUCCESS);
}

static isc_result_t
wait(isc_condition_t *cond, isc_mutex_t *mutex, DWORD milliseconds) {
	DWORD result;

	cond->waiters++;
	LeaveCriticalSection(mutex);
	result = WaitForMultipleObjects(2, cond->events, FALSE, milliseconds);
	if (result == WAIT_FAILED) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	EnterCriticalSection(mutex);
	cond->waiters--;
	if (cond->waiters == 0 &&
	    !ResetEvent(cond->events[BROADCAST])) {
		/* XXX */
		LeaveCriticalSection(mutex);
		return (ISC_R_UNEXPECTED);
	}

	if (result == WAIT_TIMEOUT)
		return (ISC_R_TIMEDOUT);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_wait(isc_condition_t *cond, isc_mutex_t *mutex) {
	return (wait(cond, mutex, INFINITE));
}

isc_result_t
isc_condition_waituntil(isc_condition_t *cond, isc_mutex_t *mutex,
			isc_time_t *t)
{
	DWORD milliseconds;
	isc_uint64_t microseconds;
	isc_time_t now;

	if (isc_time_now(&now) != ISC_R_SUCCESS) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	microseconds = isc_time_microdiff(t, &now);
	if (microseconds > 0xFFFFFFFFi64 * 1000)
		milliseconds = 0xFFFFFFFF;
	else
		milliseconds = (DWORD)(microseconds / 1000);

	return (wait(cond, mutex, milliseconds));
}
