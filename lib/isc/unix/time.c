/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#include <sys/types.h>
#include <sys/time.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/time.h>

/***
 *** Intervals
 ***/

static isc_interval_t zero_interval = { 0, 0 };
isc_interval_t *isc_interval_zero = &zero_interval;

void
isc_interval_set(isc_interval_t *i,
		 unsigned int seconds, unsigned int nanoseconds) {

	/*
	 * Set 'i' to a value representing an interval of 'seconds' seconds
	 * and 'nanoseconds' nanoseconds, suitable for use in isc_time_add()
	 * and isc_time_subtract().
	 */

	REQUIRE(i != NULL);
	REQUIRE(nanoseconds < 1000000000);

	i->seconds = seconds;
	i->nanoseconds = nanoseconds;
}

isc_boolean_t
isc_interval_iszero(isc_interval_t *i) {

	/*
	 * Returns ISC_TRUE iff. 'i' is the zero interval.
	 */

	REQUIRE(i != NULL);

	if (i->seconds == 0 && i->nanoseconds == 0)
		return (ISC_TRUE);

	return (ISC_FALSE);
}


/***
 *** Absolute Times
 ***/

static isc_time_t epoch = { 0, 0 };
isc_time_t *isc_time_epoch = &epoch;

void
isc_time_settoepoch(isc_time_t *t) {
	/*
	 * Set 't' to the time of the epoch.
	 */

	REQUIRE(t != NULL);

	t->seconds = 0;
	t->nanoseconds = 0;
}

isc_boolean_t
isc_time_isepoch(isc_time_t *t) {

	/*
	 * Returns ISC_TRUE iff. 't' is the epoch ("time zero").
	 */

	REQUIRE(t != NULL);

	if (t->seconds == 0 && t->nanoseconds == 0)
		return (ISC_TRUE);

	return (ISC_FALSE);
}

isc_result_t
isc_time_now(isc_time_t *t) {
	struct timeval tv;

	/*
	 * Set *t to the current absolute time.
	 */
	
	REQUIRE(t != NULL);
	
	if (gettimeofday(&tv, NULL) == -1) {
		UNEXPECTED_ERROR(__FILE__, __LINE__, strerror(errno));
		return (ISC_R_UNEXPECTED);
	}

	t->seconds = tv.tv_sec;
	t->nanoseconds = tv.tv_usec * 1000;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_time_nowplusinterval(isc_time_t *t, isc_interval_t *i) {
	struct timeval tv;

	/*
	 * Set *t to the current absolute time + i.
	 */
	
	REQUIRE(t != NULL);
	REQUIRE(i != NULL);
	
	if (gettimeofday(&tv, NULL) == -1) {
		UNEXPECTED_ERROR(__FILE__, __LINE__, strerror(errno));
		return (ISC_R_UNEXPECTED);
	}

	t->seconds = tv.tv_sec + i->seconds;
	t->nanoseconds = tv.tv_usec * 1000 + i->nanoseconds;
	if (t->nanoseconds > 1000000000) {
		t->seconds++;
		t->nanoseconds -= 1000000000;
	}

	return (ISC_R_SUCCESS);
}

int
isc_time_compare(isc_time_t *t1, isc_time_t *t2) {

	/*
	 * Compare the times referenced by 't1' and 't2'
	 */

	REQUIRE(t1 != NULL && t2 != NULL);

	if (t1->seconds < t2->seconds)
		return (-1);
	if (t1->seconds > t2->seconds)
		return (1);
	if (t1->nanoseconds < t2->nanoseconds)
		return (-1);
	if (t1->nanoseconds > t2->nanoseconds)
		return (1);
	return (0);
}

void
isc_time_add(isc_time_t *t, isc_interval_t *i, isc_time_t *result)
{
	/*
	 * Add 't' to 'i', storing the result in 'result'.
	 */

	REQUIRE(t != NULL && i != NULL && result != NULL);

	result->seconds = t->seconds + i->seconds;
	result->nanoseconds = t->nanoseconds + i->nanoseconds;
	if (result->nanoseconds > 1000000000) {
		result->seconds++;
		result->nanoseconds -= 1000000000;
	}
}

void
isc_time_subtract(isc_time_t *t, isc_interval_t *i, isc_time_t *result) {
	/*
	 * Subtract 'i' from 't', storing the result in 'result'.
	 */

	REQUIRE(t != NULL && i != NULL && result != NULL);
	
	result->seconds = t->seconds - i->seconds;
	if (t->nanoseconds >= i->nanoseconds)
		result->nanoseconds = t->nanoseconds - i->nanoseconds;
	else {
		result->nanoseconds = 1000000000 - i->nanoseconds +
			t->nanoseconds;
		result->seconds--;
	}
}

isc_uint64_t
isc_time_microdiff(isc_time_t *t1, isc_time_t *t2) {
	isc_uint64_t i1, i2, i3;

	REQUIRE(t1 != NULL && t2 != NULL);

	i1 = t1->seconds * 1000000000 + t1->nanoseconds;
	i2 = t2->seconds * 1000000000 + t2->nanoseconds;

	if (i1 <= i2)
		return (0);

	i3 = i1 - i2;

	/*
	 * Convert to microseconds.
	 */
	i3 = (i1 - i2) / 1000;

	return (i3);
}
