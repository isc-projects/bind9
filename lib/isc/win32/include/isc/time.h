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

#ifndef ISC_TIME_H
#define ISC_TIME_H 1

#include <windows.h>

#include <isc/lang.h>
#include <isc/result.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/***
 *** Intervals
 ***/

/*
 * The contents of this structure are private, and MUST NOT be accessed
 * directly by callers.
 *
 * The contents are exposed only to allow callers to avoid dynamic allocation.
 */
struct isc_interval {
	isc_int64_t interval;
};

extern isc_interval_t *isc_interval_zero;

void
isc_interval_set(isc_interval_t *i,
		 unsigned int seconds, unsigned int nanoseconds);
/*
 * Set 'i' to a value representing an interval of 'seconds' seconds and
 * 'nanoseconds' nanoseconds, suitable for use in isc_time_add() and
 * isc_time_subtract().
 *
 * Requires:
 *
 *	't' is a valid pointer.
 *	nanoseconds < 1000000000.
 */

isc_boolean_t
isc_interval_iszero(isc_interval_t *i);
/*
 * Returns ISC_TRUE iff. 'i' is the zero interval.
 *
 * Requires:
 *
 *	't' is a valid pointer.
 *
 */

/***
 *** Absolute Times
 ***/

/*
 * The contents of this structure are private, and MUST NOT be accessed
 * directly by callers.
 *
 * The contents are exposed only to allow callers to avoid dynamic allocation.
 */

struct isc_time {
	FILETIME absolute;
};

extern isc_time_t *isc_time_epoch;

void
isc_time_set(isc_time_t *t, unsigned int seconds, unsigned int nanoseconds);
/*
 * Set 't' to a particular number of seconds + nanoseconds since the epoch.
 *
 * Notes:
 *	This call is equivalent to:
 *
 *	isc_time_settoepoch(t);
 *	isc_interval_set(i, seconds, nanoseconds);
 *	isc_time_add(t, i, t);
 *
 * Requires:
 *	't' is a valid pointer.
 *	nanoseconds < 1000000000.
 */

void
isc_time_settoepoch(isc_time_t *t);
/*
 * Set 't' to the time of the epoch.
 *
 * Notes:
 * 	The date of the epoch is platform-dependent.
 *
 * Requires:
 *
 *	't' is a valid pointer.
 *
 */

isc_boolean_t
isc_time_isepoch(isc_time_t *t);
/*
 * Returns ISC_TRUE iff. 't' is the epoch ("time zero").
 *
 * Requires:
 *
 *	't' is a valid pointer.
 *
 */

isc_result_t
isc_time_now(isc_time_t *t);
/*
 * Set 't' to the current absolute time.
 *
 * Requires:
 *
 *	't' is a valid pointer.
 *
 * Returns:
 *
 *	Success
 *	Unexpected error
 */

isc_result_t
isc_time_nowplusinterval(isc_time_t *t, isc_interval_t *i);
/*
 * Set *t to the current absolute time + i.
 *
 * Note:
 *	Overflow is not checked.
 *
 *	This call is equivalent to:
 *
 *		isc_time_now(t);
 *		isc_time_add(t, i, t);
 *
 * Requires:
 *
 *	't' and 'i' are valid pointers.
 *
 * Returns:
 *
 *	Success
 *	Unexpected error
 */

int
isc_time_compare(isc_time_t *t1, isc_time_t *t2);
/*
 * Compare the times referenced by 't1' and 't2'
 *
 * Requires:
 *
 *	't1' and 't2' are valid pointers.
 *
 * Returns:
 *
 *	-1		t1 < t2		(comparing times, not pointers)
 *	0		t1 = t2
 *	1		t1 > t2
 */

void
isc_time_add(isc_time_t *t, isc_interval_t *i, isc_time_t *result);
/*
 * Add 'i' to 't', storing the result in 'result'.
 *
 * Notes:
 *	Overflow is not checked.
 *
 * Requires:
 *
 *	't', 'i', and 'result' are valid pointers.
 */

void
isc_time_subtract(isc_time_t *t, isc_interval_t *i, isc_time_t *result);
/*
 * Subtract 'i' from 't', storing the result in 'result'.
 *
 * Requires:
 *
 *	't', 'i', and 'result' are valid pointers.
 *
 *	t >= epoch + i			(comparing times, not pointers)
 */

isc_uint64_t
isc_time_microdiff(isc_time_t *t1, isc_time_t *t2);
/*
 * Find the difference in milliseconds between time t1 and time t2.
 * t2 is the subtrahend of t1; ie, difference = t1 - t2.
 *
 * Requires:
 *	't1' and 't2' are valid pointers.
 */

isc_uint32_t
isc_time_seconds(isc_time_t *t);
/*
 * Return the number of seconds since the epoch stored in a time structure.
 *
 * Requires:
 *	't' is a valid pointer.
 */

isc_uint32_t
isc_time_nanoseconds(isc_time_t *t);
/*
 * Return the number of nanoseconds stored in a time structure.
 *
 * Notes:
 *	This is the number of nanoseconds in excess of the the number
 *	of seconds since the epoch; it will always be less than one
 *	full second.
 *
 * Requires:
 *	't' is a valid pointer.
 *
 * Ensures:
 *	The returned value is less than 1*10^9.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_TIME_H */
