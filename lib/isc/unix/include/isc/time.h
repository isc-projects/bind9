
#ifndef ISC_TIME_H
#define ISC_TIME_H 1

#include <time.h>
#include <isc/result.h>

/* 
 * This structure can be used both to represent absolute times, and to
 * to represent intervals.
 */

typedef struct isc_time {
	time_t	seconds;
	long	nanoseconds;
} *isc_time_t;

isc_result_t
isc_time_get(isc_time_t t);
/*
 * Set 't' to the current absolute time (secs + nsec since January 1, 1970).
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

int
isc_time_compare(isc_time_t t1, isc_time_t t2);
/*
 * Compare the times referenced by 't1' and 't2'
 *
 * Requires:
 *
 *	't1' and 't2' are a valid.
 *
 * Returns:
 *
 *	-1		t1 < t2		(comparing times, not pointers)
 *	0		t1 = t2
 *	1		t1 > t2
 */

void
isc_time_add(isc_time_t t1, isc_time_t t2, isc_time_t t3);
/*
 * Add 't1' to 't2', storing the result in 't3'.
 *
 * Requires:
 *
 *	't1', 't2', and 't3' are valid.
 */

void
isc_time_subtract(isc_time_t t1, isc_time_t t2, isc_time_t t3);
/*
 * Subtract 't2' from 't1', storing the result in 't3'.
 *
 * Requires:
 *
 *	't1', 't2', and 't3' are valid.
 *
 *	t1 >= t2			(comparing times, not pointers)
 */

#endif /* ISC_TIME_H */
