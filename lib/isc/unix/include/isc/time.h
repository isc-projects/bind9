
#include <isc/result.h>

/* 
 * This structure can be used both to represent absolute times, and to
 * to represent intervals.
 */

typedef struct os_time_t {
	time_t	seconds;
	long	nanoseconds;
} os_time_t;

isc_result
os_time_get(os_time_t *timep);
/*
 * Set *timep to the current absolute time (secs + nsec since January 1, 1970).
 *
 * Requires:
 *
 *	'timep' is a valid pointer.
 *
 * Returns:
 *
 *	Success
 *	Unexpected error
 */

int
os_time_compare(os_time_t *t1p, os_time_t *t2p);
/*
 * Compare the times referenced by 't1p' and 't2p'
 *
 * Requires:
 *
 *	't1p' and 't2p' are a valid.
 *
 * Returns:
 *
 *	-1		*tp1 < *t2p
 *	0		*tp1 = *t2p
 *	1		*tp1 > *t2p
 */

void
os_time_add(os_time_t *t1p, os_time_t *t2p, os_time_t *t3p);
/*
 * Add 't1p' to 't2p', storing the result in 't3p'.
 *
 * Requires:
 *
 *	't1p', 't2p', and 't3p' are valid.
 */

void
os_time_subtract(os_time_t *t1p, os_time_t *t2p, os_time_t *t3p);
/*
 * Subtract 't2p' from 't1p', storing the result in 't3p'.
 *
 * Requires:
 *
 *	't1p', 't2p', and 't3p' are valid.
 *
 *	*tp1 >= *t2p
 */
