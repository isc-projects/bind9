
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <isc/assertions.h>
#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/time.h>

isc_result
os_time_get(os_time_t *timep) {
	struct timeval tv;

	/*
	 * Set *timep to the current absolute time (secs + nsec since
	 * January 1, 1970).
	 */
	
	REQUIRE(timep != NULL);
	
	if (gettimeofday(&tv, NULL) == -1) {
		UNEXPECTED_ERROR(__FILE__, __LINE__, strerror(errno));
		return (ISC_R_UNEXPECTED);
	}

	timep->seconds = tv.tv_sec;
	timep->nanoseconds = tv.tv_usec * 1000;

	return (ISC_R_SUCCESS);
}

int
os_time_compare(os_time_t *t1p, os_time_t *t2p) {
	/*
	 * Compare the times referenced by 't1p' and 't2p'
	 */

	REQUIRE(t1p != NULL && t2p != NULL);

	if (t1p->seconds < t2p->seconds)
		return (-1);
	if (t1p->seconds > t2p->seconds)
		return (1);
	if (t1p->nanoseconds < t2p->nanoseconds)
		return (-1);
	if (t1p->nanoseconds > t2p->nanoseconds)
		return (1);
	return (0);
}

void
os_time_add(os_time_t *t1p, os_time_t *t2p, os_time_t *t3p)
{
	/*
	 * Add 't1p' to 't2p', storing the result in 't3p'.
	 */

	REQUIRE(t1p != NULL && t2p != NULL && t3p != NULL);

	t3p->seconds = t1p->seconds + t2p->seconds;
	t3p->nanoseconds = t1p->nanoseconds + t2p->nanoseconds;
	if (t3p->nanoseconds > 1000000000) {
		t3p->seconds++;
		t3p->nanoseconds -= 1000000000;
	}
}

void
os_time_subtract(os_time_t *t1p, os_time_t *t2p, os_time_t *t3p) {
	/*
	 * Subtract 't2p' from 't1p', storing the result in 't1p'.
	 */

	REQUIRE(t1p != NULL && t2p != NULL && t3p != NULL);
	REQUIRE(os_time_compare(t1p, t2p) >= 0);
	
	t3p->seconds = t1p->seconds - t2p->seconds;
	if (t1p->nanoseconds >= t2p->nanoseconds)
		t3p->nanoseconds = t1p->nanoseconds - t2p->nanoseconds;
	else {
		t3p->nanoseconds = 1000000000 - t2p->nanoseconds +
			t1p->nanoseconds;
		t3p->seconds--;
	}
}
