
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/time.h>

isc_result
isc_time_get(isc_time_t timep) {
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
isc_time_compare(isc_time_t t1, isc_time_t t2) {
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
isc_time_add(isc_time_t t1, isc_time_t t2, isc_time_t t3)
{
	/*
	 * Add 't1' to 't2', storing the result in 't3'.
	 */

	REQUIRE(t1 != NULL && t2 != NULL && t3 != NULL);

	t3->seconds = t1->seconds + t2->seconds;
	t3->nanoseconds = t1->nanoseconds + t2->nanoseconds;
	if (t3->nanoseconds > 1000000000) {
		t3->seconds++;
		t3->nanoseconds -= 1000000000;
	}
}

void
isc_time_subtract(isc_time_t t1, isc_time_t t2, isc_time_t t3) {
	/*
	 * Subtract 't2' from 't1', storing the result in 't1'.
	 */

	REQUIRE(t1 != NULL && t2 != NULL && t3 != NULL);
	REQUIRE(isc_time_compare(t1, t2) >= 0);
	
	t3->seconds = t1->seconds - t2->seconds;
	if (t1->nanoseconds >= t2->nanoseconds)
		t3->nanoseconds = t1->nanoseconds - t2->nanoseconds;
	else {
		t3->nanoseconds = 1000000000 - t2->nanoseconds +
			t1->nanoseconds;
		t3->seconds--;
	}
}
