
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <windows.h>

#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/time.h>

isc_result
isc_time_get(isc_time_t t) {
	/*
	 * Set *timep to the current absolute time (secs + nsec since
	 * January 1, 1970).
	 */
	
	REQUIRE(t != NULL);

	/* XXX No nanoseconds! */
	t->seconds = (unsigned long)time(NULL);
	t->nanoseconds = 0;
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
