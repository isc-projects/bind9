
#include <sys/time.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <isc/assertions.h>
#include <isc/unexpect.h>
#include <isc/time.h>

/***
 *** Intervals
 ***/

void
isc_interval_set(isc_interval_t i,
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
isc_interval_iszero(isc_interval_t i) {

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

void
isc_time_settoepoch(isc_time_t t) {
	/*
	 * Set 't' to the time of the epoch.
	 */

	REQUIRE(t != NULL);

	t->seconds = 0;
	t->nanoseconds = 0;
}

isc_boolean_t
isc_time_isepoch(isc_time_t t) {

	/*
	 * Returns ISC_TRUE iff. 't' is the epoch ("time zero").
	 */

	REQUIRE(t != NULL);

	if (t->seconds == 0 && t->nanoseconds == 0)
		return (ISC_TRUE);

	return (ISC_FALSE);
}

isc_result_t
isc_time_get(isc_time_t t) {
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
isc_time_add(isc_time_t t, isc_interval_t i, isc_time_t result)
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
isc_time_subtract(isc_time_t t, isc_interval_t i, isc_time_t result) {
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


/***
 *** UNIX-only
 ***/


void
isc_time_fromtimeval(isc_time_t t, struct timeval *tv) {

	/*
	 * Set 't' to the time given by 'ts'.
	 */

	REQUIRE(t != NULL && tv != NULL);

	t->seconds = tv->tv_sec;
	t->nanoseconds = tv->tv_usec * 1000;
}

void
isc_time_totimeval(isc_time_t t, struct timeval *tv) {

	/*
	 * Convert 't' to a UNIX timeval.
	 */

	REQUIRE(t != NULL && tv != NULL);

	tv->tv_sec = t->seconds;
	tv->tv_usec = t->nanoseconds / 1000;
}

void
isc_time_fromtimespec(isc_time_t t, struct timespec *ts) {

	/*
	 * Set 't' to the time given by 'ts'.
	 */

	REQUIRE(t != NULL && ts != NULL);

	t->seconds = ts->tv_sec;
	t->nanoseconds = ts->tv_nsec;
}

void
isc_time_totimespec(isc_time_t t, struct timespec *ts) {

	/*
	 * Convert 't' to a UNIX timespec.
	 */

	REQUIRE(t != NULL && ts != NULL);

	ts->tv_sec = t->seconds;
	ts->tv_nsec = t->nanoseconds;
}
