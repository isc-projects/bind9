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

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <windows.h>

#include <isc/assertions.h>
#include <isc/time.h>

/*
 * struct FILETIME uses "100-nanoseconds intervals".
 * NS / S = 1000000000 (10^9).
 * While it is reasonably obvious that this makes the needed
 * conversion factor 10^7, it is coded this way for additional clarity.
 */
#define NS_PER_S 	1000000000
#define NS_INTERVAL	100
#define INTERVALS_PER_S (NS_PER_S / NS_INTERVAL)
#define UINT64_MAX	0xffffffffffffffffui64

/***
 *** Intervals
 ***/

static isc_interval_t zero_interval = { 0 };
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

	i->interval = (LONGLONG)seconds * INTERVALS_PER_S
		+ nanoseconds / NS_INTERVAL;
}

isc_boolean_t
isc_interval_iszero(isc_interval_t *i) {

	/*
	 * Returns ISC_TRUE iff. 'i' is the zero interval.
	 */

	REQUIRE(i != NULL);
	if (i->interval == 0)
		return (ISC_TRUE);

	return (ISC_FALSE);
}


/***
 *** Absolute Times
 ***/

static isc_time_t epoch = { 0, 0 };
isc_time_t *isc_time_epoch = &epoch;

void
isc_time_set(isc_time_t *t, unsigned int seconds, unsigned int nanoseconds) {
	ULARGE_INTEGER i;

	/*
	 * Set 't' to a particular number of seconds + nanoseconds since the
	 * epoch.
	 */
	REQUIRE(t != NULL);
	REQUIRE(nanoseconds < 1000000000);

	i.QuadPart = (LONGLONG)seconds * INTERVALS_PER_S
		+ nanoseconds / NS_INTERVAL;

	t->absolute.dwLowDateTime = i.LowPart;
	t->absolute.dwHighDateTime = i.HighPart;

}

void
isc_time_settoepoch(isc_time_t *t) {
	/*
	 * Set 't' to the time of the epoch.
	 */

	REQUIRE(t != NULL);

	t->absolute.dwLowDateTime = 0;
	t->absolute.dwHighDateTime = 0;
}

isc_boolean_t
isc_time_isepoch(isc_time_t *t) {
	/*
	 * Returns ISC_TRUE iff. 't' is the epoch ("time zero").
	 */

	REQUIRE(t != NULL);

	if (t->absolute.dwLowDateTime == 0 &&
	    t->absolute.dwHighDateTime == 0)
		return (ISC_TRUE);

	return (ISC_FALSE);
}

isc_result_t
isc_time_now(isc_time_t *t) {
	/*
	 * Set *t to the current absolute time.
	 */
	
	REQUIRE(t != NULL);

	GetSystemTimeAsFileTime(&t->absolute);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_time_nowplusinterval(isc_time_t *t, isc_interval_t *i) {
	ULARGE_INTEGER i1;

	/*
	 * Set *t to the current absolute time + i.
	 */
	
	REQUIRE(t != NULL);
	REQUIRE(i != NULL);
	
	GetSystemTimeAsFileTime(&t->absolute);

	i1.LowPart = t->absolute.dwLowDateTime;
	i1.HighPart = t->absolute.dwHighDateTime;

	if (UINT64_MAX - i1.QuadPart < i->interval)
		return (ISC_R_RANGE);

	i1.QuadPart += i->interval;

	t->absolute.dwLowDateTime  = i1.LowPart;
	t->absolute.dwHighDateTime = i1.HighPart;

	return (ISC_R_SUCCESS);
}

int
isc_time_compare(isc_time_t *t1, isc_time_t *t2) {
	/*
	 * Compare the times referenced by 't1' and 't2'
	 */

	REQUIRE(t1 != NULL && t2 != NULL);

	return ((int)CompareFileTime(&t1->absolute, &t2->absolute));
}

isc_result_t
isc_time_add(isc_time_t *t, isc_interval_t *i, isc_time_t *result) {
	ULARGE_INTEGER i1;

	/*
	 * Add 't' to 'i', storing the result in 'result'.
	 */

	REQUIRE(t != NULL && i != NULL && result != NULL);

	i1.LowPart = t->absolute.dwLowDateTime;
	i1.HighPart = t->absolute.dwHighDateTime;

	if (UINT64_MAX - i1.QuadPart < i->interval)
		return (ISC_R_RANGE);

	i1.QuadPart += i->interval;

	result->absolute.dwLowDateTime = i1.LowPart;
	result->absolute.dwHighDateTime = i1.HighPart;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_time_subtract(isc_time_t *t, isc_interval_t *i, isc_time_t *result) {
	ULARGE_INTEGER i1;

	/*
	 * Subtract 'i' from 't', storing the result in 'result'.
	 */

	REQUIRE(t != NULL && i != NULL && result != NULL);

	i1.LowPart = t->absolute.dwLowDateTime;
	i1.HighPart = t->absolute.dwHighDateTime;

	if (i.QuadPart < i->interval)
		return (ISC_R_RANGE);

	i1.QuadPart -= i->interval;

	result->absolute.dwLowDateTime = i1.LowPart;
	result->absolute.dwHighDateTime = i1.HighPart;
}

isc_uint64_t
isc_time_microdiff(isc_time_t *t1, isc_time_t *t2) {
	ULARGE_INTEGER i1, i2;
	LONGLONG i3;

	REQUIRE(t1 != NULL && t2 != NULL);

	i1.LowPart  = t1->absolute.dwLowDateTime;
	i1.HighPart = t1->absolute.dwHighDateTime;
	i2.LowPart  = t2->absolute.dwLowDateTime;
	i2.HighPart = t2->absolute.dwHighDateTime;

	if (i1.QuadPart <= i2.QuadPart)
		return (0);

	/*
	 * Convert to microseconds.
	 */
	i3 = (i1.QuadPart - i2.QuadPart) / 10;

	return (i3);
}

isc_uint32_t
isc_time_seconds(isc_time_t *t) {
	ULARGE_INTEGER i;

	REQUIRE(t != NULL);

	i.LowPart = t->absolute.dwLowDateTime;
	i.HighPart = t->absolute.dwHighDateTime;

	INSIST(i.QuadPart / INTERVALS_PER_S <= (isc_uint32_t)-1);

	return ((isc_uint32_t)(i.QuadPart / INTERVALS_PER_S));
}

isc_result_t
isc_time_secondsastimet(isc_time_t *t, time_t *secondsp) {
	ULARGE_INTEGER i1, i2;
	time_t seconds;

	REQUIRE(t != NULL);

	i1.LowPart = t->absolute.dwLowDateTime;
	i1.HighPart = t->absolute.dwHighDateTime;

	i1.QuadPart /= INTERVALS_PER_S;

	/*
	 * Ensure that the number of seconds can be represented by a time_t.
	 * Since the number seconds is an unsigned int and since time_t is
	 * mostly opaque, this is trickier than it seems.  (This standardized
	 * opaqueness of time_t is *very* * frustrating; time_t is not even
	 * limited to being an integral type.)  Thought it is known at the
	 * time of this writing that time_t is a signed long on the Win32
	 * platform, the full treatment is given to figuring out if things
	 * fit to allow for future Windows platforms where time_t is *not*
	 * a signed long, or where perhaps a signed long is longer than
	 * it currently is.
	 */
	seconds = (time_t)i1.QuadPart;

	/*
	 * First, only do the range tests if the type of size_t is integral.
	 * Float/double easily include the maximum possible values.
	 */
	if ((time_t)0.5 != 0.5) {
		/*
		 * Did all the bits make it in?
		 */
		if ((seconds & i1.QuadPart) != i1.QuadPart)
			return (ISC_R_RANGE);

		/*
		 * Is time_t signed with the high bit set?
		 *
		 * The first test (the sizeof comparison) determines
		 * whether we can even deduce the signedness of time_t
		 * by using ANSI's rule about integer conversion to
		 * wider integers.
		 *
		 * The second test uses that ANSI rule to see whether
		 * the value of time_t was sign extended into QuadPart.
		 * If the test is true, then time_t is signed.
		 *
		 * The final test ensures the high bit is not set, or
		 * the value is negative and hence there is a range error.
		 */
		if (sizeof(time_t) < sizeof(i2.QuadPart) &&
		    ((i2.QuadPart = (time_t)-1) ^ (time_t)-1) != 0 &&
		    (seconds & (1 << (sizeof(time_t) * 8 - 1))) != 0)
			return (ISC_R_RANGE);

		/*
		 * Last test ... the size of time_t is >= that of i2.QuadPart,
		 * so we can't determine its signedness.  Unconditionally
		 * declare anything with the high bit set as out of range.
		 * Since even the maxed signed value is ludicrously far from
		 * when this is being written, this rule shall not impact
		 * anything for all intents and purposes.
		 *
		 * How far?  Well ... if FILETIME is in 100 ns intervals since
		 * 1600, and a QuadPart can store 9223372036854775808 such
		 * intervals when interpreted as signed (ie, if sizeof(time_t)
		 * == sizeof(QuadPart) but time_t is signed), that means
		 * 9223372036854775808 / INTERVALS_PER_S = 922,337,203,685
		 * seconds.  That number divided by 60 * 60 * 24 * 365 seconds
		 * per year means a signed time_t can store at least 29,247
		 * years, with only 400 of those years used up since 1600 as I
		 * write this in May, 2000.
		 *
		 * (Real date calculations are of course incredibly more
		 * complex; I'm only describing the approximate scale of
		 * the numbers involved here.)
		 *
		 * If the Galactic Federation is still running libisc's time
		 * libray on a Windows platform in the year 27647 A.D., then
		 * feel free to hunt down my greatgreatgreatgreatgreat(etc)
		 * grandchildren and whine at them about what I did.
		 */
		if ((seconds & (1 << (sizeof(time_t) * 8 - 1))) != 0)
			return (ISC_R_RANGE);
	}

	*secondsp = seconds;

	return (ISC_R_SUCCESS);
}

isc_uint32_t
isc_time_nanoseconds(isc_time_t *t) {
	ULARGE_INTEGER i;

	REQUIRE(t != NULL);

	i.LowPart = t->absolute.dwLowDateTime;
	i.HighPart = t->absolute.dwHighDateTime;

	i.QuadPart -= isc_time_seconds(t);

	ENSURE(i.QuadPart * NS_INTERVAL < NS);

	return ((isc_uint32_t)(i.QuadPart * NS_INTERVAL));
}
