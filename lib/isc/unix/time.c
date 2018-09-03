/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

#include <sys/time.h>	/* Required for struct timeval on some platforms. */

#include <isc/log.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/tm.h>
#include <isc/util.h>

#define NS_PER_S	1000000000	/*%< Nanoseconds per second. */
#define NS_PER_US	1000		/*%< Nanoseconds per microsecond. */
#define NS_PER_MS	1000000		/*%< Nanoseconds per millisecond. */
#define US_PER_S	1000000		/*%< Microseconds per second. */

/*
 * All of the INSIST()s checks of nanoseconds < NS_PER_S are for
 * consistency checking of the type. In lieu of magic numbers, it
 * is the best we've got.  The check is only performed on functions which
 * need an initialized type.
 */

#ifndef ISC_FIX_TV_USEC
#define ISC_FIX_TV_USEC 1
#endif

/*%
 *** Intervals
 ***/

static const isc_interval_t zero_interval = { 0, 0 };
const isc_interval_t * const isc_interval_zero = &zero_interval;

static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

#if ISC_FIX_TV_USEC
static inline void
fix_tv_usec(struct timeval *tv) {
	bool fixed = false;

	if (tv->tv_usec < 0) {
		fixed = true;
		do {
			tv->tv_sec -= 1;
			tv->tv_usec += US_PER_S;
		} while (tv->tv_usec < 0);
	} else if (tv->tv_usec >= US_PER_S) {
		fixed = true;
		do {
			tv->tv_sec += 1;
			tv->tv_usec -= US_PER_S;
		} while (tv->tv_usec >=US_PER_S);
	}
	/*
	 * Call syslog directly as was are called from the logging functions.
	 */
	if (fixed)
		(void)syslog(LOG_ERR, "gettimeofday returned bad tv_usec: corrected");
}
#endif

void
isc_interval_set(isc_interval_t *i,
		 unsigned int seconds, unsigned int nanoseconds)
{
	REQUIRE(i != NULL);
	REQUIRE(nanoseconds < NS_PER_S);

	i->seconds = seconds;
	i->nanoseconds = nanoseconds;
}

bool
isc_interval_iszero(const isc_interval_t *i) {
	REQUIRE(i != NULL);
	INSIST(i->nanoseconds < NS_PER_S);

	if (i->seconds == 0 && i->nanoseconds == 0)
		return (true);

	return (false);
}


/***
 *** Absolute Times
 ***/

static const isc_time_t epoch = { 0, 0 };
const isc_time_t * const isc_time_epoch = &epoch;

void
isc_time_set(isc_time_t *t, unsigned int seconds, unsigned int nanoseconds) {
	REQUIRE(t != NULL);
	REQUIRE(nanoseconds < NS_PER_S);

	t->seconds = seconds;
	t->nanoseconds = nanoseconds;
}

void
isc_time_settoepoch(isc_time_t *t) {
	REQUIRE(t != NULL);

	t->seconds = 0;
	t->nanoseconds = 0;
}

bool
isc_time_isepoch(const isc_time_t *t) {
	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);

	if (t->seconds == 0 && t->nanoseconds == 0)
		return (true);

	return (false);
}


isc_result_t
isc_time_now(isc_time_t *t) {
	struct timeval tv;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(t != NULL);

	if (gettimeofday(&tv, NULL) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__, "%s", strbuf);
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Does POSIX guarantee the signedness of tv_sec and tv_usec?  If not,
	 * then this test will generate warnings for platforms on which it is
	 * unsigned.  In any event, the chances of any of these problems
	 * happening are pretty much zero, but since the libisc library ensures
	 * certain things to be true ...
	 */
#if ISC_FIX_TV_USEC
	fix_tv_usec(&tv);
	if (tv.tv_sec < 0)
		return (ISC_R_UNEXPECTED);
#else
	if (tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= US_PER_S)
		return (ISC_R_UNEXPECTED);
#endif

	/*
	 * Ensure the tv_sec value fits in t->seconds.
	 */
	if (sizeof(tv.tv_sec) > sizeof(t->seconds) &&
	    ((tv.tv_sec | (unsigned int)-1) ^ (unsigned int)-1) != 0U)
		return (ISC_R_RANGE);

	t->seconds = tv.tv_sec;
	t->nanoseconds = tv.tv_usec * NS_PER_US;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_time_nowplusinterval(isc_time_t *t, const isc_interval_t *i) {
	struct timeval tv;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(t != NULL);
	REQUIRE(i != NULL);
	INSIST(i->nanoseconds < NS_PER_S);

	if (gettimeofday(&tv, NULL) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__, "%s", strbuf);
		return (ISC_R_UNEXPECTED);
	}

	/*
	 * Does POSIX guarantee the signedness of tv_sec and tv_usec?  If not,
	 * then this test will generate warnings for platforms on which it is
	 * unsigned.  In any event, the chances of any of these problems
	 * happening are pretty much zero, but since the libisc library ensures
	 * certain things to be true ...
	 */
#if ISC_FIX_TV_USEC
	fix_tv_usec(&tv);
	if (tv.tv_sec < 0)
		return (ISC_R_UNEXPECTED);
#else
	if (tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= US_PER_S)
		return (ISC_R_UNEXPECTED);
#endif

	/*
	 * Ensure the resulting seconds value fits in the size of an
	 * unsigned int.  (It is written this way as a slight optimization;
	 * note that even if both values == INT_MAX, then when added
	 * and getting another 1 added below the result is UINT_MAX.)
	 */
	if ((tv.tv_sec > INT_MAX || i->seconds > INT_MAX) &&
	    ((long long)tv.tv_sec + i->seconds > UINT_MAX))
		return (ISC_R_RANGE);

	t->seconds = tv.tv_sec + i->seconds;
	t->nanoseconds = tv.tv_usec * NS_PER_US + i->nanoseconds;
	if (t->nanoseconds >= NS_PER_S) {
		t->seconds++;
		t->nanoseconds -= NS_PER_S;
	}

	return (ISC_R_SUCCESS);
}

int
isc_time_compare(const isc_time_t *t1, const isc_time_t *t2) {
	REQUIRE(t1 != NULL && t2 != NULL);
	INSIST(t1->nanoseconds < NS_PER_S && t2->nanoseconds < NS_PER_S);

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

isc_result_t
isc_time_add(const isc_time_t *t, const isc_interval_t *i, isc_time_t *result)
{
	REQUIRE(t != NULL && i != NULL && result != NULL);
	INSIST(t->nanoseconds < NS_PER_S && i->nanoseconds < NS_PER_S);

	/*
	 * Ensure the resulting seconds value fits in the size of an
	 * unsigned int.  (It is written this way as a slight optimization;
	 * note that even if both values == INT_MAX, then when added
	 * and getting another 1 added below the result is UINT_MAX.)
	 */
	if ((t->seconds > INT_MAX || i->seconds > INT_MAX) &&
	    ((long long)t->seconds + i->seconds > UINT_MAX))
		return (ISC_R_RANGE);

	result->seconds = t->seconds + i->seconds;
	result->nanoseconds = t->nanoseconds + i->nanoseconds;
	if (result->nanoseconds >= NS_PER_S) {
		result->seconds++;
		result->nanoseconds -= NS_PER_S;
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_time_subtract(const isc_time_t *t, const isc_interval_t *i,
		  isc_time_t *result)
{
	REQUIRE(t != NULL && i != NULL && result != NULL);
	INSIST(t->nanoseconds < NS_PER_S && i->nanoseconds < NS_PER_S);

	if ((unsigned int)t->seconds < i->seconds ||
	    ((unsigned int)t->seconds == i->seconds &&
	     t->nanoseconds < i->nanoseconds))
	    return (ISC_R_RANGE);

	result->seconds = t->seconds - i->seconds;
	if (t->nanoseconds >= i->nanoseconds)
		result->nanoseconds = t->nanoseconds - i->nanoseconds;
	else {
		result->nanoseconds = NS_PER_S - i->nanoseconds +
			t->nanoseconds;
		result->seconds--;
	}

	return (ISC_R_SUCCESS);
}

uint64_t
isc_time_microdiff(const isc_time_t *t1, const isc_time_t *t2) {
	uint64_t i1, i2, i3;

	REQUIRE(t1 != NULL && t2 != NULL);
	INSIST(t1->nanoseconds < NS_PER_S && t2->nanoseconds < NS_PER_S);

	i1 = (uint64_t)t1->seconds * NS_PER_S + t1->nanoseconds;
	i2 = (uint64_t)t2->seconds * NS_PER_S + t2->nanoseconds;

	if (i1 <= i2)
		return (0);

	i3 = i1 - i2;

	/*
	 * Convert to microseconds.
	 */
	i3 /= NS_PER_US;

	return (i3);
}

uint32_t
isc_time_seconds(const isc_time_t *t) {
	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);

	return ((uint32_t)t->seconds);
}

isc_result_t
isc_time_secondsastimet(const isc_time_t *t, time_t *secondsp) {
	time_t seconds;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);

	/*
	 * Ensure that the number of seconds represented by t->seconds
	 * can be represented by a time_t.  Since t->seconds is an unsigned
	 * int and since time_t is mostly opaque, this is trickier than
	 * it seems.  (This standardized opaqueness of time_t is *very*
	 * frustrating; time_t is not even limited to being an integral
	 * type.)
	 *
	 * The mission, then, is to avoid generating any kind of warning
	 * about "signed versus unsigned" while trying to determine if the
	 * the unsigned int t->seconds is out range for tv_sec, which is
	 * pretty much only true if time_t is a signed integer of the same
	 * size as the return value of isc_time_seconds.
	 *
	 * If the paradox in the if clause below is true, t->seconds is out
	 * of range for time_t.
	 */
	seconds = (time_t)t->seconds;

	INSIST(sizeof(unsigned int) == sizeof(uint32_t));
	INSIST(sizeof(time_t) >= sizeof(uint32_t));

	if (t->seconds > (~0U>>1) && seconds <= (time_t)(~0U>>1))
		return (ISC_R_RANGE);

	*secondsp = seconds;

	return (ISC_R_SUCCESS);
}

uint32_t
isc_time_nanoseconds(const isc_time_t *t) {
	REQUIRE(t != NULL);

	ENSURE(t->nanoseconds < NS_PER_S);

	return ((uint32_t)t->nanoseconds);
}

void
isc_time_formattimestamp(const isc_time_t *t, char *buf, unsigned int len) {
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t) t->seconds;
	flen = strftime(buf, len, "%d-%b-%Y %X", localtime_r(&now, &tm));
	INSIST(flen < len);
	if (flen != 0)
		snprintf(buf + flen, len - flen,
			 ".%03u", t->nanoseconds / NS_PER_MS);
	else {
		strlcpy(buf, "99-Bad-9999 99:99:99.999", len);
	}
}

void
isc_time_formathttptimestamp(const isc_time_t *t, char *buf, unsigned int len) {
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	/*
	 * 5 spaces, 1 comma, 3 GMT, 2 %d, 4 %Y, 8 %H:%M:%S, 3+ %a, 3+ %b (29+)
	 */
	now = (time_t)t->seconds;
	flen = strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT",
			gmtime_r(&now, &tm));
	INSIST(flen < len);
}

isc_result_t
isc_time_parsehttptimestamp(char *buf, isc_time_t *t) {
	struct tm t_tm;
	time_t when;
	char *p;

	REQUIRE(buf != NULL);
	REQUIRE(t != NULL);

	p = isc_tm_strptime(buf, "%a, %d %b %Y %H:%M:%S", &t_tm);
	if (p == NULL)
		return (ISC_R_UNEXPECTED);
	when = isc_tm_timegm(&t_tm);
	if (when == -1)
		return (ISC_R_UNEXPECTED);
	isc_time_set(t, when, 0);
	return (ISC_R_SUCCESS);
}

void
isc_time_formatISO8601L(const isc_time_t *t, char *buf, unsigned int len) {
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t)t->seconds;
	flen = strftime(buf, len, "%Y-%m-%dT%H:%M:%S", localtime_r(&now, &tm));
	INSIST(flen < len);
}

void
isc_time_formatISO8601Lms(const isc_time_t *t, char *buf, unsigned int len) {
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t)t->seconds;
	flen = strftime(buf, len, "%Y-%m-%dT%H:%M:%S", localtime_r(&now, &tm));
	INSIST(flen < len);
	if (flen > 0U && len - flen >= 6) {
		snprintf(buf + flen, len - flen, ".%03u",
			 t->nanoseconds / NS_PER_MS);
	}
}

void
isc_time_formatISO8601(const isc_time_t *t, char *buf, unsigned int len) {
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t)t->seconds;
	flen = strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", gmtime_r(&now, &tm));
	INSIST(flen < len);
}

void
isc_time_formatISO8601ms(const isc_time_t *t, char *buf, unsigned int len) {
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t)t->seconds;
	flen = strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", gmtime_r(&now, &tm));
	INSIST(flen < len);
	if (flen > 0U && len - flen >= 5) {
		flen -= 1; /* rewind one character (Z) */
		snprintf(buf + flen, len - flen, ".%03uZ",
			 t->nanoseconds / NS_PER_MS);
	}
}

void
isc_time_formatshorttimestamp(const isc_time_t *t, char *buf, unsigned int len)
{
	time_t now;
	unsigned int flen;
	struct tm tm;

	REQUIRE(t != NULL);
	INSIST(t->nanoseconds < NS_PER_S);
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);

	now = (time_t)t->seconds;
	flen = strftime(buf, len, "%Y%m%d%H%M%S", gmtime_r(&now, &tm));
	INSIST(flen < len);
	if (flen > 0U && len - flen >= 5) {
		snprintf(buf + flen, len - flen, "%03u",
			 t->nanoseconds / NS_PER_MS);
	}
}

#define is_leap(y) ((((y) % 4) == 0 && ((y) % 100) != 0) || ((y) % 400) == 0)

#define RANGE(min, max, value) \
	do { \
		if (value < (min) || value > (max)) \
			return (ISC_R_RANGE); \
	} while (0)

isc_result_t
isc_time_ISO8601fromtext(isc_time_t *t, const char *str) {
	int year, month, day, hour, minute, second;
	int64_t value;
	unsigned int ns = 0;
	int secs;
	int i;
	const char *cp;

	if (strlen(str) < 20)
		return (ISC_R_BADTIME);
	/*
	 * Confirm the source digits are only digits.  sscanf() allows some
	 * minor exceptions.
	 */
	for (i = 0; i < 19; i++) {
		switch (i) {
		case 4:
		case 7:
			if (str[i] != '-') {
				return (ISC_R_BADTIME);
			}
			break;
		case 10:
			if (str[i] != 'T' && str[i] != 't') {
				return (ISC_R_BADTIME);
			}
			break;
		case 13:
		case 16:
			if (str[i] != ':') {
				return (ISC_R_BADTIME);
			}
			break;
		default:
			if (!isdigit((unsigned char)str[i]))
				return (ISC_R_BADTIME);
			break;
		}
	}
	if (sscanf(str, "%4d-%2d-%2d%*c%2d:%2d:%2d",
		   &year, &month, &day, &hour, &minute, &second) != 6) {
		return (ISC_R_BADTIME);
	}

	RANGE(0, 9999, year);
	RANGE(1, 12, month);
	RANGE(1, days[month - 1] +
		 ((month == 2 && is_leap(year)) ? 1 : 0), day);
#ifdef __COVERITY__
	/*
	 * Use a simplified range to silence Coverity warning (in
	 * arithmetic with day below).
	 */
	RANGE(1, 31, day);
#endif /* __COVERITY__ */

	RANGE(0, 23, hour);
	RANGE(0, 59, minute);
	RANGE(0, 60, second);           /* 60 == leap second. */

	/*
	 * Calculate seconds from epoch.
	 * Note: this uses a idealized calendar.
	 */
	value = second + (60 * minute) + (3600 * hour) + ((day - 1) * 86400);
	for (i = 0; i < (month - 1); i++)
		value += days[i] * 86400;
	if (is_leap(year) && month > 2)
		value += 86400;
	if (year < 1970) {
		for (i = 1969; i >= year; i--) {
			secs = (is_leap(i) ? 366 : 365) * 86400;
			value -= secs;
		}
	} else {
		for (i = 1970; i < year; i++) {
			secs = (is_leap(i) ? 366 : 365) * 86400;
			value += secs;
		}
	}

	/*
	 * Skip to fractions of seconds or time zone.
	 */
	cp = str + 19;

	/*
	 * Process fractions of seconds.
	 */
	if (*cp == '.') {
		int m = 100000000;	/* .1 in ns. */

		/*
		 * Skip decimal point.
		 */
		cp++;

		/*
		 * Process leading zeros.
		 */
		while (*cp == '0') {
			m /= 10;
			cp++;
		}

		/*
		 * Process any other digits.
		 */
		while (*cp >= '0' && *cp <= '9') {
			ns += (*cp - '0') * m;
			m /= 10;
			cp++;
		}
	}

	/*
	 * Process timezone offset which must exist.
	 */
	if (*cp == 'z' || *cp == 'Z') {
		/* empty */
	} else if (*cp == '-' || *cp == '+') {
		bool plus = (*cp++ == '+');
		if (strlen(cp) != 5) {
			return (ISC_R_BADTIME);
		}
		for (i = 0; i < 5; i++) {
			switch (i) {
			case 2:
				if (cp[i] != ':') {
					return (ISC_R_BADTIME);
				}
				break;
			default:
				if (!isdigit((unsigned char)cp[i]))
					return (ISC_R_BADTIME);
				break;
			}
		}
		if (sscanf(cp, "%2d:%2d", &hour, &minute) != 2) {
			return (ISC_R_BADTIME);
		}
		RANGE(0, 23, hour);
		RANGE(0, 59, minute);

		/*
		 * -00:00 is localtime which is not permitted.
		 */
		if (!plus && hour == 0 && minute == 0) {
			return (ISC_R_BADTIME);
		}

		/*
		 * '+' offsets are in front of UTC so they need to be
		 * subtracted.
		 */
		if (plus) {
			value -= hour * 3600 + minute * 60;
		} else {
			value += hour * 3600 + minute * 60;
		}
	} else {
		return (ISC_R_BADTIME);
	}

	if (value < 0)
		return (ISC_R_BADTIME);

	t->seconds = value;
	t->nanoseconds = ns;
	return (ISC_R_SUCCESS);
}
