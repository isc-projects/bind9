/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <time.h>

#include <isc/region.h>
#include <isc/result.h>
#include <isc/serial.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/time.h>

static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

isc_result_t
dns_time64_totext(int64_t t, isc_buffer_t *target) {
	struct tm tm;
	char buf[sizeof("!!!!!!YYYY!!!!!!!!MM!!!!!!!!DD!!!!!!!!HH!!!!!!!!MM!!!!"
			"!!!!SS")];
	int secs;
	unsigned int l;
	isc_region_t region;

/*
 * Warning. Do NOT use arguments with side effects with these macros.
 */
#define is_leap(y)	 ((((y) % 4) == 0 && ((y) % 100) != 0) || ((y) % 400) == 0)
#define year_secs(y)	 ((is_leap(y) ? 366 : 365) * 86400)
#define month_secs(m, y) ((days[m] + ((m == 1 && is_leap(y)) ? 1 : 0)) * 86400)

	tm.tm_year = 70;
	while (t < 0) {
		if (tm.tm_year == 0) {
			return ISC_R_RANGE;
		}
		tm.tm_year--;
		secs = year_secs(tm.tm_year + 1900);
		t += secs;
	}
	while ((secs = year_secs(tm.tm_year + 1900)) <= t) {
		t -= secs;
		tm.tm_year++;
		if (tm.tm_year + 1900 > 9999) {
			return ISC_R_RANGE;
		}
	}
	tm.tm_mon = 0;
	while ((secs = month_secs(tm.tm_mon, tm.tm_year + 1900)) <= t) {
		t -= secs;
		tm.tm_mon++;
	}
	tm.tm_mday = 1;
	while (86400 <= t) {
		t -= 86400;
		tm.tm_mday++;
	}
	tm.tm_hour = 0;
	while (3600 <= t) {
		t -= 3600;
		tm.tm_hour++;
	}
	tm.tm_min = 0;
	while (60 <= t) {
		t -= 60;
		tm.tm_min++;
	}
	tm.tm_sec = (int)t;
	/* yyyy  mm  dd  HH  MM  SS */
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02d",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		 tm.tm_min, tm.tm_sec);

	isc_buffer_availableregion(target, &region);
	l = strlen(buf);

	if (l > region.length) {
		return ISC_R_NOSPACE;
	}

	memmove(region.base, buf, l);
	isc_buffer_add(target, l);
	return ISC_R_SUCCESS;
}

int64_t
dns_time64_from32(uint32_t value) {
	isc_stdtime_t now = isc_stdtime_now();
	int64_t start;
	int64_t t;

	/*
	 * Adjust the time to the closest epoch.  This should be changed
	 * to use a 64-bit counterpart to isc_stdtime_now() if one ever
	 * is defined, but even the current code is good until the year
	 * 2106.
	 */

	start = (int64_t)now;
	if (isc_serial_gt(value, now)) {
		t = start + (value - now);
	} else {
		t = start - (now - value);
	}

	return t;
}

isc_result_t
dns_time32_totext(uint32_t value, isc_buffer_t *target) {
	return dns_time64_totext(dns_time64_from32(value), target);
}

isc_result_t
dns_time64_fromtext(const char *source, int64_t *target) {
	int year, month, day, hour, minute, second;
	int64_t value;
	int secs;
	int i;

#define RANGE(min, max, value)                      \
	do {                                        \
		if (value < (min) || value > (max)) \
			return ((ISC_R_RANGE));     \
	} while (0)

	if (strlen(source) != 14U) {
		return DNS_R_SYNTAX;
	}
	/*
	 * Confirm the source only consists digits.  sscanf() allows some
	 * minor exceptions.
	 */
	for (i = 0; i < 14; i++) {
		if (!isdigit((unsigned char)source[i])) {
			return DNS_R_SYNTAX;
		}
	}
	if (sscanf(source, "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour,
		   &minute, &second) != 6)
	{
		return DNS_R_SYNTAX;
	}

	RANGE(0, 9999, year);
	RANGE(1, 12, month);
	RANGE(1, days[month - 1] + ((month == 2 && is_leap(year)) ? 1 : 0),
	      day);
#ifdef __COVERITY__
	/*
	 * Use a simplified range to silence Coverity warning (in
	 * arithmetic with day below).
	 */
	RANGE(1, 31, day);
#endif /* __COVERITY__ */

	RANGE(0, 23, hour);
	RANGE(0, 59, minute);
	RANGE(0, 60, second); /* 60 == leap second. */

	/*
	 * Calculate seconds from epoch.
	 * Note: this uses a idealized calendar.
	 */
	value = second + (60 * minute) + (3600 * hour) + ((day - 1) * 86400);
	for (i = 0; i < (month - 1); i++) {
		value += days[i] * 86400;
	}
	if (is_leap(year) && month > 2) {
		value += 86400;
	}
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

	*target = value;
	return ISC_R_SUCCESS;
}

isc_result_t
dns_time32_fromtext(const char *source, uint32_t *target) {
	int64_t value64;
	isc_result_t result;
	result = dns_time64_fromtext(source, &value64);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	*target = (uint32_t)value64;

	return ISC_R_SUCCESS;
}
