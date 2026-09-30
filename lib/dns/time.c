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

static int64_t
date_to_days(uint32_t year, uint32_t month, uint32_t day) {
	/*
	 * This is the Neri-Schneider calendar algorithm from "Euclidean affine
	 * functions and their application to calendar algorithms".
	 *
	 * Map January and February to the end of the preceding year.  Shift
	 * the calendar by one 400-year cycle so that dates in year zero can
	 * still be calculated using unsigned arithmetic.
	 */
	const uint32_t jan_feb = month <= 2U;
	const uint32_t y = year + 400U - jan_feb;
	const uint32_t m = month + 12U * jan_feb;
	const uint32_t century = y / 100U;
	const uint32_t days_to_year = 1461U * y / 4U - century + century / 4U;
	const uint32_t days_to_month = (979U * m - 2919U) / 32U;
	const uint32_t shifted_days = days_to_year + days_to_month + day - 1U;

	/*
	 * 719468 selects the Unix epoch; 146097 compensates for the 400-year
	 * shift above.
	 */
	return (int64_t)shifted_days - (719468LL + 146097LL);
}

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
#define is_leap(y)   ((((y) % 4) == 0 && ((y) % 100) != 0) || ((y) % 400) == 0)
#define year_secs(y) ((is_leap(y) ? 366 : 365) * 86400)
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

static isc_result_t
time64_fromtext(const char *source, size_t length, int64_t *target) {
	uint32_t digits[14];
	uint32_t year, month, day, hour, minute, second;
	uint32_t month_days;
	unsigned int i;

	if (length != ARRAY_SIZE(digits)) {
		return DNS_R_SYNTAX;
	}
	for (i = 0; i < ARRAY_SIZE(digits); i++) {
		digits[i] = (unsigned char)source[i] - (unsigned int)'0';
		if (digits[i] > 9U) {
			return DNS_R_SYNTAX;
		}
	}

	/* "YYYYxxxxxxxxxx" */
	year = digits[0] * 1000U + digits[1] * 100U + digits[2] * 10U +
	       digits[3];
	/* "xxxxMMxxxxxxxx" */
	month = digits[4] * 10U + digits[5];
	/* "xxxxxxDDxxxxxx" */
	day = digits[6] * 10U + digits[7];
	/* "xxxxxxxxHHxxxx" */
	hour = digits[8] * 10U + digits[9];
	/* "xxxxxxxxxxMMxx" */
	minute = digits[10] * 10U + digits[11];
	/* "xxxxxxxxxxxxSS" */
	second = digits[12] * 10U + digits[13];

	if (month - 1U >= ARRAY_SIZE(days)) {
		return ISC_R_RANGE;
	}
	month_days = days[month - 1U] +
		     ((month == 2U && is_leap(year)) ? 1U : 0U);
	if (day - 1U >= month_days || hour > 23U || minute > 59U ||
	    second > 60U) /* 60 == leap second. */
	{
		return ISC_R_RANGE;
	}

	*target = date_to_days(year, month, day) * 86400LL + hour * 3600U +
		  minute * 60U + second;
	return ISC_R_SUCCESS;
}

isc_result_t
dns_time64_fromregion(isc_textregion_t source, int64_t *target) {
	return time64_fromtext(source.base, source.length, target);
}

isc_result_t
dns_time64_fromtext(const char *source, int64_t *target) {
	return time64_fromtext(source, strlen(source), target);
}

isc_result_t
dns_time32_fromregion(isc_textregion_t source, uint32_t *target) {
	int64_t value64;

	RETERR(dns_time64_fromregion(source, &value64));
	*target = (uint32_t)value64;

	return ISC_R_SUCCESS;
}

isc_result_t
dns_time32_fromtext(const char *source, uint32_t *target) {
	int64_t value64;

	RETERR(dns_time64_fromtext(source, &value64));
	*target = (uint32_t)value64;

	return ISC_R_SUCCESS;
}
