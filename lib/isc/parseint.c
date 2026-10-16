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
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#include <isc/overflow.h>
#include <isc/parseint.h>
#include <isc/result.h>
#include <isc/util.h>

isc_result_t
isc_parse_uint64(uint64_t *uip, const char *string, int base) {
	unsigned long long ui;
	char *endp = NULL;

	REQUIRE(uip != NULL && string != NULL);

	if (isalnum((unsigned char)string[0]) == 0 && string[0] != '+') {
		return ISC_R_BADNUMBER;
	}

	if (strtoll(string, NULL, base) < 0) {
		return ISC_R_BADNUMBER;
	}

	errno = 0;
	ui = strtoull(string, &endp, base);

	if (*endp != '\0') {
		return ISC_R_BADNUMBER;
	}

	switch (errno) {
	case 0:
		*uip = ui;
		return ISC_R_SUCCESS;
	case EINVAL:
		return ISC_R_BADNUMBER;
	case ERANGE:
		return ISC_R_RANGE;
	default:
		UNREACHABLE();
	}
}

isc_result_t
isc_parse_uint32(uint32_t *uip, const char *string, int base) {
	uint64_t val;

	RETERR(isc_parse_uint64(&val, string, base));
	if (val > UINT32_MAX) {
		return ISC_R_RANGE;
	}
	*uip = (uint32_t)val;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_uint16(uint16_t *uip, const char *string, int base) {
	uint64_t val;

	RETERR(isc_parse_uint64(&val, string, base));
	if (val > UINT16_MAX) {
		return ISC_R_RANGE;
	}
	*uip = (uint16_t)val;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_uint8(uint8_t *uip, const char *string, int base) {
	uint64_t val;

	RETERR(isc_parse_uint64(&val, string, base));
	if (val > UINT8_MAX) {
		return ISC_R_RANGE;
	}
	*uip = (uint8_t)val;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_int64(int64_t *ip, const char *string, int base) {
	long long i;
	char *endp;

	REQUIRE(ip != NULL && string != NULL);

	if (!isalnum((unsigned char)string[0]) && string[0] != '+' &&
	    string[0] != '-')
	{
		return ISC_R_BADNUMBER;
	}

	errno = 0;
	i = strtoll(string, &endp, base);

	if (*endp != '\0') {
		return ISC_R_BADNUMBER;
	}

	switch (errno) {
	case 0:
		*ip = i;
		return ISC_R_SUCCESS;
	case EINVAL:
		return ISC_R_BADNUMBER;
	case ERANGE:
		return ISC_R_RANGE;
	default:
		UNREACHABLE();
	}
}

isc_result_t
isc_parse_int32(int32_t *ip, const char *string, int base) {
	int64_t val;

	RETERR(isc_parse_int64(&val, string, base));
	if (val > INT32_MAX || val < INT32_MIN) {
		return ISC_R_RANGE;
	}
	*ip = (int32_t)val;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_int16(int16_t *ip, const char *string, int base) {
	int64_t val;

	RETERR(isc_parse_int64(&val, string, base));
	if (val > INT16_MAX || val < INT16_MIN) {
		return ISC_R_RANGE;
	}
	*ip = (int16_t)val;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_int8(int8_t *ip, const char *string, int base) {
	int64_t val;

	RETERR(isc_parse_int64(&val, string, base));
	if (val > INT8_MAX || val < INT8_MIN) {
		return ISC_R_RANGE;
	}
	*ip = (int8_t)val;
	return ISC_R_SUCCESS;
}
