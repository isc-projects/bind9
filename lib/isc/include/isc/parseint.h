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

#pragma once

#include <stdint.h>

#include <isc/types.h>

/*! \file isc/parseint.h
 * \brief Parse integers, in a saner way than atoi() or strtoul() do.
 */

/***
 ***	Functions
 ***/

#define isc_parse_unsigned_number(uip, string, base) \
	_Generic((uip),                              \
		uint64_t *: isc_parse_uint64,        \
		uint32_t *: isc_parse_uint32,        \
		uint16_t *: isc_parse_uint16,        \
		uint8_t *: isc_parse_uint8)((uip), (string), (base))

#define isc_parse_signed_number(ip, string, base) \
	_Generic((ip),                            \
		int64_t *: isc_parse_int64,       \
		int32_t *: isc_parse_int32,       \
		int16_t *: isc_parse_int16,       \
		int8_t *: isc_parse_int8)((ip), (string), (base))
/**
 *
 * Parse the null-terminated string 'string' containing a base 'base'
 * integer, storing the result in '*uip'.
 *
 * The base is interpreted as in strtoul().
 * Unlike strtoul(), leading whitespace is not accepted and all errors
 * (including overflow) are reported uniformly through the return value.
 *
 * Requires:
 *\li	'string' points to a null-terminated string
 *\li	0 <= 'base' <= 36
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_BADNUMBER   The string is not numeric (in the given base)
 *\li	#ISC_R_RANGE	  The number is not representable as the requested type.
 */

isc_result_t
isc_parse_uint64(uint64_t *uip, const char *string, int base);

isc_result_t
isc_parse_uint32(uint32_t *uip, const char *string, int base);

isc_result_t
isc_parse_uint16(uint16_t *uip, const char *string, int base);

isc_result_t
isc_parse_uint8(uint8_t *uip, const char *string, int base);

isc_result_t
isc_parse_int64(int64_t *ip, const char *string, int base);

isc_result_t
isc_parse_int32(int32_t *ip, const char *string, int base);

isc_result_t
isc_parse_int16(int16_t *ip, const char *string, int base);

isc_result_t
isc_parse_int8(int8_t *ip, const char *string, int base);
