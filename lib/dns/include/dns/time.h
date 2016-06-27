/*
 * Copyright (C) 1999-2001, 2004-2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: time.h,v 1.19 2012/01/27 23:46:58 tbox Exp $ */

#ifndef DNS_TIME_H
#define DNS_TIME_H 1

/*! \file dns/time.h */

/***
 ***	Imports
 ***/

#include <isc/buffer.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

/***
 ***	Functions
 ***/

isc_result_t
dns_time64_fromtext(const char *source, isc_int64_t *target);
/*%<
 * Convert a date and time in YYYYMMDDHHMMSS text format at 'source'
 * into to a 64-bit count of seconds since Jan 1 1970 0:00 GMT.
 * Store the count at 'target'.
 */

isc_result_t
dns_time32_fromtext(const char *source, isc_uint32_t *target);
/*%<
 * Like dns_time64_fromtext, but returns the second count modulo 2^32
 * as per RFC2535.
 */


isc_result_t
dns_time64_totext(isc_int64_t value, isc_buffer_t *target);
/*%<
 * Convert a 64-bit count of seconds since Jan 1 1970 0:00 GMT into
 * a YYYYMMDDHHMMSS text representation and append it to 'target'.
 */

isc_result_t
dns_time32_totext(isc_uint32_t value, isc_buffer_t *target);
/*%<
 * Like dns_time64_totext, but for a 32-bit cyclic time value.
 * Of those dates whose counts of seconds since Jan 1 1970 0:00 GMT
 * are congruent with 'value' modulo 2^32, the one closest to the
 * current date is chosen.
 */

isc_int64_t
dns_time64_from32(isc_uint32_t value);
/*%<
 * Covert a 32-bit cyclic time value into a 64 bit time stamp.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_TIME_H */
