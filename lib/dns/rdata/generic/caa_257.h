/*
 * Copyright (C) 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_CAA_257_H
#define GENERIC_CAA_257_H 1

/* $Id$ */

typedef struct dns_rdata_caa {
	dns_rdatacommon_t	common;
	isc_mem_t *		mctx;
	isc_uint8_t		flags;
	unsigned char *		tag;
	isc_uint8_t		tag_len;
	unsigned char		*value;
	isc_uint8_t		value_len;
} dns_rdata_caa_t;

#endif /* GENERIC_CAA_257_H */
