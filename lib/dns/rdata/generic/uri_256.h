/*
 * Copyright (C) 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_URI_256_H
#define GENERIC_URI_256_H 1

/* $Id$ */

typedef struct dns_rdata_uri {
	dns_rdatacommon_t	common;
	isc_mem_t *		mctx;
	isc_uint16_t		priority;
	isc_uint16_t		weight;
	unsigned char *		target;
	isc_uint16_t		tgt_len;
} dns_rdata_uri_t;

#endif /* GENERIC_URI_256_H */
