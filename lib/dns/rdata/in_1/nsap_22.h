/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef IN_1_NSAP_22_H
#define IN_1_NSAP_22_H 1

/* $Id: nsap_22.h,v 1.18 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per RFC1706 */

typedef struct dns_rdata_in_nsap {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	unsigned char		*nsap;
	isc_uint16_t		nsap_len;
} dns_rdata_in_nsap_t;

#endif /* IN_1_NSAP_22_H */
