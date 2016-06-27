/*
 * Copyright (C) 1999-2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef IN_1_WKS_11_H
#define IN_1_WKS_11_H 1

/* $Id: wks_11.h,v 1.22 2007/06/19 23:47:17 tbox Exp $ */

typedef	struct dns_rdata_in_wks {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	struct in_addr		in_addr;
	isc_uint16_t		protocol;
	unsigned char		*map;
	isc_uint16_t		map_len;
} dns_rdata_in_wks_t;

#endif /* IN_1_WKS_11_H */
