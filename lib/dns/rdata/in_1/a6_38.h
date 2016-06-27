/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef IN_1_A6_38_H
#define IN_1_A6_38_H 1

/* $Id: a6_38.h,v 1.24 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per RFC2874 */

typedef struct dns_rdata_in_a6 {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		prefix;
	isc_uint8_t		prefixlen;
	struct in6_addr		in6_addr;
} dns_rdata_in_a6_t;

#endif /* IN_1_A6_38_H */
