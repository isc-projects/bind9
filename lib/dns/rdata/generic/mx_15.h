/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef GENERIC_MX_15_H
#define GENERIC_MX_15_H 1

/* $Id: mx_15.h,v 1.29 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_mx {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint16_t		pref;
	dns_name_t		mx;
} dns_rdata_mx_t;

#endif /* GENERIC_MX_15_H */
