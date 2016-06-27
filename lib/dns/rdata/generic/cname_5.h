/*
 * Copyright (C) 1998-2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: cname_5.h,v 1.26 2007/06/19 23:47:17 tbox Exp $ */

#ifndef GENERIC_CNAME_5_H
#define GENERIC_CNAME_5_H 1

typedef struct dns_rdata_cname {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		cname;
} dns_rdata_cname_t;

#endif /* GENERIC_CNAME_5_H */
