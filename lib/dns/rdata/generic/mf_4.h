/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef GENERIC_MF_4_H
#define GENERIC_MF_4_H 1

/* $Id: mf_4.h,v 1.26 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_mf {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		mf;
} dns_rdata_mf_t;

#endif /* GENERIC_MF_4_H */
