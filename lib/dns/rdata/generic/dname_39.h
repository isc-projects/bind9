/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_DNAME_39_H
#define GENERIC_DNAME_39_H 1

/* $Id: dname_39.h,v 1.21 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief per RFC2672 */

typedef struct dns_rdata_dname {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		dname;
} dns_rdata_dname_t;

#endif /* GENERIC_DNAME_39_H */
