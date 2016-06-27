/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef IN_1_SRV_33_H
#define IN_1_SRV_33_H 1

/* $Id: srv_33.h,v 1.19 2007/06/19 23:47:17 tbox Exp $ */

/* Reviewed: Fri Mar 17 13:01:00 PST 2000 by bwelling */

/*!
 *  \brief Per RFC2782 */

typedef struct dns_rdata_in_srv {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint16_t		priority;
	isc_uint16_t		weight;
	isc_uint16_t		port;
	dns_name_t		target;
} dns_rdata_in_srv_t;

#endif /* IN_1_SRV_33_H */
