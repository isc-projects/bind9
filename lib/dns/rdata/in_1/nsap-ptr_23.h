/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef IN_1_NSAP_PTR_23_H
#define IN_1_NSAP_PTR_23_H 1

/* $Id: nsap-ptr_23.h,v 1.19 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per RFC1348.  Obsoleted in RFC 1706 - use PTR instead. */

typedef struct dns_rdata_in_nsap_ptr {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		owner;
} dns_rdata_in_nsap_ptr_t;

#endif /* IN_1_NSAP_PTR_23_H */
