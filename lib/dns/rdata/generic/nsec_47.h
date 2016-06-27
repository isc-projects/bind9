/*
 * Copyright (C) 2003-2005, 2007, 2008, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_NSEC_47_H
#define GENERIC_NSEC_47_H 1

/* $Id: nsec_47.h,v 1.10 2008/07/15 23:47:21 tbox Exp $ */

/*!
 * \brief Per RFC 3845 */

typedef struct dns_rdata_nsec {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		next;
	unsigned char		*typebits;
	isc_uint16_t		len;
} dns_rdata_nsec_t;

#endif /* GENERIC_NSEC_47_H */
