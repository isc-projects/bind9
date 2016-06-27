/*
 * Copyright (C) 1999-2002, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_NXT_30_H
#define GENERIC_NXT_30_H 1

/* $Id: nxt_30.h,v 1.25 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief RFC2535 */

typedef struct dns_rdata_nxt {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		next;
	unsigned char		*typebits;
	isc_uint16_t		len;
} dns_rdata_nxt_t;

#endif /* GENERIC_NXT_30_H */
