/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef GENERIC_SOA_6_H
#define GENERIC_SOA_6_H 1

/* $Id: soa_6.h,v 1.32 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_soa {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		origin;
	dns_name_t		contact;
	isc_uint32_t		serial;		/*%< host order */
	isc_uint32_t		refresh;	/*%< host order */
	isc_uint32_t		retry;		/*%< host order */
	isc_uint32_t		expire;		/*%< host order */
	isc_uint32_t		minimum;	/*%< host order */
} dns_rdata_soa_t;


#endif /* GENERIC_SOA_6_H */
