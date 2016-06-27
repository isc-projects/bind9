/*
 * Copyright (C) 2006, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef IN_1_DHCID_49_H
#define IN_1_DHCID_49_H 1

/* $Id: dhcid_49.h,v 1.5 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_in_dhcid {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	unsigned char		*dhcid;
	unsigned int		length;
} dns_rdata_in_dhcid_t;

#endif /* IN_1_DHCID_49_H */
