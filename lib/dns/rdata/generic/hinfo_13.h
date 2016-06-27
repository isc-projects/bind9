/*
 * Copyright (C) 1998-2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_HINFO_13_H
#define GENERIC_HINFO_13_H 1

/* $Id: hinfo_13.h,v 1.25 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_hinfo {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	char			*cpu;
	char			*os;
	isc_uint8_t		cpu_len;
	isc_uint8_t		os_len;
} dns_rdata_hinfo_t;

#endif /* GENERIC_HINFO_13_H */
