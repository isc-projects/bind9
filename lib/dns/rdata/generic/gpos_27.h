/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_GPOS_27_H
#define GENERIC_GPOS_27_H 1

/* $Id: gpos_27.h,v 1.17 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief per RFC1712 */

typedef struct dns_rdata_gpos {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	char			*longitude;
	char			*latitude;
	char			*altitude;
	isc_uint8_t		long_len;
	isc_uint8_t		lat_len;
	isc_uint8_t		alt_len;
} dns_rdata_gpos_t;

#endif /* GENERIC_GPOS_27_H */
