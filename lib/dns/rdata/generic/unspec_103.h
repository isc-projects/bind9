/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef GENERIC_UNSPEC_103_H
#define GENERIC_UNSPEC_103_H 1

/* $Id: unspec_103.h,v 1.17 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_unspec_t {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	unsigned char		*data;
	isc_uint16_t		datalen;
} dns_rdata_unspec_t;

#endif /* GENERIC_UNSPEC_103_H */
