/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef IN_1_KX_36_H
#define IN_1_KX_36_H 1

/* $Id: kx_36.h,v 1.20 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per RFC2230 */

typedef struct dns_rdata_in_kx {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint16_t		preference;
	dns_name_t		exchange;
} dns_rdata_in_kx_t;

#endif /* IN_1_KX_36_H */
