/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef GENERIC_PTR_12_H
#define GENERIC_PTR_12_H 1

/* $Id: ptr_12.h,v 1.27 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_ptr {
	dns_rdatacommon_t       common;
	isc_mem_t               *mctx;
	dns_name_t              ptr;
} dns_rdata_ptr_t;

#endif /* GENERIC_PTR_12_H */
