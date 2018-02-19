/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* */
#ifndef GENERIC_NS_2_H
#define GENERIC_NS_2_H 1

/* $Id: ns_2.h,v 1.27 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_ns {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		name;
} dns_rdata_ns_t;


#endif /* GENERIC_NS_2_H */
