/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* */
#ifndef GENERIC_MG_8_H
#define GENERIC_MG_8_H 1

/* $Id: mg_8.h,v 1.26 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_mg {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		mg;
} dns_rdata_mg_t;

#endif /* GENERIC_MG_8_H */
