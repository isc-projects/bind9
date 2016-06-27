/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* */
#ifndef HS_4_A_1_H
#define HS_4_A_1_H 1

/* $Id: a_1.h,v 1.12 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_hs_a {
	dns_rdatacommon_t	common;
	struct in_addr          in_addr;
} dns_rdata_hs_a_t;

#endif /* HS_4_A_1_H */
