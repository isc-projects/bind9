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
#ifndef GENERIC_PROFORMA_H
#define GENERIC_PROFORMA_H 1

/* $Id: proforma.h,v 1.23 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_# {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;	/* if required */
	/* type & class specific elements */
} dns_rdata_#_t;

#endif /* GENERIC_PROFORMA_H */
