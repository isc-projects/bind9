/*
 * Copyright (C) 2003-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: sshfp_44.h,v 1.8 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per RFC 4255 */

#ifndef GENERIC_SSHFP_44_H
#define GENERIC_SSHFP_44_H 1

typedef struct dns_rdata_sshfp {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint8_t		algorithm;
	isc_uint8_t		digest_type;
	isc_uint16_t		length;
	unsigned char		*digest;
} dns_rdata_sshfp_t;

#endif /* GENERIC_SSHFP_44_H */
