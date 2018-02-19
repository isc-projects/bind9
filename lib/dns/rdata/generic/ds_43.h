/*
 * Copyright (C) 2002, 2004, 2005, 2007, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: ds_43.h,v 1.7 2007/06/19 23:47:17 tbox Exp $ */

#ifndef GENERIC_DS_43_H
#define GENERIC_DS_43_H 1

/*!
 *  \brief per draft-ietf-dnsext-delegation-signer-05.txt */
typedef struct dns_rdata_ds {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint16_t		key_tag;
	isc_uint8_t		algorithm;
	isc_uint8_t		digest_type;
	isc_uint16_t		length;
	unsigned char		*digest;
} dns_rdata_ds_t;

#endif /* GENERIC_DS_43_H */
