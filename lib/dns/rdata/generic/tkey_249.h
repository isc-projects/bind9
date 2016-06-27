/*
 * Copyright (C) 1999-2001, 2003-2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_TKEY_249_H
#define GENERIC_TKEY_249_H 1

/* $Id: tkey_249.h,v 1.24 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per draft-ietf-dnsind-tkey-00.txt */

typedef struct dns_rdata_tkey {
	dns_rdatacommon_t	common;
	isc_mem_t *		mctx;
	dns_name_t		algorithm;
	isc_uint32_t		inception;
	isc_uint32_t		expire;
	isc_uint16_t		mode;
	isc_uint16_t		error;
	isc_uint16_t		keylen;
	unsigned char *		key;
	isc_uint16_t		otherlen;
	unsigned char *		other;
} dns_rdata_tkey_t;


#endif /* GENERIC_TKEY_249_H */
