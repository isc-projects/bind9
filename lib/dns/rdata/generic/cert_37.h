/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: cert_37.h,v 1.20 2007/06/19 23:47:17 tbox Exp $ */

#ifndef GENERIC_CERT_37_H
#define GENERIC_CERT_37_H 1

/*% RFC2538 */
typedef struct dns_rdata_cert {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint16_t		type;
	isc_uint16_t		key_tag;
	isc_uint8_t		algorithm;
	isc_uint16_t		length;
	unsigned char		*certificate;
} dns_rdata_cert_t;

#endif /* GENERIC_CERT_37_H */
