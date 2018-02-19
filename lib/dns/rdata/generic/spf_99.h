/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2014, 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_SPF_99_H
#define GENERIC_SPF_99_H 1

/* $Id: spf_99.h,v 1.4 2007/06/19 23:47:17 tbox Exp $ */

typedef struct dns_rdata_spf_string {
		isc_uint8_t    length;
		unsigned char   *data;
} dns_rdata_spf_string_t;

typedef struct dns_rdata_spf {
	dns_rdatacommon_t       common;
	isc_mem_t               *mctx;
	unsigned char           *txt;
	isc_uint16_t            txt_len;
	/* private */
	isc_uint16_t            offset;
} dns_rdata_spf_t;

/*
 * ISC_LANG_BEGINDECLS and ISC_LANG_ENDDECLS are already done
 * via rdatastructpre.h and rdatastructsuf.h.
 */
#endif /* GENERIC_SPF_99_H */
