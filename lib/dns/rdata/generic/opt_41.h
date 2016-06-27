/*
 * Copyright (C) 1998-2001, 2004, 2005, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef GENERIC_OPT_41_H
#define GENERIC_OPT_41_H 1

/* $Id: opt_41.h,v 1.18 2007/06/19 23:47:17 tbox Exp $ */

/*!
 *  \brief Per RFC2671 */

typedef struct dns_rdata_opt_opcode {
		isc_uint16_t	opcode;
		isc_uint16_t	length;
		unsigned char	*data;
} dns_rdata_opt_opcode_t;

typedef struct dns_rdata_opt {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	unsigned char		*options;
	isc_uint16_t		length;
	/* private */
	isc_uint16_t		offset;
} dns_rdata_opt_t;

/*
 * ISC_LANG_BEGINDECLS and ISC_LANG_ENDDECLS are already done
 * via rdatastructpre.h and rdatastructsuf.h.
 */

isc_result_t
dns_rdata_opt_first(dns_rdata_opt_t *);

isc_result_t
dns_rdata_opt_next(dns_rdata_opt_t *);

isc_result_t
dns_rdata_opt_current(dns_rdata_opt_t *, dns_rdata_opt_opcode_t *);

#endif /* GENERIC_OPT_41_H */
