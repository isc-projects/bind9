/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef GENERIC_OPT_41_H
#define GENERIC_OPT_41_H 1

/* $Id: opt_41.h,v 1.7 2000/05/24 05:09:28 tale Exp $ */

/* RFC 2671 */

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

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

isc_result_t
dns_rdata_opt_first(dns_rdata_opt_t *);

isc_result_t
dns_rdata_opt_next(dns_rdata_opt_t *);

isc_result_t
dns_rdata_opt_current(dns_rdata_opt_t *, dns_rdata_opt_opcode_t *);

ISC_LANG_ENDDECLS

#endif /* GENERIC_OPT_41_H */
