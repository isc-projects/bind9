/*
 * Copyright (C) 1998, 1999 Internet Software Consortium.
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

 /* $Id: soa_6.h,v 1.15 1999/05/05 01:55:11 marka Exp $ */

#ifndef RDATA_GENERIC_SOA_6_H
#define RDATA_GENERIC_SOA_6_H

typedef struct dns_rdata_soa {
	dns_rdataclass_t	rdclass;
	dns_rdatatype_t		rdtype;
	ISC_LINK(void)		link;
	isc_mem_t		*mctx;
	dns_fixedname_t		origin;
	dns_fixedname_t		mname;
	isc_uint32_t		serial;
	isc_uint32_t		refresh;
	isc_uint32_t		retry;
	isc_uint32_t		expire;
	isc_uint32_t		minimum;
} dns_rdata_soa_t;

#endif	/* RDATA_GENERIC_SOA_6_H */
