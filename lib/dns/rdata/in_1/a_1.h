/*
 * Copyright (C) 1998-1999 Internet Software Consortium.
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

 /* $Id: a_1.h,v 1.13 1999/05/05 01:55:12 marka Exp $ */

#ifndef RDATA_IN_1_A_1_H
#define RDATA_IN_1_A_1_H

typedef struct dns_rdata_in_a {
	dns_rdataclass_t	rdclass;	/* host order */
	dns_rdatatype_t		rdtype;		/* host order */
	ISC_LINK(void)		link;
	isc_mem_t		*mctx;
	isc_uint32_t            address;	/* network order */
} dns_rdata_in_a_t;

#endif RDATA_IN_1_A_1_H
