/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: sig_24.h,v 1.16 2000/03/17 17:07:10 gson Exp $ */

/* RFC 2535 */

typedef struct dns_rdata_generic_sig_t {
	dns_rdatacommon_t	common;
	isc_mem_t *		mctx;
	dns_rdatatype_t		covered;
	dns_secalg_t		algorithm;
	isc_uint8_t		labels;
	isc_uint32_t		originalttl;
	isc_uint32_t		timeexpire;
	isc_uint32_t		timesigned;
	isc_uint16_t		keyid;
        dns_name_t		signer;
	isc_uint16_t		siglen;
	unsigned char *		signature;
} dns_rdata_generic_sig_t;

