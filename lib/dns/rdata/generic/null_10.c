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

 /* $Id: null_10.c,v 1.5 1999/01/22 05:02:47 marka Exp $ */

#ifndef RDATA_GENERIC_NULL_10_H
#define RDATA_GENERIC_NULL_10_H

static dns_result_t
fromtext_null(dns_rdataclass_t class, dns_rdatatype_t type,
	      isc_lex_t *lexer, dns_name_t *origin,
	      isc_boolean_t downcase, isc_buffer_t *target) {

	REQUIRE(type == 10);

	class = class;		/*unused*/
	type = type;		/*unused*/
	lexer = lexer;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/
	target = target;	/*unused*/

	return (DNS_R_SUCCESS);
}

static dns_result_t
totext_null(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	

	REQUIRE(rdata->type == 10);
	REQUIRE(rdata->length == 0);

	origin = origin;	/*unused*/
	target = target;	/*unused*/

	return (DNS_R_SUCCESS);
}

static dns_result_t
fromwire_null(dns_rdataclass_t class, dns_rdatatype_t type,
	      isc_buffer_t *source, dns_decompress_t *dctx,
	      isc_boolean_t downcase, isc_buffer_t *target) {

	REQUIRE(type == 10);

	class = class;		/*unused*/
	dctx = dctx;		/*unused*/
	downcase = downcase;	/*unused*/
	target = target;	/*unused*/
	source = source;	/*unused*/

	return (DNS_R_SUCCESS);
}

static dns_result_t
towire_null(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == 10);

	cctx = cctx;		/*unused*/
	target = target;	/*unused*/

	return (DNS_R_SUCCESS);
}

static int
compare_null(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {

	REQUIRE(rdata1->type == rdata1->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 10);

	return (0);
}

static dns_result_t
fromstruct_null(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == 10);

	class = class;	/*unused*/

	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_null(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 10);

	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_NULL_10_H */
