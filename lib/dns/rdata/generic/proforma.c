/*
 * Copyright (C) 1998 Internet Software Consortium.
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

 /* $Id: proforma.c,v 1.4 1999/01/20 05:20:23 marka Exp $ */

#ifndef RDATA_GENERIC_#_#_H
#define RDATA_GENERIC_#_#_H

static dns_result_t
fromtext_#(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_lex_t *lexer, dns_name_t *origin,
	   isc_boolean_t downcase, isc_buffer_t *target) {
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;

	REQUIRE(type == #);
	REQUIRE(class == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
totext_#(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->class == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
fromwire_#(dns_rdataclass_t class, dns_rdatatype_t type,
	   isc_buffer_t *source, dns_decompress_t *dctx,
	   isc_boolean_t downcase, isc_buffer_t *target) {

	REQUIRE(type == #);
	REQUIRE(class == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
towire_#(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->class == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static int
compare_#(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == #);
	REQUIRE(rdata1->class == #);

	return (-2);
}

static dns_result_t
fromstruct_#(dns_rdataclass_t class, dns_rdatatype_t type, void *source,
	     isc_buffer_t *target) {

	REQUIRE(type == #);
	REQUIRE(class == #);

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_#(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == #);
	REQUIRE(rdata->class == #);

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_#_#_H */
