/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <isc/assertions.h>
#include <dns/conflsn.h>
#include <dns/confcommon.h>

#include "confpvt.h"


#define LISTEN_MAGIC		0x4c49534eU /* LISN */
#define LLIST_MAGIC		0x4c6c6973U /* Llis */
#define CHECK_LISTEN(l)		REQUIRE(DNS_C_VALID_STRUCT(l,LISTEN_MAGIC))
#define CHECK_LLIST(l)		REQUIRE(DNS_C_VALID_STRUCT(l,LLIST_MAGIC))


isc_result_t
dns_c_lstnon_new(isc_mem_t *mem, dns_c_lstnon_t **listen)
{
	dns_c_lstnon_t *ll;
	isc_result_t result;

	REQUIRE(listen != NULL);

	*listen = NULL;
	
	ll = isc_mem_get(mem, sizeof *ll);
	ll->mem = mem;
	ll->port = 0;
	ll->magic = LISTEN_MAGIC;

	result = dns_c_ipmatchlist_new(mem, &ll->iml);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mem, ll, sizeof *ll);
		return (result);
	}
	
	ISC_LINK_INIT(ll, next);

	*listen = ll;
		
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_lstnon_delete(dns_c_lstnon_t **listen)
{
	dns_c_lstnon_t *lo;
	isc_result_t r;

	REQUIRE(listen != NULL);

	lo = *listen;
	if (lo == NULL) {
		return (ISC_R_SUCCESS);
	}
	CHECK_LISTEN(lo);

	r = dns_c_ipmatchlist_delete(&lo->iml);
	if (r != ISC_R_SUCCESS) {
		return (r);
	}

	isc_mem_put(lo->mem, lo, sizeof *lo);

	*listen = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_lstnon_setiml(dns_c_lstnon_t *listen, dns_c_ipmatchlist_t *iml,
		     isc_boolean_t deepcopy)
{
	isc_result_t result;
	
	REQUIRE(listen != NULL);
	REQUIRE(iml != NULL);
	
	result = dns_c_ipmatchlist_delete(&listen->iml);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	if (deepcopy) {
		result = dns_c_ipmatchlist_copy(listen->mem,
						 &listen->iml, iml);
	} else {
		listen->iml = iml;
	}

	return (result);
}

	
		




isc_result_t
dns_c_lstnlist_new(isc_mem_t *mem, dns_c_lstnlist_t **llist)
{
	dns_c_lstnlist_t *ll;

	REQUIRE(llist != NULL);

	*llist = NULL;
	
	ll = isc_mem_get(mem, sizeof *ll);
	if (ll == NULL) {
		return  (ISC_R_NOMEMORY);
	}

	ll->mem = mem;
	ll->magic = LLIST_MAGIC;
	ISC_LIST_INIT(ll->elements);

	*llist = ll;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_lstnlist_delete(dns_c_lstnlist_t **llist)
{
	dns_c_lstnlist_t *ll;
	dns_c_lstnon_t *lo, *lotmp;
	isc_result_t r;

	REQUIRE(llist != NULL);

	ll = *llist;
	if (ll == NULL) {
		return (ISC_R_SUCCESS);
	}

	CHECK_LLIST(ll);

	lo = ISC_LIST_HEAD(ll->elements);
	while (lo != NULL) {
		lotmp = ISC_LIST_NEXT(lo, next);
		ISC_LIST_UNLINK(ll->elements, lo, next);
		r = dns_c_lstnon_delete(&lo);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}

		lo = lotmp;
	}

	isc_mem_put(ll->mem, ll, sizeof *ll);

	*llist = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_lstnlist_print(FILE *fp, int indent, dns_c_lstnlist_t *ll)
{
	dns_c_lstnon_t *lo;

	if (ll == NULL) {
		return (ISC_R_SUCCESS);
	}

	CHECK_LLIST(ll);
	
	lo = ISC_LIST_HEAD(ll->elements);
	while (lo != NULL) {
		dns_c_printtabs(fp, indent);
		dns_c_lstnon_print(fp, indent, lo);
		lo = ISC_LIST_NEXT(lo, next);
		fprintf(fp, "\n");
	}

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_lstnon_print(FILE *fp, int indent, dns_c_lstnon_t *lo)
{
	REQUIRE(lo != NULL);
	REQUIRE(lo->iml != NULL);
	CHECK_LISTEN(lo);
	
	fprintf(fp, "listen-on ");
	if (lo->port != htons(DNS_C_DEFAULTPORT)) {
		fprintf(fp, "port %d ", (int)ntohs(lo->port));
	}

	dns_c_ipmatchlist_print(fp, indent + 1, lo->iml);

	return (ISC_R_SUCCESS);
}

