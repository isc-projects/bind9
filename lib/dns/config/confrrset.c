/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: confrrset.c,v 1.16.4.1 2001/01/09 22:44:52 bwelling Exp $ */

#include <config.h>

#include <isc/mem.h>
#include <isc/util.h>

#include <dns/confrrset.h>

isc_result_t
dns_c_rrsolist_clear(dns_c_rrsolist_t *olist) {
	dns_c_rrso_t *elem;

	REQUIRE(DNS_C_RRSOLIST_VALID(olist));

	elem = ISC_LIST_HEAD(olist->elements);
	while (elem != NULL) {
		ISC_LIST_UNLINK(olist->elements, elem, next);
		dns_c_rrso_delete(&elem);
		elem = ISC_LIST_HEAD(olist->elements);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_rrsolist_append(dns_c_rrsolist_t *dest, dns_c_rrsolist_t *src) {
	dns_c_rrso_t *oldelem;
	dns_c_rrso_t *newelem;
	isc_result_t res;

	REQUIRE(DNS_C_RRSOLIST_VALID(dest));
	REQUIRE(DNS_C_RRSOLIST_VALID(src));

	oldelem = ISC_LIST_HEAD(src->elements);
	while (oldelem != NULL) {
		res = dns_c_rrso_copy(dest->mem, &newelem, oldelem);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}

		ISC_LIST_APPEND(dest->elements, newelem, next);
		oldelem = ISC_LIST_NEXT(oldelem, next);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_rrsolist_new(isc_mem_t *mem, dns_c_rrsolist_t **rval) {
	dns_c_rrsolist_t *ro;

	ro = isc_mem_get(mem, sizeof *ro);
	if (ro == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ISC_LIST_INIT(ro->elements);
	ro->mem = mem;
	ro->magic = DNS_C_RRSOLIST_MAGIC;

	*rval = ro;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_rrso_new(isc_mem_t *mem, dns_c_rrso_t **res, dns_rdataclass_t oclass,
	       dns_rdatatype_t otype, const char *name,
	       dns_c_ordering_t ordering)
{
	dns_c_rrso_t *newo;

	REQUIRE(mem != NULL);
	REQUIRE(res != NULL);

	if (name == NULL) {
		name = "*";
	}

	newo = isc_mem_get(mem, sizeof *newo);
	if (newo == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newo->magic = DNS_C_RRSO_MAGIC;
	newo->mem = mem;
	newo->otype = otype;
	newo->oclass = oclass;
	newo->ordering = ordering;
	ISC_LINK_INIT(newo, next);

	newo->name = isc_mem_strdup(mem, name);
	if (newo->name == NULL) {
		newo->magic = 0;
		isc_mem_put(mem, newo, sizeof *newo);
		return (ISC_R_NOMEMORY);
	}

	*res = newo;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_rrsolist_delete(dns_c_rrsolist_t **list) {
	dns_c_rrso_t *elem, *q;
	dns_c_rrsolist_t *l;
	isc_result_t r;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_RRSOLIST_VALID(*list));

	l = *list;

	elem = ISC_LIST_HEAD(l->elements);
	while (elem != NULL) {
		q = ISC_LIST_NEXT(elem, next);
		ISC_LIST_UNLINK(l->elements, elem, next);
		r = dns_c_rrso_delete(&elem);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}

		elem = q;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_rrso_delete(dns_c_rrso_t **order) {
	dns_c_rrso_t *oldo;

	REQUIRE(order != NULL);
	REQUIRE(DNS_C_RRSO_VALID(*order));

	oldo = *order;

	REQUIRE(oldo->name != NULL);
	isc_mem_free(oldo->mem, oldo->name);

	oldo->magic = 0;
	isc_mem_put(oldo->mem, oldo, sizeof *oldo);

	*order = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_rrso_copy(isc_mem_t *mem, dns_c_rrso_t **dest, dns_c_rrso_t *source) {
	dns_c_rrso_t *newo;
	isc_result_t res;

	REQUIRE(DNS_C_RRSO_VALID(*dest));
	REQUIRE(DNS_C_RRSO_VALID(source));

	res = dns_c_rrso_new(mem, &newo, source->oclass,
			     source->otype, source->name,
			     source->ordering);
	if (res == ISC_R_SUCCESS) {
		*dest = newo;
	} else {
		*dest = NULL;
	}

	return (res);
}

isc_result_t
dns_c_rrsolist_copy(isc_mem_t *mem, dns_c_rrsolist_t **dest,
		    dns_c_rrsolist_t *source)

{
	dns_c_rrsolist_t *nlist;
	dns_c_rrso_t *elem;
	dns_c_rrso_t *newe;
	isc_result_t res;

	REQUIRE(DNS_C_RRSOLIST_VALID(source));
	REQUIRE(dest != NULL);

	res = dns_c_rrsolist_new(mem, &nlist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	elem = ISC_LIST_HEAD(source->elements);
	while (elem != NULL) {
		res = dns_c_rrso_copy(mem, &newe, elem);
		if (res != ISC_R_SUCCESS) {
			dns_c_rrsolist_delete(&nlist);
			return (res);
		}

		ISC_LIST_APPEND(nlist->elements, newe, next);

		elem = ISC_LIST_NEXT(elem, next);
	}

	*dest = nlist;

	return (ISC_R_SUCCESS);
}

void
dns_c_rrsolist_print(FILE *fp, int indent, dns_c_rrsolist_t *rrlist) {
	dns_c_rrso_t *or;

	REQUIRE(DNS_C_RRSOLIST_VALID(rrlist));

	if (ISC_LIST_EMPTY(rrlist->elements)) {
		return;
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "rrset-order {\n");

	or = ISC_LIST_HEAD(rrlist->elements);
	while (or != NULL) {
		dns_c_rrso_print(fp, indent + 1, or);
		or = ISC_LIST_NEXT(or, next);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");

}

void
dns_c_rrso_print(FILE *fp, int indent, dns_c_rrso_t *order) {
	REQUIRE(DNS_C_RRSO_VALID(order));

	dns_c_printtabs(fp, indent);

	fputs("class ", fp);
	if (order->oclass == dns_rdataclass_any) {
		fputc('*', fp);
	} else {
		dns_c_dataclass_tostream(fp, order->oclass);
	}


	fputs(" type ", fp);
	if (order->otype == dns_rdatatype_any) {
		fputc('*', fp);
	} else {
		dns_c_datatype_tostream(fp, order->otype);
	}

	fprintf(fp, " name \"%s\"", order->name);

	fprintf(fp, " order %s",
		dns_c_ordering2string(order->ordering, ISC_TRUE));

	fputs(";\n", fp);
}
