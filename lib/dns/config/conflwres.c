/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: conflwres.c,v 1.6.4.2 2001/01/22 20:12:31 bwelling Exp $ */

#include <config.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/conflwres.h>
#include <dns/confcommon.h>
#include <dns/rdataclass.h>

static isc_result_t
search_delete(dns_c_search_t **search);

isc_result_t
dns_c_lwreslist_new(isc_mem_t *mem, dns_c_lwreslist_t **list) {
	dns_c_lwreslist_t *newlist;

	REQUIRE(mem != NULL);
	REQUIRE(list != NULL);

	newlist = isc_mem_get(mem, sizeof *newlist);
	if (newlist == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newlist->mem = mem;
	newlist->magic = DNS_C_LWLIST_MAGIC;

	ISC_LIST_INIT(newlist->lwreslist);

	*list = newlist;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwreslist_delete(dns_c_lwreslist_t **list)
{
	dns_c_lwreslist_t *l;
	dns_c_lwres_t *lwres;
	isc_result_t res;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_LWLIST_VALID(*list));

	l = *list;

	while (!ISC_LIST_EMPTY(l->lwreslist)) {
		lwres = ISC_LIST_HEAD(l->lwreslist);
		ISC_LIST_UNLINK(l->lwreslist, lwres, next);
		res = dns_c_lwres_delete(&lwres);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwreslist_append(dns_c_lwreslist_t *list,
		       dns_c_lwres_t *lwres)
{
	REQUIRE(DNS_C_LWLIST_VALID(list));
	REQUIRE(DNS_C_LWRES_VALID(lwres));

	ISC_LIST_APPEND(list->lwreslist, lwres, next);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwreslist_addlwres(dns_c_lwreslist_t *list, dns_c_lwres_t *lwres) {
	REQUIRE(DNS_C_LWLIST_VALID(list));
	REQUIRE(DNS_C_LWRES_VALID(lwres));

	ISC_LIST_APPEND(list->lwreslist, lwres, next);

	return (ISC_R_SUCCESS);
}

dns_c_lwres_t *
dns_c_lwreslist_head (dns_c_lwreslist_t *list) {
	REQUIRE(DNS_C_LWLIST_VALID(list));

	return (ISC_LIST_HEAD(list->lwreslist));
}

dns_c_lwres_t *
dns_c_lwreslist_next(dns_c_lwres_t *lwres) {
	REQUIRE(DNS_C_LWRES_VALID(lwres));

	return (ISC_LIST_NEXT(lwres, next));
}


void
dns_c_lwreslist_print(FILE *fp, int indent, dns_c_lwreslist_t *list)
{
	dns_c_lwres_t *lwres;

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);
	if (list == NULL)
		return;
	else
		REQUIRE(DNS_C_LWLIST_VALID(list));

	lwres = ISC_LIST_HEAD(list->lwreslist);
	while (lwres != NULL) {
		dns_c_lwres_print(fp, indent, lwres);
		fprintf(fp, "\n");
		lwres = ISC_LIST_NEXT(lwres, next);
	}
}

isc_result_t
dns_c_lwres_new(isc_mem_t *mem, dns_c_lwres_t **lwresp)
{
	dns_c_lwres_t *lwres;

	REQUIRE(lwresp != NULL);

	lwres = isc_mem_get(mem, sizeof *lwres);
	if (lwres == NULL) {
		return (ISC_R_NOMEMORY);
	}

	lwres->magic = DNS_C_LWRES_MAGIC;
	lwres->mem = mem;

	lwres->listeners = NULL;
	lwres->view = NULL;
	lwres->viewclass = dns_rdataclass_in;
	lwres->searchlist = NULL;
	lwres->ndots = 1;
	lwres->ndotsset = ISC_FALSE;

	ISC_LINK_INIT(lwres, next);

	*lwresp = lwres;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_lwres_delete(dns_c_lwres_t **lwresp)
{
	dns_c_lwres_t *lwres;
	isc_mem_t *mem;

	REQUIRE(lwresp != NULL);
	REQUIRE(DNS_C_LWRES_VALID(*lwresp));

	lwres = *lwresp;

	mem = lwres->mem;

	lwres->magic = 0;
	if (lwres->view != NULL)
		isc_mem_free(mem, lwres->view);
	if (lwres->listeners != NULL)
		dns_c_iplist_detach(&lwres->listeners);
	if (lwres->searchlist != NULL)
		dns_c_searchlist_delete(&lwres->searchlist);
	lwres->mem = NULL;

	ISC_LINK_INIT(lwres, next);

	isc_mem_put(mem, lwres, sizeof *lwres);

	*lwresp = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwres_setlistenon(dns_c_lwres_t *lwres, dns_c_iplist_t *listeners) {
	if (lwres->listeners != NULL)
		return (ISC_R_EXISTS);
	dns_c_iplist_attach(listeners, &lwres->listeners);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwres_setview(dns_c_lwres_t *lwres, char *view,
		    dns_rdataclass_t rdclass)
{
	if (lwres->view != NULL)
		return (ISC_R_EXISTS);
	lwres->view = isc_mem_strdup(lwres->mem, view);
	if (lwres->view == NULL)
		return (ISC_R_NOMEMORY);
	lwres->viewclass = rdclass;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwres_setsearchlist(dns_c_lwres_t *lwres,
			  dns_c_searchlist_t *searchlist)
{
	if (lwres->searchlist != NULL)
		return (ISC_R_EXISTS);
	lwres->searchlist = searchlist;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwres_setndots(dns_c_lwres_t *lwres, unsigned int ndots) {
	if (lwres->ndotsset)
		return (ISC_R_EXISTS);
	lwres->ndots = ndots;
	lwres->ndotsset = ISC_TRUE;
	return (ISC_R_SUCCESS);
}

void
dns_c_lwres_print(FILE *fp, int indent, dns_c_lwres_t *lwres)
{
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_LWRES_VALID(lwres));

	dns_c_printtabs(fp, indent);
	fprintf(fp, "lwres {\n");

	if (lwres->listeners != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "listen-on ");
		dns_c_iplist_printfully(fp, indent + 2, ISC_TRUE,
					lwres->listeners);
	}

	if (lwres->view != NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "view \"%s\"", lwres->view);
		if (lwres->viewclass != dns_rdataclass_in) {
			char classtext[10];
			isc_buffer_t b;
			isc_buffer_init(&b, classtext, sizeof(classtext));
			(void)dns_rdataclass_totext(lwres->viewclass, &b);
			fprintf(fp, " %.*s", (int)isc_buffer_usedlength(&b),
				(char *)isc_buffer_base(&b));
		}
		fprintf(fp, ";\n");
	}

	if (lwres->searchlist != NULL) {
		dns_c_searchlist_print(fp, indent, lwres->searchlist);
		fprintf(fp, ";\n");
	}

	if (lwres->ndotsset) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "ndots %d;\n", lwres->ndots);
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}

isc_result_t
dns_c_searchlist_new(isc_mem_t *mem, dns_c_searchlist_t **list)
{
	dns_c_searchlist_t *l;

	l = isc_mem_get(mem, sizeof *l);
	if (l == NULL) {
		return (ISC_R_NOMEMORY);
	}

	l->magic = DNS_C_SEARCHLIST_MAGIC;
	l->mem = mem;
	ISC_LIST_INIT(l->searches);

	*list = l;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_searchlist_delete(dns_c_searchlist_t **list)
{
	dns_c_searchlist_t *l;
	dns_c_search_t *si, *tmpsi;
	isc_result_t r;

	REQUIRE(list != NULL);
	REQUIRE(DNS_C_SEARCHLIST_VALID(*list));

	l = *list;

	si = ISC_LIST_HEAD(l->searches);
	while (si != NULL) {
		tmpsi = ISC_LIST_NEXT(si, next);
		ISC_LIST_UNLINK(l->searches, si, next);
		r = search_delete(&si);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}
		si = tmpsi;
	}

	l->magic = 0;
	isc_mem_put(l->mem, l, sizeof *l);

	*list = NULL;

	return (ISC_R_SUCCESS);
}

static isc_result_t
search_delete(dns_c_search_t **search)
{
	dns_c_search_t *si;

	REQUIRE(search != NULL);
	REQUIRE(DNS_C_SEARCH_VALID(*search));

	si = *search;

	isc_mem_free(si->mem, si->search);

	si->magic = 0;
	isc_mem_put(si->mem, si, sizeof *si);

	*search = NULL;

	return (ISC_R_SUCCESS);
}

void
dns_c_searchlist_append(dns_c_searchlist_t *list, dns_c_search_t *search)
{
	REQUIRE(DNS_C_SEARCHLIST_VALID(list));
	REQUIRE(DNS_C_SEARCH_VALID(search));

	ISC_LIST_APPEND(list->searches, search, next);
}

void
dns_c_searchlist_print(FILE *fp, int indent,
		    dns_c_searchlist_t *list)
{
	dns_c_search_t *iter;

	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_SEARCHLIST_VALID(list));

	if (ISC_LIST_EMPTY(list->searches)) {
		return;
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "search {\n");
	iter = ISC_LIST_HEAD(list->searches);
	if (iter == NULL) {
		dns_c_printtabs(fp, indent + 1);
		fprintf(fp, "/* no search list defined */\n");
	} else {
		while (iter != NULL) {
			dns_c_printtabs(fp, indent + 1);
			fprintf(fp, "\"%s\";\n", iter->search);
			iter = ISC_LIST_NEXT(iter, next);
		}
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "}");
}

isc_result_t
dns_c_search_new(isc_mem_t *mem, const char *val, dns_c_search_t **search)
{
	dns_c_search_t *ki;

	REQUIRE(val != NULL);
	REQUIRE(search != NULL);

	ki = isc_mem_get(mem, sizeof *ki);
	if (ki == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ki->magic = DNS_C_SEARCH_MAGIC;
	ki->mem = mem;
	ki->search = isc_mem_strdup(mem, val);
	if (ki->search == NULL) {
		isc_mem_put(mem, ki, sizeof *ki);
		return (ISC_R_NOMEMORY);
	}

	ISC_LINK_INIT(ki, next);

	*search = ki;

	return (ISC_R_SUCCESS);
}

