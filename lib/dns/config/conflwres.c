/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: conflwres.c,v 1.2 2000/10/04 20:50:25 bwelling Exp $ */

#include <config.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/conflwres.h>
#include <dns/confcommon.h>
#include <dns/rdataclass.h>

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
		       dns_c_lwres_t *lwres, isc_boolean_t copy)
{
	dns_c_lwres_t *newe;
	isc_result_t res;

	REQUIRE(DNS_C_LWLIST_VALID(list));
	REQUIRE(DNS_C_LWRES_VALID(lwres));

	if (copy) {
		res = dns_c_lwres_copy(list->mem, &newe, lwres);
		if (res != ISC_R_SUCCESS) {
			return (res);
		}
	} else {
		newe = lwres;
	}

	ISC_LIST_APPEND(list->lwreslist, newe, next);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_lwreslist_copy(isc_mem_t *mem, dns_c_lwreslist_t **dest,
		     dns_c_lwreslist_t *src)
{
	dns_c_lwreslist_t *newlist;
	dns_c_lwres_t *lwres;
	isc_result_t res;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_LWLIST_VALID(src));

	res = dns_c_lwreslist_new(mem, &newlist);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	lwres = ISC_LIST_HEAD(src->lwreslist);
	while (lwres != NULL) {
		res = dns_c_lwreslist_append(newlist, lwres, ISC_TRUE);
		if (res != ISC_R_SUCCESS) {
			dns_c_lwreslist_delete(&newlist);
			return (res);
		}

		lwres = ISC_LIST_NEXT(lwres, next);
	}

	*dest = newlist;

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
	lwres->mem = NULL;

	ISC_LINK_INIT(lwres, next);

	isc_mem_put(mem, lwres, sizeof *lwres);

	*lwresp = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t dns_c_lwres_copy(isc_mem_t *mem, dns_c_lwres_t **dest,
			      dns_c_lwres_t *src)
{
	dns_c_lwres_t *newlwres;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_LWRES_VALID(src));

	newlwres = isc_mem_get(mem, sizeof *newlwres);
	if (newlwres == NULL) {
		return (ISC_R_NOMEMORY);
	}
	newlwres->magic = DNS_C_LWRES_MAGIC;
	newlwres->listeners = NULL;
	newlwres->view = NULL;

	if (src->view != NULL) {
		newlwres->view = isc_mem_strdup(mem, src->view);
		if (newlwres->view == NULL) {
			dns_c_lwres_delete(&newlwres);
			return (ISC_R_NOMEMORY);
		}
	}

	if (src->listeners != NULL)
		dns_c_iplist_attach(src->listeners, &newlwres->listeners);
	newlwres->viewclass = src->viewclass;

	*dest = newlwres;

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
			fprintf(fp, " %.*s", isc_buffer_usedlength(&b),
				(char *)isc_buffer_base(&b));
		}
		fprintf(fp, ";\n");
	}

	dns_c_printtabs(fp, indent);
	fprintf(fp, "};\n");
}
