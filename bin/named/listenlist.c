/*
 * Copyright (C) 2000  Internet Software Consortium.
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
#include <isc/mem.h>
#include <isc/result.h>

#include <named/listenlist.h>

static void destroy(ns_listenlist_t *list);

static isc_result_t
ns_listenelt_create(isc_mem_t *mctx, in_port_t port,
		    dns_acl_t *acl, ns_listenelt_t **target)
{
	ns_listenelt_t *elt = NULL;
	REQUIRE(target != NULL && *target == NULL);
	elt = isc_mem_get(mctx, sizeof(*elt));
	if (elt == NULL)
		return (ISC_R_NOMEMORY);
	elt->mctx = mctx;
	ISC_LINK_INIT(elt, link);
	elt->port = port;
	elt->acl = acl;
	*target = elt;
	return (ISC_R_SUCCESS);
}

static void
ns_listenelt_destroy(ns_listenelt_t *elt) {
	if (elt->acl != NULL)
		dns_acl_detach(&elt->acl);
	isc_mem_put(elt->mctx, elt, sizeof(*elt));
}

static isc_result_t
ns_listenelt_fromconfig(dns_c_lstnon_t *celt, dns_c_ctx_t *cctx,
			 dns_aclconfctx_t *actx,
			 isc_mem_t *mctx, ns_listenelt_t **target)
{
	isc_result_t result;
	ns_listenelt_t *delt = NULL;
	REQUIRE(target != NULL && *target == NULL);
	result = ns_listenelt_create(mctx, celt->port, NULL, &delt);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_acl_fromconfig(celt->iml, cctx, actx, mctx, &delt->acl);
	if (result != DNS_R_SUCCESS) {
		ns_listenelt_destroy(delt);
		return (result);
	}
	*target = delt;
	return (ISC_R_SUCCESS);
}

static isc_result_t
ns_listenlist_create(isc_mem_t *mctx, ns_listenlist_t **target) {
	ns_listenlist_t *list = NULL;
	REQUIRE(target != NULL && *target == NULL);
	list = isc_mem_get(mctx, sizeof(*list));
	if (list == NULL)
		return (ISC_R_NOMEMORY);
	list->mctx = mctx;
	list->refcount = 1;
	ISC_LIST_INIT(list->elts);
	*target = list;
	return (ISC_R_SUCCESS);
}

isc_result_t
ns_listenlist_fromconfig(dns_c_lstnlist_t *clist, dns_c_ctx_t *cctx,
			  dns_aclconfctx_t *actx,
			  isc_mem_t *mctx, ns_listenlist_t **target)
{
	dns_c_lstnon_t *ce;
	isc_result_t result;
	ns_listenlist_t *dlist = NULL;
		
	REQUIRE(target != NULL && *target == NULL);

	result = ns_listenlist_create(mctx, &dlist);
	if (result != ISC_R_SUCCESS)
		return (result);
	
	for (ce = ISC_LIST_HEAD(clist->elements);
	     ce != NULL;
	     ce = ISC_LIST_NEXT(ce, next))
	{
		ns_listenelt_t *delt = NULL;
		result = ns_listenelt_fromconfig(ce, cctx, actx, mctx, &delt);
		if (result != DNS_R_SUCCESS)
			goto cleanup;
		ISC_LIST_APPEND(dlist->elts, delt, link);
	}
	*target = dlist;
	return (ISC_R_SUCCESS);

 cleanup:
	destroy(dlist);
	return (result);
}

static void
destroy(ns_listenlist_t *list) {
	ns_listenelt_t *elt, *next;
	for (elt = ISC_LIST_HEAD(list->elts);
	     elt != NULL;
	     elt = next)
	{
		next = ISC_LIST_NEXT(elt, link);
		ns_listenelt_destroy(elt);
	}
	isc_mem_put(list->mctx, list, sizeof(*list));	
}

void
ns_listenlist_attach(ns_listenlist_t *source, ns_listenlist_t **target)
{
	INSIST(source->refcount > 0);
	source->refcount++;
	*target = source;
}

void
ns_listenlist_detach(ns_listenlist_t **listp)
{
	ns_listenlist_t *list = *listp;
	INSIST(list->refcount > 0);
	list->refcount--;
	if (list->refcount == 0)
		destroy(list);
	*listp = NULL;
}

isc_result_t
ns_listenlist_default(isc_mem_t *mctx, in_port_t port,
		      ns_listenlist_t **target)
{
	isc_result_t result;
	dns_acl_t *acl = NULL;
	ns_listenelt_t *elt = NULL;
	ns_listenlist_t *list = NULL;

	REQUIRE(target != NULL && *target == NULL);	
	result = dns_acl_any(mctx, &acl);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	
	result = ns_listenelt_create(mctx, port, acl, &elt);
	if (result != ISC_R_SUCCESS)
		goto cleanup_acl;

	result = ns_listenlist_create(mctx, &list);
	if (result != ISC_R_SUCCESS)
		goto cleanup_listenelt;

	ISC_LIST_APPEND(list->elts, elt, link);

	*target = list;
	return (ISC_R_SUCCESS);

 cleanup_listenelt:
	ns_listenelt_destroy(elt);
 cleanup_acl:
	dns_acl_detach(&acl);
 cleanup:
	return (result);
}
