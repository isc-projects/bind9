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

#include <string.h>

#include <isc/types.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/rwlock.h>

#include <dns/types.h>
#include <dns/dbtable.h>
#include <dns/resolver.h>
#include <dns/view.h>

#include "../isc/util.h"		/* XXXRTH */

isc_result_t
dns_view_create(isc_mem_t *mctx, dns_rdataclass_t rdclass, char *name,
		dns_resolver_t *resolver, dns_view_t **viewp)
{
	dns_view_t *view;
	isc_result_t result;

	/*
	 * Create a view.
	 */

	REQUIRE(name != NULL);
	REQUIRE(viewp != NULL && *viewp == NULL);

	view = isc_mem_get(mctx, sizeof *view);
	if (view == NULL)
		return (ISC_R_NOMEMORY);
	view->name = isc_mem_strdup(mctx, name);
	if (view->name == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup_view;
	}
	result = isc_mutex_init(&view->lock);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_name;
	}
	view->dbtable = NULL;
	result = dns_dbtable_create(mctx, rdclass, &view->dbtable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "dns_dbtable_create() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_mutex;
	}
	view->resolver = NULL;
	if (resolver != NULL)
		dns_resolver_attach(resolver, &view->resolver);

	view->mctx = mctx;
	view->rdclass = rdclass;
	view->references = 1;
	view->magic = DNS_VIEW_MAGIC;
	
	*viewp = view;

	return (ISC_R_SUCCESS);

 cleanup_mutex:
	isc_mutex_destroy(&view->lock);

 cleanup_name:
	isc_mem_free(mctx, view->name);

 cleanup_view:
	isc_mem_put(mctx, view, sizeof *view);

	return (result);
}

void
dns_view_attach(dns_view_t *source, dns_view_t **targetp) {
	REQUIRE(DNS_VIEW_VALID(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	LOCK(&source->lock);

	INSIST(source->references > 0);
	source->references++;
	INSIST(source->references != 0);

	UNLOCK(&source->lock);

	*targetp = source;
}

static inline void
destroy(dns_view_t *view) {
	REQUIRE(!ISC_LINK_LINKED(view, link));

	if (view->resolver != NULL)
		dns_resolver_detach(&view->resolver);
	dns_dbtable_detach(&view->dbtable);
	isc_mutex_destroy(&view->lock);
	isc_mem_free(view->mctx, view->name);
	isc_mem_put(view->mctx, view, sizeof *view);
}

void
dns_view_detach(dns_view_t **viewp) {
	dns_view_t *view;
	isc_boolean_t need_destroy = ISC_FALSE;

	REQUIRE(viewp != NULL);
	view = *viewp;
	REQUIRE(DNS_VIEW_VALID(view));

	LOCK(&view->lock);

	INSIST(view->references > 0);
	view->references--;
	if (view->references == 0)
		need_destroy = ISC_TRUE;

	UNLOCK(&view->lock);

	*viewp = NULL;

	if (need_destroy)
		destroy(view);
}
