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

#include <dns/types.h>
#include <dns/dbtable.h>
#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/rbt.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/view.h>

#include "../isc/util.h"		/* XXXRTH */

isc_result_t
dns_view_create(isc_mem_t *mctx, dns_rdataclass_t rdclass,
		const char *name, dns_view_t **viewp)
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
	view->zonetable = NULL;
	result = dns_zt_create(mctx, rdclass, &view->zonetable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "dns_zt_create() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_mutex;
	}
	view->secroots = NULL;
	result = dns_rbt_create(mctx, NULL, NULL, &view->secroots);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "dns_rbt_create() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_zt;
	}

	view->cachedb = NULL;
	view->hints = NULL;
	view->resolver = NULL;
	view->mctx = mctx;
	view->rdclass = rdclass;
	view->frozen = ISC_FALSE;
	view->references = 1;
	ISC_LINK_INIT(view, link);
	view->magic = DNS_VIEW_MAGIC;
	
	*viewp = view;

	return (ISC_R_SUCCESS);

 cleanup_zt:
	dns_zt_detach(&view->zonetable);

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

	/*
	 * Attach '*targetp' to 'source'.
	 */

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
	if (view->hints != NULL)
		dns_db_detach(&view->hints);
	if (view->cachedb != NULL)
		dns_db_detach(&view->cachedb);
	dns_zt_detach(&view->zonetable);
	dns_rbt_destroy(&view->secroots);
	isc_mutex_destroy(&view->lock);
	isc_mem_free(view->mctx, view->name);
	isc_mem_put(view->mctx, view, sizeof *view);
}

void
dns_view_detach(dns_view_t **viewp) {
	dns_view_t *view;
	isc_boolean_t need_destroy = ISC_FALSE;

	/*
	 * Detach '*viewp' from its view.
	 */

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

isc_result_t
dns_view_createresolver(dns_view_t *view,
			isc_taskmgr_t *taskmgr, unsigned int ntasks,
			isc_socketmgr_t *socketmgr,
			isc_timermgr_t *timermgr,
			dns_dispatch_t *dispatch)
{
	/*
	 * Create a resolver for the view.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);
	REQUIRE(view->resolver == NULL);
	
	return (dns_resolver_create(view, taskmgr, ntasks, socketmgr,
				    timermgr, dispatch, &view->resolver));
}

void
dns_view_setcachedb(dns_view_t *view, dns_db_t *cachedb) {

	/*
	 * Set the view's cache database.
	 */

	/*
	 * WARNING!  THIS ROUTINE WILL BE REPLACED WITH dns_view_setcache()
	 * WHEN WE HAVE INTEGRATED CACHE OBJECT SUPPORT INTO THE LIBRARY.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);
	REQUIRE(view->cachedb == NULL);
	REQUIRE(dns_db_iscache(cachedb));

	dns_db_attach(cachedb, &view->cachedb);
}

void
dns_view_sethints(dns_view_t *view, dns_db_t *hints) {

	/*
	 * Set the view's hints database.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);
	REQUIRE(view->hints == NULL);
	REQUIRE(dns_db_iszone(hints));

	dns_db_attach(hints, &view->hints);
}

isc_result_t
dns_view_addzone(dns_view_t *view, dns_zone_t *zone) {
	isc_result_t result;

	/*
	 * Add zone 'zone' to 'view'.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);

	result = dns_zt_mount(view->zonetable, zone);

	return (result);
}

void
dns_view_freeze(dns_view_t *view) {
	
	/*
	 * Freeze view.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);

	view->frozen = ISC_TRUE;
}

isc_result_t
dns_view_findzone(dns_view_t *view, dns_name_t *name, dns_zone_t **zone) {
	isc_result_t result;
	dns_zone_t *dummy = NULL;

	REQUIRE(DNS_VIEW_VALID(view));

	result = dns_zt_find(view->zonetable, name, NULL, &dummy);
	if (result == DNS_R_PARTIALMATCH) {
		dns_zone_detach(&dummy);
		result = DNS_R_NOTFOUND;
	} else if (result == DNS_R_SUCCESS) {
		dns_zone_attach(dummy, zone);
		dns_zone_detach(&dummy);
	}
	return (result);
}

isc_result_t
dns_view_find(dns_view_t *view, dns_name_t *name, dns_rdatatype_t type,
	      isc_stdtime_t now, unsigned int options, isc_boolean_t use_hints,
	      dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	isc_result_t result;
	dns_fixedname_t foundname;
	dns_db_t *db;
	dns_dbversion_t *version;
	isc_boolean_t is_zone;
	dns_rdataset_t zrdataset, zsigrdataset;
	dns_zone_t *zone;

	/*
	 * Find an rdataset whose owner name is 'name', and whose type is
	 * 'type'.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(view->frozen);
	REQUIRE(type != dns_rdatatype_any && type != dns_rdatatype_sig);

	/*
	 * Initialize.
	 */
	dns_rdataset_init(&zrdataset);
	dns_rdataset_init(&zsigrdataset);

	/*
	 * Find a database to answer the query.
	 */
	zone = NULL;
	db = NULL;
	result = dns_zt_find(view->zonetable, name, NULL, &zone);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		result = dns_zone_getdb(zone, &db);
		if (result != DNS_R_SUCCESS && view->cachedb != NULL)
			dns_db_attach(view->cachedb, &db);
		else if (result != DNS_R_SUCCESS)
			goto cleanup;
	} else if (result == ISC_R_NOTFOUND && view->cachedb != NULL)
		dns_db_attach(view->cachedb, &db);
	else
		goto cleanup;

	is_zone = dns_db_iszone(db);

 db_find:
	/*
	 * Now look for an answer in the database.
	 */
	dns_fixedname_init(&foundname);
	result = dns_db_find(db, name, NULL, type, options,
			     now, NULL, dns_fixedname_name(&foundname),
			     rdataset, sigrdataset);

	if (result == DNS_R_DELEGATION ||
	    result == DNS_R_NOTFOUND ||
	    result == DNS_R_NXGLUE) {
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		if (sigrdataset != NULL && sigrdataset->methods != NULL)
			dns_rdataset_disassociate(sigrdataset);
		if (is_zone) {
			if (view->cachedb != NULL) {
				/*
				 * Either the answer is in the cache, or we
				 * don't know it.
				 */
				is_zone = ISC_FALSE;
				version = NULL;
				dns_db_detach(&db);
				dns_db_attach(view->cachedb, &db);
				goto db_find;
			}
		} else {
			/*
			 * We don't have the data in the cache.  If we've got
			 * glue from the zone, use it.
			 */
			if (zrdataset.methods != NULL) {
				dns_rdataset_clone(&zrdataset, rdataset);
				if (zsigrdataset.methods != NULL)
					dns_rdataset_clone(&zsigrdataset,
							   sigrdataset);
				result = DNS_R_GLUE;
				goto cleanup;
			}
		}
		/*
		 * We don't know the answer.
		 */
		result = DNS_R_NOTFOUND;
	} else if (result == DNS_R_GLUE) {
		if (view->cachedb != NULL) {
			/*
			 * We found an answer, but the cache may be better.
			 * Remember what we've got and go look in the cache.
			 */
			is_zone = ISC_FALSE;
			version = NULL;
			dns_rdataset_clone(rdataset, &zrdataset);
			dns_rdataset_disassociate(rdataset);
			if (sigrdataset != NULL &&
			    sigrdataset->methods != NULL) {
				dns_rdataset_clone(sigrdataset, &zsigrdataset);
				dns_rdataset_disassociate(sigrdataset);
			}
			dns_db_detach(&db);
			dns_db_attach(view->cachedb, &db);
			goto db_find;
		}
		/*
		 * Otherwise, the glue is the best answer.
		 */
		result = ISC_R_SUCCESS;
	}

	if (result == DNS_R_NOTFOUND && use_hints && view->hints != NULL) {
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		if (sigrdataset != NULL && sigrdataset->methods != NULL)
			dns_rdataset_disassociate(sigrdataset);
		dns_fixedname_init(&foundname);
		result = dns_db_find(view->hints, name, NULL, type, options,
				     now, NULL, dns_fixedname_name(&foundname),
				     rdataset, sigrdataset);
		if (result == ISC_R_SUCCESS || result == DNS_R_GLUE)
			result = DNS_R_HINT;
	}

 cleanup:
	if (result != ISC_R_SUCCESS &&
	    result != DNS_R_GLUE &&
	    result != DNS_R_HINT)
		result = DNS_R_NOTFOUND;

	if (zrdataset.methods != NULL) {
		dns_rdataset_disassociate(&zrdataset);
		if (zsigrdataset.methods != NULL)
			dns_rdataset_disassociate(&zsigrdataset);
	}
	if (db != NULL)
		dns_db_detach(&db);
	if (zone != NULL)
		dns_zone_detach(&zone);

	return (result);
}

dns_view_t *
dns_view_findinlist(dns_viewlist_t *list, const char *name,
		    dns_rdataclass_t rdclass) {
	dns_view_t *view;

	REQUIRE(list != NULL);

	view = ISC_LIST_HEAD(*list);
	while (view != NULL) {
		if (strcmp(view->name, name) == 0 && view->rdclass == rdclass)
			break;
		view = ISC_LIST_NEXT(view, link);
	}
	return (view);
}
