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

#include <config.h>

#include <string.h>

#include <isc/types.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/util.h>

#include <dns/types.h>
#include <dns/adb.h>
#include <dns/cache.h>
#include <dns/dbtable.h>
#include <dns/db.h>
#include <dns/events.h>
#include <dns/fixedname.h>
#include <dns/rbt.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/tsig.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zt.h>

#define RESSHUTDOWN(v)	(((v)->attributes & DNS_VIEWATTR_RESSHUTDOWN) != 0)
#define ADBSHUTDOWN(v)	(((v)->attributes & DNS_VIEWATTR_ADBSHUTDOWN) != 0)

static void resolver_shutdown(isc_task_t *task, isc_event_t *event);
static void adb_shutdown(isc_task_t *task, isc_event_t *event);

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
	result = isc_rwlock_init(&view->conflock, 1, 1);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_mutex;
	}
	view->zonetable = NULL;
	result = dns_zt_create(mctx, rdclass, &view->zonetable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "dns_zt_create() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
		goto cleanup_rwlock;
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

	view->cache = NULL;
	view->cachedb = NULL;
	view->hints = NULL;
	view->resolver = NULL;
	view->adb = NULL;
	view->mctx = mctx;
	view->rdclass = rdclass;
	view->frozen = ISC_FALSE;
	view->task = NULL;
	view->references = 1;
	view->attributes = (DNS_VIEWATTR_RESSHUTDOWN|DNS_VIEWATTR_ADBSHUTDOWN);
	view->statickeys = NULL;
	view->dynamickeys = NULL;
	result = dns_tsigkeyring_create(view->mctx, &view->dynamickeys);
	if (result != DNS_R_SUCCESS)
		goto cleanup_zt;
	ISC_LINK_INIT(view, link);
	ISC_EVENT_INIT(&view->resevent, sizeof view->resevent, 0, NULL,
		       DNS_EVENT_VIEWRESSHUTDOWN, resolver_shutdown,
		       view, NULL, NULL, NULL);
	ISC_EVENT_INIT(&view->adbevent, sizeof view->adbevent, 0, NULL,
		       DNS_EVENT_VIEWADBSHUTDOWN, adb_shutdown,
		       view, NULL, NULL, NULL);
	view->magic = DNS_VIEW_MAGIC;
	
	*viewp = view;

	return (ISC_R_SUCCESS);

 cleanup_zt:
	dns_zt_detach(&view->zonetable);

 cleanup_rwlock:
	isc_rwlock_destroy(&view->conflock);

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
	REQUIRE(view->references == 0);
	REQUIRE(RESSHUTDOWN(view));
	REQUIRE(ADBSHUTDOWN(view));

	if (view->dynamickeys != NULL)	
		dns_tsigkeyring_destroy(&view->dynamickeys);
	if (view->statickeys != NULL)	
		dns_tsigkeyring_destroy(&view->statickeys);
	if (view->adb != NULL)
		dns_adb_detach(&view->adb);
	if (view->resolver != NULL)
		dns_resolver_detach(&view->resolver);
	if (view->task != NULL)
		isc_task_detach(&view->task);
	if (view->hints != NULL)
		dns_db_detach(&view->hints);
	if (view->cachedb != NULL)
		dns_db_detach(&view->cachedb);
	if (view->cache != NULL)
		dns_cache_detach(&view->cache);
	dns_zt_detach(&view->zonetable);
	dns_rbt_destroy(&view->secroots);
	isc_mutex_destroy(&view->lock);
	isc_mem_free(view->mctx, view->name);
	isc_mem_put(view->mctx, view, sizeof *view);
}

static isc_boolean_t
all_done(dns_view_t *view) {
	/*
	 * Caller must be holding the view lock.
	 */

	if (view->references == 0 && RESSHUTDOWN(view) && ADBSHUTDOWN(view))
		return (ISC_TRUE);

	return (ISC_FALSE);
}

void
dns_view_detach(dns_view_t **viewp) {
	dns_view_t *view;
	isc_boolean_t done = ISC_FALSE;

	/*
	 * Detach '*viewp' from its view.
	 */

	REQUIRE(viewp != NULL);
	view = *viewp;
	REQUIRE(DNS_VIEW_VALID(view));

	LOCK(&view->lock);

	INSIST(view->references > 0);
	view->references--;
	if (view->references == 0) {
		if (!RESSHUTDOWN(view))
			dns_resolver_shutdown(view->resolver);
		if (!ADBSHUTDOWN(view))
			dns_adb_shutdown(view->adb);
		done = all_done(view);
	}
	UNLOCK(&view->lock);

	*viewp = NULL;

	if (done)
		destroy(view);
}

static void
resolver_shutdown(isc_task_t *task, isc_event_t *event) {
	dns_view_t *view = event->arg;
	isc_boolean_t done;
	
	REQUIRE(event->type == DNS_EVENT_VIEWRESSHUTDOWN);
	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(view->task == task);

	LOCK(&view->lock);

	view->attributes |= DNS_VIEWATTR_RESSHUTDOWN;
	done = all_done(view);

	UNLOCK(&view->lock);

	isc_event_free(&event);

	if (done)
		destroy(view);
}

static void
adb_shutdown(isc_task_t *task, isc_event_t *event) {
	dns_view_t *view = event->arg;
	isc_boolean_t done;
	
	REQUIRE(event->type == DNS_EVENT_VIEWADBSHUTDOWN);
	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(view->task == task);

	LOCK(&view->lock);

	view->attributes |= DNS_VIEWATTR_ADBSHUTDOWN;
	done = all_done(view);

	UNLOCK(&view->lock);

	isc_event_free(&event);

	if (done)
		destroy(view);
}

isc_result_t
dns_view_createresolver(dns_view_t *view,
			isc_taskmgr_t *taskmgr, unsigned int ntasks,
			isc_socketmgr_t *socketmgr,
			isc_timermgr_t *timermgr,
			unsigned int options,
			dns_dispatch_t *dispatchv4,
			dns_dispatch_t *dispatchv6)
{
	isc_result_t result;
	isc_event_t *event;

	/*
	 * Create a resolver and address database for the view.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);
	REQUIRE(view->resolver == NULL);

	result = isc_task_create(taskmgr, view->mctx, 0, &view->task);
	if (result != ISC_R_SUCCESS)
		return (result);
	isc_task_setname(view->task, "view", view);

	result = dns_resolver_create(view, taskmgr, ntasks, socketmgr,
				     timermgr, options, dispatchv4, dispatchv6,
				     &view->resolver);
	if (result != ISC_R_SUCCESS) {
		isc_task_detach(&view->task);
		return (result);
	}
	event = &view->resevent;
	dns_resolver_whenshutdown(view->resolver, view->task, &event);
	view->attributes &= ~DNS_VIEWATTR_RESSHUTDOWN;

	result = dns_adb_create(view->mctx, view, timermgr, taskmgr,
				&view->adb);
	if (result != ISC_R_SUCCESS) {
		dns_resolver_shutdown(view->resolver);
		return (result);
	}
	event = &view->adbevent;
	dns_adb_whenshutdown(view->adb, view->task, &event);
	view->attributes &= ~DNS_VIEWATTR_ADBSHUTDOWN;

	return (ISC_R_SUCCESS);
}

void
dns_view_setcache(dns_view_t *view, dns_cache_t *cache) {

	/*
	 * Set the view's cache.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(!view->frozen);

	if (view->cache != NULL) {
		dns_db_detach(&view->cachedb);
		dns_cache_detach(&view->cache);
	}
	dns_cache_attach(cache, &view->cache);
	dns_cache_attachdb(cache, &view->cachedb);
	INSIST(DNS_DB_VALID(view->cachedb));
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

void
dns_view_setkeyring(dns_view_t *view, dns_tsig_keyring_t *ring) {
	/*
	 * Set the view's static TSIG keyring.
	 */
	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(ring != NULL);
	if (view->statickeys != NULL)
		dns_tsigkeyring_destroy(&view->statickeys);
	view->statickeys = ring;
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

	if (view->resolver != NULL) {
		INSIST(view->cachedb != NULL);
		dns_resolver_freeze(view->resolver);
	}
	view->frozen = ISC_TRUE;
}

isc_result_t
dns_view_findzone(dns_view_t *view, dns_name_t *name, dns_zone_t **zonep) {
	isc_result_t result;

	REQUIRE(DNS_VIEW_VALID(view));

	result = dns_zt_find(view->zonetable, name, NULL, zonep);
	if (result == DNS_R_PARTIALMATCH) {
		dns_zone_detach(zonep);
		result = DNS_R_NOTFOUND;
	}

	return (result);
}

isc_result_t
dns_view_find(dns_view_t *view, dns_name_t *name, dns_rdatatype_t type,
	      isc_stdtime_t now, unsigned int options,
	      isc_boolean_t use_hints, dns_name_t *foundname,
	      dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	isc_result_t result;
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
	result = dns_db_find(db, name, NULL, type, options,
			     now, NULL, foundname, rdataset, sigrdataset);

	if (result == DNS_R_DELEGATION ||
	    result == DNS_R_NOTFOUND) {
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
				if (sigrdataset != NULL &&
				    zsigrdataset.methods != NULL)
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
		result = dns_db_find(view->hints, name, NULL, type, options,
				     now, NULL, foundname,
				     rdataset, sigrdataset);
		if (result == ISC_R_SUCCESS || result == DNS_R_GLUE) {
			/*
			 * We just used a hint.  Let the resolver know it
			 * should consider priming.
			 */
			dns_resolver_prime(view->resolver);
			result = DNS_R_HINT;
		} else if (result == DNS_R_NXDOMAIN ||
			   result == DNS_R_NXRDATASET)
			result = DNS_R_NOTFOUND;
	}

 cleanup:
	if (result == DNS_R_NXDOMAIN || result == DNS_R_NXRRSET) {
		/*
		 * We don't care about any DNSSEC proof data in these cases.
		 */
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		if (sigrdataset != NULL && sigrdataset->methods != NULL)
			dns_rdataset_disassociate(sigrdataset);
	}

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

isc_result_t
dns_view_simplefind(dns_view_t *view, dns_name_t *name, dns_rdatatype_t type,
		    isc_stdtime_t now, unsigned int options,
		    isc_boolean_t use_hints,
		    dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	isc_result_t result;
	dns_fixedname_t foundname;

	dns_fixedname_init(&foundname);
	result = dns_view_find(view, name, type, now, options, use_hints,
			       dns_fixedname_name(&foundname),
			       rdataset, sigrdataset);
	if (result != ISC_R_SUCCESS &&
	    result != DNS_R_GLUE &&
	    result != DNS_R_HINT &&
	    result != DNS_R_NCACHENXDOMAIN &&
	    result != DNS_R_NCACHENXRRSET &&
	    result != DNS_R_NXDOMAIN &&
	    result != DNS_R_NXRRSET &&
	    result != DNS_R_NOTFOUND) {
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		if (sigrdataset != NULL && sigrdataset->methods != NULL)
			dns_rdataset_disassociate(sigrdataset);
		result = DNS_R_NOTFOUND;
	}

	return (result);
}

isc_result_t
dns_view_findzonecut(dns_view_t *view, dns_name_t *name, dns_name_t *fname,
		     isc_stdtime_t now, unsigned int options,
		     isc_boolean_t use_hints,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	isc_result_t result;
	dns_db_t *db;
	isc_boolean_t is_zone, use_zone, try_hints;
	dns_zone_t *zone;
	dns_name_t *zfname;
	dns_rdataset_t zrdataset, zsigrdataset;
	dns_fixedname_t zfixedname;

	/*
	 * Find the best known zonecut containing 'name'.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(view->frozen);

	db = NULL;
	zone = NULL;
	use_zone = ISC_FALSE;
	try_hints = ISC_FALSE;
	zfname = NULL;

	/*
	 * Initialize.
	 */
	dns_fixedname_init(&zfixedname);
	dns_rdataset_init(&zrdataset);
	dns_rdataset_init(&zsigrdataset);

	/*
	 * Find the right database.
	 */
	result = dns_zt_find(view->zonetable, name, NULL, &zone);
	if (result == DNS_R_SUCCESS || result == DNS_R_PARTIALMATCH)
		result = dns_zone_getdb(zone, &db);
	if (result == ISC_R_NOTFOUND) {
		/*
		 * We're not directly authoritative for this query name, nor
		 * is it a subdomain of any zone for which we're
		 * authoritative.
		 */
		if (view->cachedb != NULL) {
			/*
			 * We have a cache; try it.
			 */
			dns_db_attach(view->cachedb, &db);
		} else {
			/*
			 * Maybe we have hints...
			 */
			try_hints = ISC_TRUE;
			goto finish;
		}
	} else if (result != ISC_R_SUCCESS) {
		/*
		 * Something is broken.
		 */
		goto cleanup;
	}
	is_zone = dns_db_iszone(db);

 db_find:
	/*
	 * Look for the zonecut.
	 */
	if (is_zone) {
		result = dns_db_find(db, name, NULL, dns_rdatatype_ns, options,
				     now, NULL, fname, rdataset, sigrdataset);
		if (result == DNS_R_DELEGATION)
			result = ISC_R_SUCCESS;
		else if (result != ISC_R_SUCCESS)
			goto cleanup;
		if (view->cachedb != NULL && db != view->hints) {
			/*
			 * We found an answer, but the cache may be better.
			 */
			zfname = dns_fixedname_name(&zfixedname);
			result = dns_name_concatenate(fname, NULL, zfname,
						      NULL);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			dns_rdataset_clone(rdataset, &zrdataset);
			dns_rdataset_disassociate(rdataset);
			if (sigrdataset != NULL &&
			    sigrdataset->methods != NULL) {
				dns_rdataset_clone(sigrdataset, &zsigrdataset);
				dns_rdataset_disassociate(sigrdataset);
			}
			dns_db_detach(&db);
			dns_db_attach(view->cachedb, &db);
			is_zone = ISC_FALSE;
			goto db_find;
		}
	} else {
		result = dns_db_findzonecut(db, name, options, now, NULL,
					    fname, rdataset, sigrdataset);
		if (result == ISC_R_SUCCESS) {
			if (zfname != NULL &&
			    !dns_name_issubdomain(fname, zfname)) {
				/*
				 * We found a zonecut in the cache, but our
				 * zone delegation is better.
				 */
				use_zone = ISC_TRUE;
			}
		} else if (result == ISC_R_NOTFOUND) {
			if (zfname != NULL) {
				/*
				 * We didn't find anything in the cache, but we
				 * have a zone delegation, so use it.
				 */
				use_zone = ISC_TRUE;
			} else {
				/*
				 * Maybe we have hints...
				 */
				try_hints = ISC_TRUE;
			}
		} else {
			/*
			 * Something bad happened.
			 */
			goto cleanup;
		}
	}

 finish:
	if (use_zone) {
		if (rdataset->methods != NULL) {
			dns_rdataset_disassociate(rdataset);
			if (sigrdataset != NULL &&
			    sigrdataset->methods != NULL)
				dns_rdataset_disassociate(sigrdataset);
		}
		result = dns_name_concatenate(zfname, NULL, fname, NULL);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		dns_rdataset_clone(&zrdataset, rdataset);
		if (sigrdataset != NULL && zrdataset.methods != NULL)
			dns_rdataset_clone(&zsigrdataset, sigrdataset);
	} else if (try_hints && use_hints && view->hints != NULL) {
		/*
		 * We've found nothing so far, but we have hints.
		 */
		result = dns_db_find(view->hints, dns_rootname, NULL,
				     dns_rdatatype_ns, 0, now, NULL, fname,
				     rdataset, NULL);
		if (result != ISC_R_SUCCESS) {
			/*
			 * We can't even find the hints for the root
			 * nameservers!
			 */
			result = ISC_R_NOTFOUND;
		}
	}

 cleanup:
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

isc_result_t
dns_viewlist_find(dns_viewlist_t *list, const char *name,
		  dns_rdataclass_t rdclass, dns_view_t **viewp)
{
	dns_view_t *view;

	REQUIRE(list != NULL);

	for (view = ISC_LIST_HEAD(*list);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link)) {
		if (strcmp(view->name, name) == 0 && view->rdclass == rdclass)
			break;
	}
	if (view == NULL)
		return (ISC_R_NOTFOUND);

	dns_view_attach(view, viewp);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_view_load(dns_view_t *view, isc_boolean_t stop) {

	REQUIRE(DNS_VIEW_VALID(view));

	return (dns_zt_load(view->zonetable, stop));
}

isc_result_t
dns_view_checksig(dns_view_t *view, isc_buffer_t *source, dns_message_t *msg) {
	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(source != NULL);

	return dns_tsig_verify(source, msg, view->statickeys,
			       view->dynamickeys);
}

