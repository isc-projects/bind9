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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/rwlock.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>
#include <isc/app.h>
#include <isc/dir.h>

#include <dns/cache.h>
#include <dns/confparser.h>
#include <dns/types.h>
#include <dns/result.h>
#include <dns/master.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/compress.h>
#include <dns/db.h>
#include <dns/dbtable.h>
#include <dns/message.h>
#include <dns/journal.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/tsig.h>
#include <dns/tkey.h>

#include <named/types.h>
#include <named/globals.h>
#include <named/log.h>
#include <named/rootns.h>
#include <named/server.h>

#include "../../isc/util.h"		/* XXXRTH */

typedef struct {
	isc_mem_t *		mctx;
	dns_viewlist_t		viewlist;
} ns_load_t;

static isc_task_t *		server_task;
static dns_view_t *		version_view;


static isc_result_t
create_default_view(isc_mem_t *mctx, dns_rdataclass_t rdclass,
		    dns_view_t **viewp)
{
	dns_view_t *view;
	dns_cache_t *cache;
	
	isc_result_t result;

	REQUIRE(viewp != NULL && *viewp == NULL);

	/*
	 * View.
	 */
	view = NULL;
	result = dns_view_create(mctx, rdclass, "_default", &view);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Cache.
	 */
	cache = NULL;
	result = dns_cache_create(mctx, ns_g_taskmgr, ns_g_timermgr, rdclass,
				  "rbt", 0, NULL, &cache);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	dns_view_setcache(view, cache);
	dns_cache_detach(&cache);

	/*
	 * XXXRTH  Temporary support for loading cache contents.
	 */
	if (ns_g_cachefile != NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER,
			      ISC_LOG_DEBUG(1), "loading cache '%s'",
			      ns_g_cachefile);
		result = dns_db_load(view->cachedb, ns_g_cachefile);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	}

	/*
	 * Resolver.
	 *
	 * XXXRTH hardwired number of tasks.  Also, we'll need to
	 * see if we are dealing with a shared dispatcher in this view.
	 */
	result = dns_view_createresolver(view, ns_g_taskmgr, 31,
					 ns_g_socketmgr, ns_g_timermgr,
					 NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * We have default hints for class IN.
	 */
	if (rdclass == dns_rdataclass_in)
		dns_view_sethints(view, ns_g_rootns);

	*viewp = view;

	return (ISC_R_SUCCESS);

 cleanup:
	dns_view_detach(&view);

	return (result);
}

static isc_result_t
load_zone(dns_c_ctx_t *ctx, dns_c_zone_t *czone, dns_c_view_t *cview,
	  void *uap)
{
	ns_load_t *lctx;
	dns_view_t *view, *tview, *pview;
	dns_zone_t *zone, *tzone;
	dns_name_t *origin;
	isc_result_t result;

	/*
	 * Load (or reload) a zone.
	 */

	lctx = uap;

	tzone = NULL;
	zone = NULL;
	pview = NULL;

	/*
	 * Find the view.
	 */
	view = NULL;
	if (cview != NULL) {
		result = dns_viewlist_find(&lctx->viewlist, cview->name,
					   czone->zclass, &view);
		if (result != ISC_R_SUCCESS)
			return (result);
	} else {
		result = dns_viewlist_find(&lctx->viewlist, "_default",
					   czone->zclass, &view);
		if (result == ISC_R_NOTFOUND) {
			/*
			 * Create a default view.
			 */
			tview = NULL;
			result = create_default_view(ctx->mem, czone->zclass,
						     &tview);
			if (result != ISC_R_SUCCESS)
				return (result);
			dns_view_attach(tview, &view);
			ISC_LIST_APPEND(lctx->viewlist, view, link);
		} else if (result != ISC_R_SUCCESS)
			return (result);
	}

	/*
	 * Do we already have a production version of this view?
	 */
	RWLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	result = dns_viewlist_find(&ns_g_viewlist, view->name, view->rdclass,
				   &pview);
     	RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	if (result != ISC_R_NOTFOUND && result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Create a new zone structure and configure it.
	 */
	result = dns_zone_create(&zone, lctx->mctx);
	if (result != ISC_R_SUCCESS)
		return (result);
	result = dns_zone_copy(ns_g_lctx, ctx, czone, zone);
	if (result != ISC_R_SUCCESS)
		return (result);

	if (dns_zone_gettype(zone) == dns_zone_hint) {
		INSIST(0);
	} else {
		/*
		 * Check for duplicates in the new zone table.
		 */
		origin = dns_zone_getorigin(zone);
		result = dns_view_findzone(view, origin, &tzone);
		if (result == ISC_R_SUCCESS) {
			/*
			 * We already have this zone!
			 */
			result = ISC_R_EXISTS;
			goto cleanup;
		}

		/*
		 * Do we have the zone in the production view?
		 */
		if (pview != NULL)
			result = dns_view_findzone(pview, origin, &tzone);
		else
			result = ISC_R_NOTFOUND;
		if (result == ISC_R_SUCCESS) {
			/*
			 * Yes.
			 *
			 * If the production zone's configuration is
			 * the same as the new zone's, we can use the
			 * production zone.
			 */
			if (dns_zone_equal(zone, tzone))
				result = dns_view_addzone(view, tzone);
			else
				result = dns_view_addzone(view, zone);
		} else if (result == ISC_R_NOTFOUND) {
			/*
			 * This is a new zone.
			 */
			result = dns_view_addzone(view, zone);
			if (result != DNS_R_SUCCESS)
				goto cleanup;

			result = dns_zonemgr_managezone(ns_g_zonemgr, zone);
			if (result != DNS_R_SUCCESS)
				goto cleanup;
		}
	}

 cleanup:
	if (tzone != NULL)
		dns_zone_detach(&tzone);
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (pview != NULL)
		dns_view_detach(&pview);
	if (view != NULL)
		dns_view_detach(&view);

	return (result);
}

static void
load_configuration(const char *filename) {
	isc_result_t result;
	ns_load_t lctx;
	dns_c_cbks_t callbacks;
	dns_c_ctx_t *configctx, *oconfigctx;
	dns_view_t *view, *view_next;
	dns_viewlist_t oviewlist;

	lctx.mctx = ns_g_mctx;
	ISC_LIST_INIT(lctx.viewlist);

	callbacks.zonecbk = load_zone;
	callbacks.zonecbkuap = &lctx;
	callbacks.optscbk = NULL;
	callbacks.optscbkuap = NULL;

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "loading '%s'", filename);

	configctx = NULL;
	result = dns_c_parse_namedconf(filename, ns_g_mctx, &configctx,
				       &callbacks);
	if (result != ISC_R_SUCCESS) {
#ifdef notyet
		for (view = ISC_LIST_HEAD(lctx.viewlist);
		     view != NULL;
		     view = view_next) {
			view_next = ISC_LIST_NEXT(view, link);
			ISC_LIST_UNLINK(lctx.viewlist, view, link);
			dns_view_detach(&view);
		}
#endif
		ns_server_fatal(NS_LOGMODULE_SERVER, ISC_FALSE,
				"load of '%s' failed", filename);
	}
	
	/*
	 * If we haven't created any views, create a default view for class
	 * IN.  (We're a caching-only server.)
	 */
	if (ISC_LIST_EMPTY(lctx.viewlist)) {
		view = NULL;
		result = create_default_view(ns_g_mctx, dns_rdataclass_in,
					     &view);
		if (result != ISC_R_SUCCESS)
			ns_server_fatal(NS_LOGMODULE_SERVER, ISC_FALSE,
					"could not create default view");
		ISC_LIST_APPEND(lctx.viewlist, view, link);
	}

	/*
	 * Freeze the views.
	 */
	for (view = ISC_LIST_HEAD(lctx.viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link))
		dns_view_freeze(view);

	/*
	 * Attach the version view.
	 */
	view = NULL;
	dns_view_attach(version_view, &view);
	ISC_LIST_APPEND(lctx.viewlist, view, link);

	/*
	 * Change directory.
	 */
	if (configctx->options != NULL &&
	    configctx->options->directory != NULL) {
		result = isc_dir_chdir(configctx->options->directory);
		if (result != ISC_R_SUCCESS)
			ns_server_fatal(NS_LOGMODULE_SERVER, ISC_FALSE,
					"change directory to '%s' failed: %s",
					configctx->options->directory,
					isc_result_totext(result));
	}

	/*
	 * Load zones.
	 */
	for (view = ISC_LIST_HEAD(lctx.viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		dns_view_load(view);
	}

	/*
	 * Force zone maintenance.  Do this after loading
	 * so that we know when we need to force AXFR of
	 * slave zones whose master files are missing.
	 */
	dns_zonemgr_forcemaint(ns_g_zonemgr);
		
	/*
	 * Put the configuration into production.
	 */

	RWLOCK(&ns_g_viewlock, isc_rwlocktype_write);

	oviewlist = ns_g_viewlist;
	ns_g_viewlist = lctx.viewlist;

	oconfigctx = ns_g_confctx;
	ns_g_confctx = configctx;

	RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_write);

	/*
	 * Cleanup old configuration.
	 */

	for (view = ISC_LIST_HEAD(oviewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(oviewlist, view, link);
		dns_view_detach(&view);
	}

	if (oconfigctx != NULL)
		dns_c_ctx_delete(&oconfigctx);

	/*
	 * Load the TSIG information from the configuration
	 */
        result = dns_tsig_init(ns_g_lctx, ns_g_confctx, ns_g_mctx);
        if (result != ISC_R_SUCCESS)
                ns_server_fatal(NS_LOGMODULE_SERVER, ISC_FALSE,
				"dns_tsig_init() failed: %s",
                                isc_result_totext(result));

	/*
	 * Load the TKEY information from the configuration
	 */
	result = dns_tkey_init(ns_g_lctx, ns_g_confctx, ns_g_mctx);
	if (result != ISC_R_SUCCESS) {
		ns_server_fatal(NS_LOGMODULE_SERVER, ISC_FALSE,
				"dns_tkey_init() failed: %s",
				isc_result_totext(result));
	}
}

static void
run_server(isc_task_t *task, isc_event_t *event) {

	(void)task;

	isc_event_free(&event);

	load_configuration(ns_g_conffile);

	ns_interfacemgr_scan(ns_g_interfacemgr);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "running");
}

static isc_result_t
create_version_view(void) {
	dns_view_t *view;
	dns_zone_t *zone;
	dns_db_t *db;
	dns_name_t *origin;
	dns_result_t result, eresult;
	isc_buffer_t source;
	size_t len;
	int soacount, nscount;
	dns_rdatacallbacks_t callbacks;
	char version_text[1024];

	(void)sprintf(version_text, "version 0 CHAOS TXT \"%s\"\n",
		      ns_g_version);

	view = NULL;
	result = dns_view_create(ns_g_mctx, dns_rdataclass_ch, "_version",
				 &view);
	if (result != ISC_R_SUCCESS)
		return (result);

	zone = NULL;
	result = dns_zone_create(&zone, ns_g_mctx);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_zone_setorigin(zone, "bind.");
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	origin = dns_zone_getorigin(zone);

	db = NULL;
	result = dns_db_create(ns_g_mctx, "rbt", origin, ISC_FALSE,
			       view->rdclass, 0, NULL, &db);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	len = strlen(version_text);
	isc_buffer_init(&source, version_text, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	dns_rdatacallbacks_init(&callbacks);
	result = dns_db_beginload(db, &callbacks.add, &callbacks.add_private);
	if (result != DNS_R_SUCCESS)
		return (result);
	result = dns_master_loadbuffer(&source, &db->origin, &db->origin,
				       db->rdclass, ISC_FALSE,
				       &soacount, &nscount, &callbacks,
				       ns_g_mctx);
	eresult = dns_db_endload(db, &callbacks.add_private);
	if (result != ISC_R_SUCCESS)
		result = eresult;
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_zone_replacedb(zone, db, ISC_FALSE);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	result = dns_view_addzone(view, zone);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	dns_view_freeze(view);

	version_view = view;
	view = NULL;

	result = ISC_R_SUCCESS;

 cleanup:
	if (db != NULL)
		dns_db_detach(&db);
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (view != NULL)
		dns_view_detach(&view);

	return (result);
}

static void
shutdown_server(isc_task_t *task, isc_event_t *event) {
	dns_view_t *view, *view_next;

	(void)task;

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "shutting down");

	RWLOCK(&ns_g_viewlock, isc_rwlocktype_write);

	for (view = ISC_LIST_HEAD(ns_g_viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(ns_g_viewlist, view, link);
		dns_view_detach(&view);
	}

	/*
	 * XXXRTH  Is this the right place to do this?
	 */
	dns_c_ctx_delete(&ns_g_confctx);

	dns_tkey_destroy();
	dns_tsig_destroy();

	RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_write);

	isc_task_detach(&server_task);

	dns_view_detach(&version_view);

	dns_zonemgr_destroy(&ns_g_zonemgr);
			     
	ns_rootns_destroy();

	isc_event_free(&event);
}

isc_result_t
ns_server_init(void) {
	isc_result_t result;

	/*
	 * Setup default root server hints.
	 */
	result = ns_rootns_init();
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_zonemgr_create(ns_g_mctx, ns_g_taskmgr, ns_g_timermgr,
				    ns_g_socketmgr, &ns_g_zonemgr);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = create_version_view();
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Setup the server task, which is responsible for coordinating
	 * startup and shutdown of the server.
	 */
	result = isc_task_create(ns_g_taskmgr, ns_g_mctx, 0, &server_task);
	if (result != ISC_R_SUCCESS)
		goto cleanup_rootns;
	result = isc_task_onshutdown(server_task, shutdown_server, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;
	result = isc_app_onrun(ns_g_mctx, server_task, run_server, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	return (ISC_R_SUCCESS);

	/* XXXRTH  Add zonemgr, and version view cleanups. */

 cleanup_task:
	isc_task_detach(&server_task);

 cleanup_rootns:
	ns_rootns_destroy();

	return (result);
}

void
ns_server_fatal(isc_logmodule_t *module, isc_boolean_t want_core,
		const char *format, ...)
{
	va_list args;

	va_start(args, format);
	isc_log_vwrite(ns_g_lctx, NS_LOGCATEGORY_GENERAL, module,
		       ISC_LOG_CRITICAL, format, args);
	va_end(args);
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_CRITICAL, "exiting (due to fatal error)");

	if (want_core && ns_g_coreok)
		abort();
	exit(1);
}
