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

#include <named/types.h>
#include <named/globals.h>
#include <named/rootns.h>
#include <named/server.h>
#include <named/xfrin.h>

#include "../../isc/util.h"		/* XXXRTH */


static isc_result_t server_config_load(const char *conffile, isc_mem_t *mem);
static isc_result_t server_config_reload(const char *conffile, isc_mem_t *mem);
static isc_result_t zoneload(dns_c_ctx_t *ctx, dns_c_zone_t *zone,
			     dns_c_view_t *view, void *uap);
static isc_result_t zonereload(dns_c_ctx_t *ctx, dns_c_zone_t *zone,
			       dns_c_view_t *view, void *uap);
static isc_result_t optionsload(dns_c_ctx_t *ctx, void *uap);
static isc_result_t optionsreload(dns_c_ctx_t *ctx, void *uap);


static isc_task_t *		server_task;
static dns_db_t *		version_db;
static dns_view_t *		version_view;

static dns_result_t
load(ns_dbinfo_t *dbi, char *view_name) {
	dns_fixedname_t forigin;
	dns_name_t *origin;
	dns_result_t result;
	isc_buffer_t source;
	size_t len;
	dns_view_t *view;

	/*
	 * XXXRTH  View list code will move to its own module soon.
	 */
	RWLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	for (view = ISC_LIST_HEAD(ns_g_viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link)) {
		if (strcasecmp(view_name, view->name) == 0) {
			dns_view_attach(view, &dbi->view);
			break;
		}
	}			
	RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	if (view == NULL)
		return (DNS_R_NOTFOUND);

	len = strlen(dbi->origin);
	isc_buffer_init(&source, dbi->origin, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	result = dns_name_fromtext(origin, &source, dns_rootname, ISC_FALSE,
				   NULL);
	if (result != DNS_R_SUCCESS)
		goto view_detach;

	if (dbi->iscache) {
		result = dns_db_create(ns_g_mctx, "rbt", origin, dbi->iscache,
			       view->rdclass, 0, NULL, &dbi->db);
		if (result != DNS_R_SUCCESS)
			goto view_detach;
		printf("loading cache %s (%s)\n", dbi->path, dbi->origin);
		result = dns_db_load(dbi->db, dbi->path);
		if (result != DNS_R_SUCCESS)
			goto db_detach;
		dns_view_setcachedb(view, dbi->db);
	} else {
		result = dns_zone_create(&dbi->zone, ns_g_mctx);

		printf("loading %s (%s)\n", dbi->path, dbi->origin);
		result = dns_zone_setdatabase(dbi->zone, dbi->path);
		if (result != DNS_R_SUCCESS)
			goto zone_detach;
		result = dns_zone_load(dbi->zone);

		if (result != DNS_R_SUCCESS) {
			if (dbi->isslave) {
				/*
				 * Ignore the error.
				 */
				return (DNS_R_SUCCESS);
			} else {
				goto zone_detach;
			}
		}

		printf("loaded\n");
		printf("journal rollforward\n");
		result = dns_journal_rollforward(ns_g_mctx, dbi->db, "journal");
		if (result != DNS_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "ns_rollforward(): %s",
					 dns_result_totext(result));
			/* Continue anyway... */
		}

		result = dns_view_addzone(view, dbi->zone);
		if (result != DNS_R_SUCCESS)
			goto zone_detach;
	}

	return (DNS_R_SUCCESS);

 zone_detach:
	if (dbi->zone != NULL)
		dns_zone_detach(&dbi->zone);

 db_detach:
	if (dbi->db != NULL)
		dns_db_detach(&dbi->db);

 view_detach:
	dns_view_detach(&dbi->view);

	return (result);
}

static isc_result_t
load_version(void) {
	dns_fixedname_t forigin;
	dns_name_t *origin;
	dns_result_t result, eresult;
	isc_buffer_t source;
	size_t len;
	int soacount, nscount;
	dns_rdatacallbacks_t callbacks;
	dns_view_t *view = NULL;
	char version_text[1024];
	dns_zone_t *version_zone = NULL;
	dns_db_t *version_db = NULL;

	sprintf(version_text, "version 0 CHAOS TXT \"%s\"\n", ns_g_version);

	/*
	 * XXXRTH  View list code will move to its own module soon.
	 */
	RWLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	for (view = ISC_LIST_HEAD(ns_g_viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link)) {
		if (strcasecmp(view->name, "default/CHAOS") == 0) {
			dns_view_attach(view, &version_view);
			break;
		}
	}			
	RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	if (view == NULL)
		return (DNS_R_NOTFOUND);

	len = strlen("bind.");
	isc_buffer_init(&source, "bind.", len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	result = dns_name_fromtext(origin, &source, dns_rootname, ISC_FALSE,
				   NULL);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	version_zone = NULL;
	result = dns_zone_create(&version_zone, ns_g_mctx);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	version_db = NULL;
	result = dns_db_create(ns_g_mctx, "rbt", origin, ISC_FALSE,
			       view->rdclass, 0, NULL, &version_db);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	dns_rdatacallbacks_init(&callbacks);

	len = strlen(version_text);
	isc_buffer_init(&source, version_text, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);

	result = dns_db_beginload(version_db, &callbacks.add,
				  &callbacks.add_private);
	if (result != DNS_R_SUCCESS)
		return (result);
	result = dns_master_loadbuffer(&source, &version_db->origin,
				       &version_db->origin,
				       version_db->rdclass, ISC_FALSE,
				       &soacount, &nscount, &callbacks,
				       version_db->mctx);
	eresult = dns_db_endload(version_db, &callbacks.add_private);
	if (result == ISC_R_SUCCESS)
		result = eresult;
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	dns_zone_replacedb(version_zone, version_db, ISC_FALSE);

	result = dns_view_addzone(version_view, version_zone);
	if (result != DNS_R_SUCCESS)
		goto cleanup;

	return (DNS_R_SUCCESS);


 cleanup:
	if (version_zone != NULL)
		dns_zone_detach(&version_zone);
	if (version_db != NULL)
		dns_db_detach(&version_db);
	if (version_view != NULL)
		dns_view_detach(&version_view);

	return (result);
}

static isc_result_t
load_all(void) {
	isc_result_t result = ISC_R_SUCCESS;
	ns_dbinfo_t *dbi;
	dns_view_t *view;
	
	result = load_version();
	if (result != ISC_R_SUCCESS)
		return (result);

	for (dbi = ISC_LIST_HEAD(ns_g_dbs);
	     dbi != NULL;
	     dbi = ISC_LIST_NEXT(dbi, link)) {
		result = load(dbi, "default/IN");
		if (result != ISC_R_SUCCESS)
			break;
	}

	if (result == ISC_R_SUCCESS) {
		RWLOCK(&ns_g_viewlock, isc_rwlocktype_read);
		for (view = ISC_LIST_HEAD(ns_g_viewlist);
		     view != NULL;
		     view = ISC_LIST_NEXT(view, link))
			dns_view_freeze(view);
		RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_read);
	}

	return (result);
}

static void
unload_all(void) {
	ns_dbinfo_t *dbi, *dbi_next;
	
	for (dbi = ISC_LIST_HEAD(ns_g_dbs); dbi != NULL; dbi = dbi_next) {
		dbi_next = ISC_LIST_NEXT(dbi, link);
		if (dbi->view != NULL) {
			INSIST(dbi->db != NULL);
			dns_db_detach(&dbi->db);
			dns_view_detach(&dbi->view);
		}
		isc_mem_free(ns_g_mctx, dbi->path);
		isc_mem_free(ns_g_mctx, dbi->origin);
		if (dbi->master != NULL)
			isc_mem_free(ns_g_mctx, dbi->master);
		ISC_LIST_UNLINK(ns_g_dbs, dbi, link);
		isc_mem_put(ns_g_mctx, dbi, sizeof *dbi);
	}

	if (version_view != NULL) {
		INSIST(version_db != NULL);
		dns_db_detach(&version_db);
		dns_view_detach(&version_view);
	}
}

static void
load_configuration(void) {
	isc_result_t result;

	result = server_config_load("/etc/named.conf", ns_g_mctx);
	if (result != ISC_R_SUCCESS) {
		printf("server_config_load(): %s\n",
		       isc_result_totext(result));
		/* XXX How do we make things die here? shutdown_server()?*/
	}
	
#if 0
	/* 
	 * XXXRTH  loading code below is temporary; it
	 * will be replaced by proper config file processing.
	 */

	result = load_all();
	if (result != ISC_R_SUCCESS) {
		/* XXXRTH */
		printf("load_all(): %s\n", isc_result_totext(result));
	}
#endif
}

static void
run_server(isc_task_t *task, isc_event_t *event) {
	(void)task;
	printf("server running\n");

	load_configuration();
	ns_interfacemgr_scan(ns_g_interfacemgr);

	isc_event_free(&event);
}

static void
shutdown_server(isc_task_t *task, isc_event_t *event) {
	dns_view_t *view, *view_next;

	(void)task;

	printf("server shutting down\n");

	RWLOCK(&ns_g_viewlock, isc_rwlocktype_write);
	unload_all();
	for (view = ISC_LIST_HEAD(ns_g_viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(ns_g_viewlist, view, link);
		dns_view_detach(&view);
	}
	ISC_LIST_INIT(ns_g_viewlist);
	RWUNLOCK(&ns_g_viewlock, isc_rwlocktype_write);
	isc_task_detach(&server_task);

	ns_rootns_destroy();

	isc_event_free(&event);
}

isc_result_t
ns_server_init(void) {
	isc_result_t result;
	dns_view_t *view, *view_next;

	result = ns_rootns_init();
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * XXXRTH  The view management code here will probably move to its
	 *         own module when we start using the config file.
	 */
	view = NULL;
	result = dns_view_create(ns_g_mctx, dns_rdataclass_in, "default/IN",
				 &view);
	if (result != ISC_R_SUCCESS)
		goto cleanup_views;
	ISC_LIST_APPEND(ns_g_viewlist, view, link);
	dns_view_sethints(view, ns_g_rootns);
	/*
	 * XXXRTH hardwired number of tasks.  Also, we'll need to see
	 * if we are dealing with a shared dispatcher in this view.
	 */
	result = dns_view_createresolver(view, ns_g_taskmgr, 16,
					 ns_g_socketmgr, ns_g_timermgr,
					 NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_views;
	view = NULL;
	result = dns_view_create(ns_g_mctx, dns_rdataclass_ch, "default/CHAOS",
				 &view);
	if (result != ISC_R_SUCCESS)
		goto cleanup_views;
	ISC_LIST_APPEND(ns_g_viewlist, view, link);

	result = isc_task_create(ns_g_taskmgr, ns_g_mctx, 0, &server_task);
	if (result != ISC_R_SUCCESS)
		goto cleanup_views;

	result = isc_task_onshutdown(server_task, shutdown_server, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	result = isc_app_onrun(ns_g_mctx, server_task, run_server, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	return (ISC_R_SUCCESS);

 cleanup_task:
	isc_task_detach(&server_task);

 cleanup_views:
	for (view = ISC_LIST_HEAD(ns_g_viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(ns_g_viewlist, view, link);
		dns_view_detach(&view);
	}

	ns_rootns_destroy();

	return (result);
}

static isc_result_t
server_config_load(const char *conffile, isc_mem_t *mem)
{
	dns_c_cbks_t callbacks;
	dns_c_ctx_t *configctx = NULL;
	isc_result_t res;
       

	/* Set up callbacks for the parser.
	 *
	 * If zonecbk field is non-NULL, then the function it points to
	 * will be called after each zone statement is completely
	 * parsed. The zone will be passed in as a paramater, and also
	 * installed in the config structure, but after the zonecbk
	 * function returns it will be removed from the config
	 * structure. The zonecbkuap value will be passed through to the
	 * zonecbk function as a parameter.
	 * 
	 * If the optscbk function is non-NULL, then it is called after the 
	 * options statement is completely parsed.
	 * 
	 * These functions must return ISC_R_SUCCESS, or the parser will
	 * consider that a failure and will terminate. The functions should 
	 * not modify their parameters.
	 */
	
	callbacks.zonecbk = zoneload;
	callbacks.optscbk = NULL;
	callbacks.zonecbkuap = NULL;
	callbacks.optscbkuap = NULL;

	/* XXX should log rather than write to stderr */
	fprintf(stderr, "named: loading config file %s\n", conffile);
	res = dns_c_parse_namedconf(NULL, /* XXX isc_log_t to use??? */
				    conffile, mem, &configctx,
				    &callbacks);

	if (res != ISC_R_SUCCESS) {
		/* XXX should log rather than write to stderr */
		fprintf(stderr, "named: failed to load config file %s\n",
			conffile);
		return (ISC_R_FAILURE);
	}
	
	RWLOCK(&ns_g_confctxlock, isc_rwlocktype_write);
	if (ns_g_confctx != NULL) {
		dns_c_ctx_delete(NULL /* XXX isc_log_t */, &ns_g_confctx);
	}

	ns_g_confctx = configctx;

	RWUNLOCK(&ns_g_confctxlock, isc_rwlocktype_write);

	return (ISC_R_SUCCESS);
}



/* Function to be called whenever server must reload the config file,
   e.g. on a SIGHUP. */
static isc_result_t
server_config_reload(const char *conffile, isc_mem_t *mem)
{
	dns_c_cbks_t callbacks;
	dns_c_ctx_t *configctx = NULL;
	isc_result_t res;
       

	/* Set up callbacks for the parser. See the comment in
	 * server_config_load() for usage.
	 */
	
	callbacks.zonecbk = zonereload;
	callbacks.optscbk = optionsreload;
	callbacks.zonecbkuap = NULL;
	callbacks.optscbkuap = NULL;
		
	/* XXX should log rather than write to stderr */
	fprintf(stderr, "named: reloading config file %s\n", conffile);
	res = dns_c_parse_namedconf(NULL, /* XXX isc_log_t to use??? */
				    conffile, mem, &configctx, &callbacks);

	if (res != ISC_R_SUCCESS) {
		/* XXX should log rather than write to stderr */
		fprintf(stderr, "named: failed to reload config file %s\n",
			conffile);
		return (ISC_R_FAILURE);
	}


	RWLOCK(&ns_g_confctxlock, isc_rwlocktype_write);
	if (ns_g_confctx != NULL) {
		dns_c_ctx_delete(NULL /* XXX isc_log_t */, &ns_g_confctx);
	}

	ns_g_confctx = configctx;
	RWUNLOCK(&ns_g_confctxlock, isc_rwlocktype_write);

	return (ISC_R_SUCCESS);
}



/* Called during first time config file is loaded. Called after each zone
 * statement is parsed.
 */
static isc_result_t
zoneload(dns_c_ctx_t *ctx, dns_c_zone_t *zone, dns_c_view_t *view, void *uap)
{

	/*
	 * returning anything other than ISC_R_SUCCESS will cause parsing to 
	 * fail.
	 */
	return (dns_zone_callback(ctx, zone, view, uap));
}

static isc_result_t
zonereload(dns_c_ctx_t *ctx, dns_c_zone_t *zone, dns_c_view_t *view, void *uap)
{
	(void) ctx; (void) zone; (void) view; (void) uap; /* lint */

	
	/*
	 * returning anything other than ISC_R_SUCCESS will cause parsing to 
	 * fail.
	 */

	return (ISC_R_NOTIMPLEMENTED);
}



/* Called the first time the config file is loaded after the options
 * statment is parsed
 */ 
static isc_result_t
optionsload(dns_c_ctx_t *ctx, void *uap)
{
	(void) ctx; (void) uap;		/* lint */

	/* returning anything other than ISC_R_SUCCESS will cause parsing to 
	 * fail.
	 */
	return (ISC_R_SUCCESS);
}



/* Called the subsequent times the config file is loaded after the options
 * statment is parsed
 */ 
static isc_result_t
optionsreload(dns_c_ctx_t *ctx, void *uap)
{
	(void) ctx; (void) uap;		/* lint */

	/* returning anything other than ISC_R_SUCCESS will cause parsing to 
	 * fail.
	 */
	return (ISC_R_SUCCESS);
}



