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
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>
#include <isc/app.h>

#include <dns/types.h>
#include <dns/result.h>
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

#include <named/types.h>
#include <named/globals.h>
#include <named/server.h>

#if 0
#include "udpclient.h"
#include "tcpclient.h"
#include "interfacemgr.h"
#endif

static ns_dbinfo_t *		cache_dbi;
static isc_task_t *		server_task;

static dns_result_t
load(ns_dbinfo_t *dbi) {
	dns_fixedname_t forigin;
	dns_name_t *origin;
	dns_result_t result;
	isc_buffer_t source;
	size_t len;

	len = strlen(dbi->origin);
	isc_buffer_init(&source, dbi->origin, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	result = dns_name_fromtext(origin, &source, dns_rootname, ISC_FALSE,
				   NULL);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_db_create(ns_g_mctx, "rbt", origin, dbi->iscache,
			       dns_rdataclass_in, 0, NULL, &dbi->db);
	if (result != DNS_R_SUCCESS)
		return (result);

	printf("loading %s (%s)\n", dbi->path, dbi->origin);
	result = dns_db_load(dbi->db, dbi->path);
	if (result != DNS_R_SUCCESS) {
		dns_db_detach(&dbi->db);
		return (result);
	}
	printf("loaded\n");

	if (dbi->iscache) {
		INSIST(cache_dbi == NULL);
		dns_dbtable_adddefault(ns_g_dbtable, dbi->db);
		cache_dbi = dbi;
	} else {
		if (dns_dbtable_add(ns_g_dbtable, dbi->db) != DNS_R_SUCCESS) {
			dns_db_detach(&dbi->db);
			isc_mem_put(ns_g_mctx, dbi, sizeof *dbi);
			return (result);
		}
	}

	return (DNS_R_SUCCESS);
}

static isc_result_t
load_all(void) {
	isc_result_t result = ISC_R_SUCCESS;
	ns_dbinfo_t *dbi;
	
	for (dbi = ISC_LIST_HEAD(ns_g_dbs);
	     dbi != NULL;
	     dbi = ISC_LIST_NEXT(dbi, link)) {
		result = load(dbi);
		if (result != ISC_R_SUCCESS)
			break;
	}

	return (result);
}

static void
unload_all(void) {
	ns_dbinfo_t *dbi, *dbi_next;
	
	for (dbi = ISC_LIST_HEAD(ns_g_dbs); dbi != NULL; dbi = dbi_next) {
		dbi_next = ISC_LIST_NEXT(dbi, link);
		if (dbi->db != NULL) {
			if (dns_db_iszone(dbi->db))
				dns_dbtable_remove(ns_g_dbtable, dbi->db);
			else {
				INSIST(dbi == cache_dbi);
				dns_dbtable_removedefault(ns_g_dbtable);
				cache_dbi = NULL;
			}
			dns_db_detach(&dbi->db);
		}
		ISC_LIST_UNLINK(ns_g_dbs, dbi, link);
		isc_mem_put(ns_g_mctx, dbi, sizeof *dbi);
	}
}

static void
load_configuration(void) {
	isc_result_t result;

	/* 
	 * XXXRTH  loading code below is temporary; it
	 * will be replaced by proper config file processing.
	 */

	result = load_all();
	if (result != ISC_R_SUCCESS) {
		/* XXXRTH */
		printf("load_all(): %s\n", isc_result_totext(result));
	}

	ns_interfacemgr_scan(ns_g_interfacemgr);
}

static void
run_server(isc_task_t *task, isc_event_t *event) {

	(void)task;
	printf("server running\n");

	load_configuration();

	isc_event_free(&event);
}

static void
shutdown_server(isc_task_t *task, isc_event_t *event) {
	(void)task;
	printf("server shutting down\n");
	unload_all();
	dns_dbtable_detach(&ns_g_dbtable);
	isc_task_detach(&server_task);
	isc_event_free(&event);
}

isc_result_t
ns_server_init(void) {
	isc_result_t result;
#if 0
	dns_view_t *view = NULL;
#endif

	result = dns_dbtable_create(ns_g_mctx, dns_rdataclass_in,
				    &ns_g_dbtable);
	if (result != ISC_R_SUCCESS)
		return (result);
	
#if 0
	result = dns_view_create(ns_g_viewmgr, dns_rdataclass_in, "default/IN",
				 ns_g_dbtable, NULL, &view);
	if (result != ISC_R_SUCCESS)
		goto cleanup_dbtable;
#endif

	result = isc_task_create(ns_g_taskmgr, ns_g_mctx, 0, &server_task);
	if (result != ISC_R_SUCCESS)
		goto cleanup_view;

	result = isc_task_onshutdown(server_task, shutdown_server, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	result = isc_app_onrun(ns_g_mctx, server_task, run_server, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup_task;

	return (ISC_R_SUCCESS);

 cleanup_task:
	isc_task_detach(&server_task);

 cleanup_view:
#if 0
	dns_view_detach(&view);

 cleanup_dbtable:
#endif
	dns_dbtable_detach(&ns_g_dbtable);

	return (result);
}
