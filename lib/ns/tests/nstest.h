/*
 * Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*! \file */

#include <config.h>

#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/result.h>
#include <dns/zone.h>

#include <ns/interfacemgr.h>
#include <ns/client.h>

#define CHECK(r) \
	do { \
		result = (r); \
		if (result != ISC_R_SUCCESS) \
			goto cleanup; \
	} while (0)

extern isc_mem_t *mctx;
extern isc_entropy_t *ectx;
extern isc_log_t *lctx;
extern isc_taskmgr_t *taskmgr;
extern isc_task_t *maintask;
extern isc_timermgr_t *timermgr;
extern isc_socketmgr_t *socketmgr;
extern dns_zonemgr_t *zonemgr;
extern dns_dispatchmgr_t *dispatchmgr;
extern ns_clientmgr_t *clientmgr;
extern ns_interfacemgr_t *interfacemgr;
extern ns_server_t *sctx;
extern isc_boolean_t app_running;
extern int ncpus;
extern isc_boolean_t debug_mem_record;

isc_result_t
ns_test_begin(FILE *logfile, isc_boolean_t create_managers);

void
ns_test_end(void);

isc_result_t
ns_test_makeview(const char *name, dns_view_t **viewp);

isc_result_t
ns_test_makezone(const char *name, dns_zone_t **zonep, dns_view_t *view,
				  isc_boolean_t keepview);

isc_result_t
ns_test_setupzonemgr(void);

isc_result_t
ns_test_managezone(dns_zone_t *zone);

void
ns_test_releasezone(dns_zone_t *zone);

void
ns_test_closezonemgr(void);

void
ns_test_nap(isc_uint32_t usec);

isc_result_t
ns_test_loaddb(dns_db_t **db, dns_dbtype_t dbtype, const char *origin,
	       const char *testfile);

isc_result_t
ns_test_getdata(const char *file, unsigned char *buf,
		size_t bufsiz, size_t *sizep);

isc_result_t
ns_test_getclient(ns_interface_t *ifp0, isc_boolean_t tcp,
		  ns_client_t **clientp);
