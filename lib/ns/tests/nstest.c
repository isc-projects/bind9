/*
 * Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*! \file */

#include <config.h>

#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/socket.h>
#include <isc/stdio.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/result.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <ns/client.h>
#include <ns/interfacemgr.h>
#include <ns/server.h>

#include "nstest.h"

isc_mem_t *mctx = NULL;
isc_entropy_t *ectx = NULL;
isc_log_t *lctx = NULL;
isc_taskmgr_t *taskmgr = NULL;
isc_task_t *maintask = NULL;
isc_timermgr_t *timermgr = NULL;
isc_socketmgr_t *socketmgr = NULL;
dns_zonemgr_t *zonemgr = NULL;
dns_dispatchmgr_t *dispatchmgr = NULL;
ns_clientmgr_t *clientmgr = NULL;
ns_interfacemgr_t *interfacemgr = NULL;
ns_server_t *sctx = NULL;
isc_boolean_t app_running = ISC_FALSE;
int ncpus;
isc_boolean_t debug_mem_record = ISC_TRUE;
isc_boolean_t run_managers = ISC_FALSE;

static isc_boolean_t hash_active = ISC_FALSE, dst_active = ISC_FALSE;

/*
 * Logging categories: this needs to match the list in lib/ns/log.c.
 */
static isc_logcategory_t categories[] = {
		{ "",                0 },
		{ "client",          0 },
		{ "network",         0 },
		{ "update",          0 },
		{ "queries",         0 },
		{ "unmatched",       0 },
		{ "update-security", 0 },
		{ "query-errors",    0 },
		{ NULL,              0 }
};

static isc_result_t
matchview(isc_netaddr_t *srcaddr, isc_netaddr_t *destaddr,
	  dns_message_t *message, dns_ecs_t *ecs,
	  isc_result_t *sigresultp, dns_view_t **viewp)
{
	UNUSED(srcaddr);
	UNUSED(destaddr);
	UNUSED(message);
	UNUSED(ecs);
	UNUSED(sigresultp);
	UNUSED(viewp);

	return (ISC_R_NOTIMPLEMENTED);
}

/*
 * These need to be shut down from a running task.
 */
isc_boolean_t shutdown_done = ISC_FALSE;
static void
shutdown_managers(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);

	if (clientmgr != NULL) {
		ns_clientmgr_destroy(&clientmgr);
	}

	if (interfacemgr != NULL) {
		ns_interfacemgr_shutdown(interfacemgr);
		ns_interfacemgr_detach(&interfacemgr);
	}

	if (dispatchmgr != NULL) {
		dns_dispatchmgr_destroy(&dispatchmgr);
	}

	shutdown_done = ISC_TRUE;
	run_managers = ISC_FALSE;

	isc_event_free(&event);
}

static void
cleanup_managers(void) {
	if (app_running)
		isc_app_finish();

	shutdown_done = ISC_FALSE;

	if (maintask != NULL) {
		isc_task_shutdown(maintask);
		isc_task_destroy(&maintask);
	}

	while (run_managers && !shutdown_done) {
#ifndef ISC_PLATFORM_USETHREADS
		while (isc__taskmgr_ready(taskmgr))
			isc__taskmgr_dispatch(taskmgr);
#else
		/*
		 * There's no straightforward way to determine
		 * whether all the clients have shut down, so
		 * we'll just sleep for a bit and hope.
		 */
		ns_test_nap(500000);
#endif
	}

	if (timermgr != NULL)
		isc_timermgr_destroy(&timermgr);
	if (sctx != NULL)
		ns_server_detach(&sctx);
	if (socketmgr != NULL)
		isc_socketmgr_destroy(&socketmgr);
	if (taskmgr != NULL)
		isc_taskmgr_destroy(&taskmgr);
}

static void
scan_interfaces(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);

	ns_interfacemgr_scan(interfacemgr, ISC_TRUE);
	isc_event_free(&event);
}

static isc_result_t
create_managers(void) {
	isc_result_t result;
	ns_listenlist_t *listenon = NULL;
	isc_event_t *event = NULL;
#ifdef ISC_PLATFORM_USETHREADS
	ncpus = isc_os_ncpus();
#else
	ncpus = 1;
#endif

	CHECK(isc_taskmgr_create(mctx, ncpus, 0, &taskmgr));
	CHECK(isc_task_create(taskmgr, 0, &maintask));
	isc_taskmgr_setexcltask(taskmgr, maintask);
	CHECK(isc_task_onshutdown(maintask, shutdown_managers, NULL));

	CHECK(isc_timermgr_create(mctx, &timermgr));

	CHECK(isc_socketmgr_create(mctx, &socketmgr));

	CHECK(ns_server_create(mctx, ectx, matchview, &sctx));

	CHECK(dns_dispatchmgr_create(mctx, ectx, &dispatchmgr));

	CHECK(ns_interfacemgr_create(mctx, sctx, taskmgr, timermgr,
				     socketmgr, dispatchmgr, maintask,
				     ncpus, NULL, &interfacemgr));

	CHECK(ns_clientmgr_create(mctx, sctx, taskmgr, timermgr,
				  &clientmgr));

	CHECK(ns_listenlist_default(mctx, 5300, -1, ISC_TRUE, &listenon));
	ns_interfacemgr_setlistenon4(interfacemgr, listenon);
	ns_listenlist_detach(&listenon);

	event = isc_event_allocate(mctx, maintask, ISC_TASKEVENT_TEST,
				   scan_interfaces, NULL,
				   sizeof (isc_event_t));
	isc_task_send(maintask, &event);
#ifndef ISC_PLATFORM_USETHREADS
	while (isc__taskmgr_ready(taskmgr))
		isc__taskmgr_dispatch(taskmgr);
#else
	/*
	 * There's no straightforward way to determine
	 * whether the interfaces have been scanned,
	 * we'll just sleep for a bit and hope.
	 */
	ns_test_nap(500000);
#endif

	run_managers = ISC_TRUE;

	return (ISC_R_SUCCESS);

  cleanup:
	cleanup_managers();
	return (result);
}

isc_result_t
ns_test_begin(FILE *logfile, isc_boolean_t start_managers) {
	isc_result_t result;

	if (start_managers)
		CHECK(isc_app_start());
	if (debug_mem_record)
		isc_mem_debugging |= ISC_MEM_DEBUGRECORD;
	CHECK(isc_mem_create(0, 0, &mctx));
	CHECK(isc_entropy_create(mctx, &ectx));

	CHECK(isc_hash_create(mctx, ectx, DNS_NAME_MAXWIRE));
	hash_active = ISC_TRUE;

	CHECK(dst_lib_init(mctx, ectx, ISC_ENTROPY_BLOCKING));
	dst_active = ISC_TRUE;

	if (logfile != NULL) {
		isc_logdestination_t destination;
		isc_logconfig_t *logconfig = NULL;

		CHECK(isc_log_create(mctx, &lctx, &logconfig));
		isc_log_registercategories(lctx, categories);
		isc_log_setcontext(lctx);
		dns_log_init(lctx);
		dns_log_setcontext(lctx);

		destination.file.stream = logfile;
		destination.file.name = NULL;
		destination.file.versions = ISC_LOG_ROLLNEVER;
		destination.file.maximum_size = 0;
		CHECK(isc_log_createchannel(logconfig, "stderr",
					    ISC_LOG_TOFILEDESC,
					    ISC_LOG_DYNAMIC,
					    &destination, 0));
		CHECK(isc_log_usechannel(logconfig, "stderr", NULL, NULL));
	}

	dns_result_register();

	if (start_managers)
		CHECK(create_managers());

	/*
	 * atf-run changes us to a /tmp directory, so tests
	 * that access test data files must first chdir to the proper
	 * location.
	 */
	if (chdir(TESTS) == -1)
		CHECK(ISC_R_FAILURE);

	return (ISC_R_SUCCESS);

  cleanup:
	ns_test_end();
	return (result);
}

void
ns_test_end(void) {
	if (dst_active) {
		dst_lib_destroy();
		dst_active = ISC_FALSE;
	}

	cleanup_managers();

	if (hash_active) {
		isc_hash_destroy();
		hash_active = ISC_FALSE;
	}

	if (ectx != NULL)
		isc_entropy_detach(&ectx);

	if (lctx != NULL)
		isc_log_destroy(&lctx);

	if (mctx != NULL)
		isc_mem_destroy(&mctx);
}

/*
 * Create a view.
 */
isc_result_t
ns_test_makeview(const char *name, dns_view_t **viewp) {
	isc_result_t result;
	dns_view_t *view = NULL;

	CHECK(dns_view_create(mctx, dns_rdataclass_in, name, &view));
	*viewp = view;

	return (ISC_R_SUCCESS);

 cleanup:
	if (view != NULL)
		dns_view_detach(&view);
	return (result);
}

/*
 * Create a zone with origin 'name', return a pointer to the zone object in
 * 'zonep'.  If 'view' is set, add the zone to that view; otherwise, create
 * a new view for the purpose.
 *
 * If the created view is going to be needed by the caller subsequently,
 * then 'keepview' should be set to true; this will prevent the view
 * from being detached.  In this case, the caller is responsible for
 * detaching the view.
 */
isc_result_t
ns_test_makezone(const char *name, dns_zone_t **zonep, dns_view_t *view,
		 isc_boolean_t keepview)
{
	isc_result_t result;
	dns_zone_t *zone = NULL;
	isc_buffer_t buffer;
	dns_fixedname_t fixorigin;
	dns_name_t *origin;

	if (view == NULL)
		CHECK(dns_view_create(mctx, dns_rdataclass_in, "view", &view));
	else if (!keepview)
		keepview = ISC_TRUE;

	zone = *zonep;
	if (zone == NULL)
		CHECK(dns_zone_create(&zone, mctx));

	isc_buffer_constinit(&buffer, name, strlen(name));
	isc_buffer_add(&buffer, strlen(name));
	dns_fixedname_init(&fixorigin);
	origin = dns_fixedname_name(&fixorigin);
	CHECK(dns_name_fromtext(origin, &buffer, dns_rootname, 0, NULL));
	CHECK(dns_zone_setorigin(zone, origin));
	dns_zone_setview(zone, view);
	dns_zone_settype(zone, dns_zone_master);
	dns_zone_setclass(zone, view->rdclass);
	dns_view_addzone(view, zone);

	if (!keepview)
		dns_view_detach(&view);

	*zonep = zone;

	return (ISC_R_SUCCESS);

  cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (view != NULL)
		dns_view_detach(&view);
	return (result);
}

isc_result_t
ns_test_setupzonemgr(void) {
	isc_result_t result;
	REQUIRE(zonemgr == NULL);

	result = dns_zonemgr_create(mctx, taskmgr, timermgr, socketmgr,
				    &zonemgr);
	return (result);
}

isc_result_t
ns_test_managezone(dns_zone_t *zone) {
	isc_result_t result;
	REQUIRE(zonemgr != NULL);

	result = dns_zonemgr_setsize(zonemgr, 1);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_zonemgr_managezone(zonemgr, zone);
	return (result);
}

void
ns_test_releasezone(dns_zone_t *zone) {
	REQUIRE(zonemgr != NULL);
	dns_zonemgr_releasezone(zonemgr, zone);
}

void
ns_test_closezonemgr(void) {
	REQUIRE(zonemgr != NULL);

	dns_zonemgr_shutdown(zonemgr);
	dns_zonemgr_detach(&zonemgr);
}

isc_result_t
ns_test_getclient(ns_interface_t *ifp0, isc_boolean_t tcp,
		  ns_client_t **clientp)
{
	isc_result_t result;
	ns_interface_t *ifp = ifp0;

	if (ifp == NULL) {
		ifp = ns__interfacemgr_getif(interfacemgr);
	}
	if (ifp == NULL) {
		return (ISC_R_FAILURE);
	}

	result = ns__clientmgr_getclient(clientmgr, ifp, tcp, clientp);
	return (result);
}

/*
 * Sleep for 'usec' microseconds.
 */
void
ns_test_nap(isc_uint32_t usec) {
#ifdef HAVE_NANOSLEEP
	struct timespec ts;

	ts.tv_sec = usec / 1000000;
	ts.tv_nsec = (usec % 1000000) * 1000;
	nanosleep(&ts, NULL);
#elif HAVE_USLEEP
	usleep(usec);
#else
	/*
	 * No fractional-second sleep function is available, so we
	 * round up to the nearest second and sleep instead
	 */
	sleep((usec / 1000000) + 1);
#endif
}

isc_result_t
ns_test_loaddb(dns_db_t **db, dns_dbtype_t dbtype, const char *origin,
	       const char *testfile)
{
	isc_result_t		result;
	dns_fixedname_t		fixed;
	dns_name_t		*name;

	dns_fixedname_init(&fixed);
	name = dns_fixedname_name(&fixed);

	result = dns_name_fromstring(name, origin, 0, NULL);
	if (result != ISC_R_SUCCESS)
		return(result);

	result = dns_db_create(mctx, "rbt", name, dbtype, dns_rdataclass_in,
			       0, NULL, db);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_db_load(*db, testfile);
	return (result);
}

static int
fromhex(char c) {
	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);

	printf("bad input format: %02x\n", c);
	exit(3);
	/* NOTREACHED */
}

isc_result_t
ns_test_getdata(const char *file, unsigned char *buf,
		 size_t bufsiz, size_t *sizep)
{
	isc_result_t result;
	unsigned char *bp;
	char *rp, *wp;
	char s[BUFSIZ];
	size_t len, i;
	FILE *f = NULL;
	int n;

	result = isc_stdio_open(file, "r", &f);
	if (result != ISC_R_SUCCESS)
		return (result);

	bp = buf;
	while (fgets(s, sizeof(s), f) != NULL) {
		rp = s;
		wp = s;
		len = 0;
		while (*rp != '\0') {
			if (*rp == '#')
				break;
			if (*rp != ' ' && *rp != '\t' &&
			    *rp != '\r' && *rp != '\n') {
				*wp++ = *rp;
				len++;
			}
			rp++;
		}
		if (len == 0U)
			continue;
		if (len % 2 != 0U)
			CHECK(ISC_R_UNEXPECTEDEND);
		if (len > bufsiz * 2)
			CHECK(ISC_R_NOSPACE);
		rp = s;
		for (i = 0; i < len; i += 2) {
			n = fromhex(*rp++);
			n *= 16;
			n += fromhex(*rp++);
			*bp++ = n;
		}
	}


	*sizep = bp - buf;

	result = ISC_R_SUCCESS;

 cleanup:
	isc_stdio_close(f);
	return (result);
}
