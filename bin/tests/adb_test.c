/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/timer.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/net.h>

#include <dns/address.h>
#include <dns/db.h>
#include <dns/master.h>
#include <dns/name.h>

isc_mem_t *mctx;
isc_taskmgr_t *manager;
isc_socketmgr_t *socketmgr;
isc_timermgr_t *timermgr;
unsigned char namestorage1[512];
unsigned char namestorage2[512];
unsigned char namestorage3[512];
unsigned char namestorage4[512];
dns_view_t *view;
dns_db_t *ns_g_rootns;

static void lookup_callback(isc_task_t *, isc_event_t *);
static void fatal(char *, ...);
static inline void check_result(isc_result_t, char *);

static void
fatal(char *format, ...)
{
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

static inline void
check_result(isc_result_t result, char *msg)
{
	if (result != ISC_R_SUCCESS)
		fatal("%s: %s", msg, isc_result_totext(result));
}

static char root_ns[] =
";\n"
"; Internet Root Nameservers\n"
";\n"
"; Thu Sep 23 17:57:37 PDT 1999\n"
";\n"
"$TTL 518400\n"
".                       518400  IN      NS      F.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      B.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      J.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      K.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      L.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      M.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      I.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      E.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      D.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      A.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      H.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      C.ROOT-SERVERS.NET.\n"
".                       518400  IN      NS      G.ROOT-SERVERS.NET.\n"
"F.ROOT-SERVERS.NET.     3600000 IN      A       192.5.5.241\n"
"B.ROOT-SERVERS.NET.     3600000 IN      A       128.9.0.107\n"
"J.ROOT-SERVERS.NET.     3600000 IN      A       198.41.0.10\n"
"K.ROOT-SERVERS.NET.     3600000 IN      A       193.0.14.129\n"
"L.ROOT-SERVERS.NET.     3600000 IN      A       198.32.64.12\n"
"M.ROOT-SERVERS.NET.     3600000 IN      A       202.12.27.33\n"
"I.ROOT-SERVERS.NET.     3600000 IN      A       192.36.148.17\n"
"E.ROOT-SERVERS.NET.     3600000 IN      A       192.203.230.10\n"
"D.ROOT-SERVERS.NET.     3600000 IN      A       128.8.10.90\n"
"A.ROOT-SERVERS.NET.     3600000 IN      A       198.41.0.4\n"
"H.ROOT-SERVERS.NET.     3600000 IN      A       128.63.2.53\n"
"C.ROOT-SERVERS.NET.     3600000 IN      A       192.33.4.12\n"
"G.ROOT-SERVERS.NET.     3600000 IN      A       192.112.36.4\n";

isc_result_t
ns_rootns_init(void)
{
	dns_result_t result, eresult;
	isc_buffer_t source;
	size_t len;
	int soacount, nscount;
	dns_rdatacallbacks_t callbacks;

	REQUIRE(ns_g_rootns == NULL);

	result = dns_db_create(mctx, "rbt", dns_rootname, ISC_FALSE,
			       dns_rdataclass_in, 0, NULL, &ns_g_rootns);
	if (result != ISC_R_SUCCESS)
		return (result);

	dns_rdatacallbacks_init(&callbacks);

	len = strlen(root_ns);
	isc_buffer_init(&source, root_ns, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);

	result = dns_db_beginload(ns_g_rootns, &callbacks.add,
				  &callbacks.add_private);
	if (result != ISC_R_SUCCESS)
		return (result);
	result = dns_master_loadbuffer(&source, &ns_g_rootns->origin,
				       &ns_g_rootns->origin,
				       ns_g_rootns->rdclass, ISC_FALSE,
				       &soacount, &nscount, &callbacks,
				       ns_g_rootns->mctx);
	eresult = dns_db_endload(ns_g_rootns, &callbacks.add_private);
	if (result == ISC_R_SUCCESS)
		result = eresult;
	if (result != ISC_R_SUCCESS)
		goto db_detach;

	return (DNS_R_SUCCESS);

 db_detach:
	dns_db_detach(&ns_g_rootns);

	return (result);
}

void
ns_rootns_destroy(void)
{
	REQUIRE(ns_g_rootns != NULL);

	dns_db_detach(&ns_g_rootns);
}


static void
lookup_callback(isc_task_t *task, isc_event_t *ev)
{
	dns_name_t *name;
	dns_adbhandle_t *handle;

	printf("Task %p got event %p type %08x from %p, arg %p\n",
	       task, ev, ev->type, ev->sender, ev->arg);

	name = ev->arg;
	handle = ev->sender;

	isc_event_free(&ev);
	isc_app_shutdown();
}

void
create_managers(void)
{
	isc_result_t result;

	manager = NULL;
	result = isc_taskmgr_create(mctx, 2, 0, &manager);
	check_result(result, "isc_taskmgr_create");

	timermgr = NULL;
	result = isc_timermgr_create(mctx, &timermgr);
	check_result(result, "isc_timermgr_create");

	socketmgr = NULL;
	result = isc_socketmgr_create(mctx, &socketmgr);
	check_result(result, "isc_socketmgr_create");
}

void
create_view(void)
{
	dns_db_t *db;
	isc_result_t result;

	/*
	 * View.
	 */
	view = NULL;
	result = dns_view_create(mctx, dns_rdataclass_in, "_default", &view);
	check_result(result, "dns_view_create");

	/*
	 * Cache.
	 */
	db = NULL;
	result = dns_db_create(mctx, "rbt", dns_rootname, ISC_TRUE,
			       dns_rdataclass_in, 0, NULL, &db);
	check_result(result, "dns_view_create");
	dns_view_setcachedb(view, db);
	dns_db_detach(&db);

	/*
	 * Resolver.
	 *
	 * XXXRTH hardwired number of tasks.  Also, we'll need to
	 * see if we are dealing with a shared dispatcher in this view.
	 */
	result = dns_view_createresolver(view, manager, 16, socketmgr,
					 timermgr, NULL);
	check_result(result, "dns_view_createresolver");

	result = ns_rootns_init();
	check_result(result, "ns_rootns_init()");

	/*
	 * We have default hints for class IN.
	 */
	dns_view_sethints(view, ns_g_rootns);

	dns_view_freeze(view);
}

void
destroy_view(void)
{
	dns_view_detach(&view);
	ns_rootns_destroy();
}

int
main(int argc, char **argv)
{
	isc_task_t *t1, *t2;
	isc_sockaddr_t sockaddr;
	struct in_addr ina;
	isc_result_t result;
	dns_name_t name1, name2, name3, name4;
	isc_buffer_t t, namebuf;
	dns_adb_t *adb;
	dns_adbhandle_t *handle;
	dns_adbaddrinfo_t *ai;
	isc_stdtime_t now;

	(void)argc;
	(void)argv;

	dns_result_register();
	result = isc_app_start();
	check_result(result, "isc_app_start()");

	result = isc_stdtime_get(&now);
	check_result(result, "isc_stdtime_get()");

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	create_managers();

	t1 = NULL;
	result = isc_task_create(manager, NULL, 0, &t1);
	check_result(result, "isc_task_create t1");
	t2 = NULL;
	result = isc_task_create(manager, NULL, 0, &t2);
	check_result(result, "isc_task_create t2");

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);

	create_view();

	/*
	 * Create the address database.
	 */
	adb = NULL;
	result = dns_adb_create(mctx, view, &adb);
	check_result(result, "dns_adb_create");

#define NAME1 "kechara.flame.org."
#define NAME2 "moghedien.isc.org."
#define NAME3 "nonexistant.flame.org."
#define NAME4 "f.root-servers.net."

	isc_buffer_init(&t, NAME1, sizeof NAME1 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME1));
	isc_buffer_init(&namebuf, namestorage1, sizeof namestorage1,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name1, NULL);
	result = dns_name_fromtext(&name1, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext NAME1");

	isc_buffer_init(&t, NAME2, sizeof NAME2 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME2));
	isc_buffer_init(&namebuf, namestorage2, sizeof namestorage2,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name2, NULL);
	result = dns_name_fromtext(&name2, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext NAME2");

	isc_buffer_init(&t, NAME3, sizeof NAME3 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME3));
	isc_buffer_init(&namebuf, namestorage3, sizeof namestorage3,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name3, NULL);
	result = dns_name_fromtext(&name3, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext NAME3");

	isc_buffer_init(&t, NAME4, sizeof NAME4 - 1, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(NAME4));
	isc_buffer_init(&namebuf, namestorage4, sizeof namestorage4,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name4, NULL);
	result = dns_name_fromtext(&name4, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext NAME4");

	/*
	 * Store this address for this name.
	 */
	ina.s_addr = inet_addr("1.2.3.4");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name1, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.4");
	printf("Added 1.2.3.4 -> NAME1\n");

	ina.s_addr = inet_addr("1.2.3.5");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name1, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.5");
	printf("Added 1.2.3.5 -> NAME1\n");

	result = dns_adb_insert(adb, &name2, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.5");
	printf("Added 1.2.3.5 -> NAME2\n");

	ina.s_addr = inet_addr("1.2.3.6");
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name1, &sockaddr);
	check_result(result, "dns_adb_insert 1.2.3.6");
	printf("Added 1.2.3.6 -> NAME1\n");

	/*
	 * Try to look up a name or two.
	 */
	handle = NULL;
	result = dns_adb_lookup(adb, t2, lookup_callback, &name1,
				&name1, &name1, now, &handle);
	check_result(result, "dns_adb_lookup name1");
	check_result(handle->result, "handle->result");

	dns_adb_dump(adb, stderr);
	dns_adb_dumphandle(adb, handle, stderr);

	/*
	 * Mark one entry as lame, then look this name up again.
	 */
	ai = ISC_LIST_HEAD(handle->list);
	INSIST(ai != NULL);
	ai = ISC_LIST_NEXT(ai, link);
	INSIST(ai != NULL);
	result = dns_adb_marklame(adb, ai, &name1, now + 10 * 60);
	check_result(result, "dns_adb_marklame()");

	/*
	 * And while we're here, add some goodness to it and tweak up
	 * the srtt value a bit.
	 */
	dns_adb_adjustgoodness(adb, ai, 100);
	dns_adb_adjustgoodness(adb, ai, -50);
	INSIST(ai->goodness == 50);
	dns_adb_adjustsrtt(adb, ai, 10000, 0);
	dns_adb_adjustsrtt(adb, ai, 10, 10);

	dns_adb_done(adb, &handle);

	/*
	 * look it up again
	 */
	result = dns_adb_lookup(adb, t2, lookup_callback, &name1,
				&name1, &name1, now, &handle);
	check_result(result, "dns_adb_lookup name1");
	check_result(handle->result, "handle->result");

	dns_adb_dump(adb, stderr);
	dns_adb_dumphandle(adb, handle, stderr);

	/*
	 * delete one of the names
	 */
	result = dns_adb_deletename(adb, &name2);
	check_result(result, "dns_adb_deletename name2");

	dns_adb_dump(adb, stderr);

	dns_adb_done(adb, &handle);

	/*
	 * look up a name that doesn't exit.
	 */
	result = dns_adb_lookup(adb, t2, lookup_callback, &name3,
				&name3, &name3, now, &handle);
	if (result == ISC_R_SUCCESS) {
		check_result(handle->result, "handle->result");

		check_result(result, "dns_adb_lookup name3");
		dns_adb_dump(adb, stderr);
		dns_adb_dumphandle(adb, handle, stderr);
	} else {
		fprintf(stderr, "lookup of name3: %s\n",
			isc_result_totext(result));
	}

	dns_adb_dump(adb, stderr);

	if (handle != NULL)
		dns_adb_done(adb, &handle);

	/*
	 * Look up a host that will be in the hints database
	 */
	result = dns_adb_lookup(adb, t2, lookup_callback, &name4,
				&name4, dns_rootname, now, &handle);
	if (result == ISC_R_SUCCESS) {
		check_result(handle->result, "handle->result");

		check_result(result, "dns_adb_lookup name4");
		dns_adb_dump(adb, stderr);
		dns_adb_dumphandle(adb, handle, stderr);
	} else {
		fprintf(stderr, "lookup of name4: %s\n",
			isc_result_totext(result));
	}

	dns_adb_dump(adb, stderr);

	if (handle != NULL) {
		dns_adb_dumphandle(adb, handle, stderr);
		dns_adb_done(adb, &handle);
	}

	isc_task_detach(&t1);
	isc_task_detach(&t2);

	isc_mem_stats(mctx, stdout);
	dns_adb_dump(adb, stderr);
	dns_adb_destroy(&adb);

	isc_app_run();

	destroy_view();

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
