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

#include <dns/adb.h>
#include <dns/db.h>
#include <dns/master.h>
#include <dns/name.h>

typedef struct client client_t;
struct client {
	dns_name_t		name;
	ISC_LINK(client_t)	link;
	dns_adbhandle_t	       *handle;
};

isc_mem_t *mctx;
isc_taskmgr_t *taskmgr;
isc_socketmgr_t *socketmgr;
isc_timermgr_t *timermgr;
isc_task_t *t1, *t2;
dns_view_t *view;
dns_db_t *rootdb;
ISC_LIST(client_t) clients;
ISC_LIST(client_t) dead_clients;
isc_mutex_t client_lock;
isc_stdtime_t now;
dns_adb_t *adb;

static void check_result(isc_result_t, char *, ...);

isc_result_t ns_rootns_init(void);
void ns_rootns_destroy(void);

void create_managers(void);

static void lookup_callback(isc_task_t *, isc_event_t *);

void create_view(void);
void destroy_view(void);

client_t *new_client(void);
void free_client(client_t **);
static inline void CLOCK(void);
static inline void CUNLOCK(void);
void clean_dead_client_list(void);

void lookup(char *);
void insert(char *, char *, dns_ttl_t, isc_stdtime_t);

static void
check_result(isc_result_t result, char *format, ...)
{
	va_list args;

	if (result == ISC_R_SUCCESS)
		return;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
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

	rootdb = NULL;
	result = dns_db_create(mctx, "rbt", dns_rootname, ISC_FALSE,
			       dns_rdataclass_in, 0, NULL, &rootdb);
	if (result != ISC_R_SUCCESS)
		return (result);

	dns_rdatacallbacks_init(&callbacks);

	len = strlen(root_ns);
	isc_buffer_init(&source, root_ns, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);

	result = dns_db_beginload(rootdb, &callbacks.add,
				  &callbacks.add_private);
	if (result != ISC_R_SUCCESS)
		return (result);
	result = dns_master_loadbuffer(&source, &rootdb->origin,
				       &rootdb->origin,
				       rootdb->rdclass, ISC_FALSE,
				       &soacount, &nscount, &callbacks,
				       rootdb->mctx);
	eresult = dns_db_endload(rootdb, &callbacks.add_private);
	if (result == ISC_R_SUCCESS)
		result = eresult;
	if (result != ISC_R_SUCCESS)
		goto db_detach;

	return (DNS_R_SUCCESS);

 db_detach:
	dns_db_detach(&rootdb);

	return (result);
}

void
ns_rootns_destroy(void)
{
	REQUIRE(rootdb != NULL);

	dns_db_detach(&rootdb);
}

client_t *
new_client(void)
{
	client_t *client;

	client = isc_mem_get(mctx, sizeof(client_t));
	INSIST(client != NULL);
	dns_name_init(&client->name, NULL);
	ISC_LINK_INIT(client, link);
	client->handle = NULL;

	return (client);
}

void
free_client(client_t **c)
{
	client_t *client;

	INSIST(c != NULL);
	client = *c;
	*c = NULL;
	INSIST(client != NULL);
	dns_name_free(&client->name, mctx);
	INSIST(!ISC_LINK_LINKED(client, link));
	INSIST(client->handle == NULL);

	isc_mem_put(mctx, client, sizeof(client_t));
}

static inline void
CLOCK(void)
{
	RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
}

static inline void
CUNLOCK(void)
{
	RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);
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

	CLOCK();

	isc_event_free(&ev);
	isc_app_shutdown();

	CUNLOCK();
}

void
create_managers(void)
{
	isc_result_t result;

	taskmgr = NULL;
	result = isc_taskmgr_create(mctx, 2, 0, &taskmgr);
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
	result = dns_view_createresolver(view, taskmgr, 16, socketmgr,
					 timermgr, NULL);
	check_result(result, "dns_view_createresolver");

	result = ns_rootns_init();
	check_result(result, "ns_rootns_init()");

	/*
	 * We have default hints for class IN.
	 */
	dns_view_sethints(view, rootdb);

	dns_view_freeze(view);
}

void
destroy_view(void)
{
	dns_view_detach(&view);
	ns_rootns_destroy();
}

void
insert(char *target, char *addr, dns_ttl_t ttl, isc_stdtime_t now)
{
	isc_sockaddr_t sockaddr;
	struct in_addr ina;
	dns_name_t name;
	unsigned char namedata[256];
	isc_buffer_t t, namebuf;
	isc_result_t result;

	INSIST(target != NULL);

	isc_buffer_init(&t, target, strlen(target), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(target));
	isc_buffer_init(&namebuf, namedata, sizeof namedata,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name, NULL);
	result = dns_name_fromtext(&name, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext %s", target);

	ina.s_addr = inet_addr(addr);
	isc_sockaddr_fromin(&sockaddr, &ina, 53);
	result = dns_adb_insert(adb, &name, &sockaddr, ttl, now);
	check_result(result, "dns_adb_insert %s -> %s", target, addr);
	printf("Added %s -> %s\n", target, addr);
}

void
lookup(char *target)
{
	dns_name_t name;
	unsigned char namedata[256];
	client_t *client;
	isc_buffer_t t, namebuf;
	isc_result_t result;

	INSIST(target != NULL);

	client = new_client();
	isc_buffer_init(&t, target, strlen(target), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&t, strlen(target));
	isc_buffer_init(&namebuf, namedata, sizeof namedata,
			ISC_BUFFERTYPE_BINARY);
	dns_name_init(&name, NULL);
	result = dns_name_fromtext(&name, &t, dns_rootname, ISC_FALSE,
				   &namebuf);
	check_result(result, "dns_name_fromtext %s", target);

	result = dns_name_dup(&name, mctx, &client->name);
	check_result(result, "dns_name_dup %s", target);

	result = dns_adb_lookup(adb, t2, lookup_callback, client,
				&client->name, dns_rootname, now,
				&client->handle);

	switch (result) {
	case ISC_R_NOTFOUND:
		printf("Name %s not found\n", target);
		break;
	case ISC_R_SUCCESS:
		dns_adb_dumphandle(adb, client->handle, stderr);
		break;
	}
	ISC_LIST_APPEND(dead_clients, client, link);
}

void
clean_dead_client_list(void)
{
	client_t *c;

	c = ISC_LIST_HEAD(dead_clients);
	while (c != NULL) {
		fprintf(stderr, "client %p, handle %p\n", c, c->handle);
		if (c->handle != NULL)
			dns_adb_done(&c->handle);
		ISC_LIST_UNLINK(dead_clients, c, link);
		free_client(&c);
		c = ISC_LIST_HEAD(dead_clients);
	}
}

int
main(int argc, char **argv)
{
	isc_result_t result;

	(void)argc;
	(void)argv;

	dns_result_register();
	result = isc_app_start();
	check_result(result, "isc_app_start()");

	result = isc_stdtime_get(&now);
	check_result(result, "isc_stdtime_get()");

	result = isc_mutex_init(&client_lock);
	check_result(result, "isc_mutex_init(&client_lock)");
	ISC_LIST_INIT(clients);
	ISC_LIST_INIT(dead_clients);

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	create_managers();

	t1 = NULL;
	result = isc_task_create(taskmgr, NULL, 0, &t1);
	check_result(result, "isc_task_create t1");
	t2 = NULL;
	result = isc_task_create(taskmgr, NULL, 0, &t2);
	check_result(result, "isc_task_create t2");

	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);

	create_view();

	/*
	 * Create the address database.
	 */
	adb = NULL;
	result = dns_adb_create(mctx, view, timermgr, taskmgr, &adb);
	check_result(result, "dns_adb_create");

	/*
	 * Store this address for this name.
	 */
	insert("kechara.flame.org.", "204.152.184.79", 10, now);
	insert("moghedien.flame.org.", "204.152.184.97", 10, now);
	insert("mailrelay.flame.org.", "204.152.184.79", 10, now);
	insert("mailrelay.flame.org.", "204.152.184.97", 5, now);
	insert("blackhole.flame.org.", "127.0.0.1", 0, now);

	/*
	 * Lock the entire client list here.  This will cause all events
	 * for found names to block as well.
	 */
	CLOCK();
	lookup("kechara.flame.org.");
	lookup("moghedien.isc.org.");
	lookup("nonexistant.flame.org.");
	lookup("f.root-servers.net.");
	CUNLOCK();

	dns_adb_dump(adb, stderr);

	isc_task_detach(&t1);
	isc_task_detach(&t2);

	isc_mem_stats(mctx, stdout);
	dns_adb_dump(adb, stderr);
	dns_adb_detach(&adb);

	isc_app_run();

	CLOCK();
	clean_dead_client_list();
	CUNLOCK();

	destroy_view();

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&taskmgr);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
