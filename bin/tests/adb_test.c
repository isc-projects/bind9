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
#include <dns/cache.h>
#include <dns/db.h>
#include <dns/master.h>
#include <dns/name.h>
#include <dns/log.h>

typedef struct client client_t;
struct client {
	dns_name_t		name;
	ISC_LINK(client_t)	link;
	dns_adbfind_t	       *find;
};

isc_mem_t *mctx;
isc_mempool_t *cmp;
isc_log_t *lctx;
isc_taskmgr_t *taskmgr;
isc_socketmgr_t *socketmgr;
isc_timermgr_t *timermgr;
isc_task_t *t1, *t2;
dns_view_t *view;
dns_db_t *rootdb;
ISC_LIST(client_t) clients;
isc_mutex_t client_lock;
isc_stdtime_t now;
dns_adb_t *adb;

static void check_result(isc_result_t, char *, ...);
isc_result_t ns_rootns_init(void);
void create_managers(void);
static void lookup_callback(isc_task_t *, isc_event_t *);
void create_view(void);
client_t *new_client(void);
void free_client(client_t **);
static inline void CLOCK(void);
static inline void CUNLOCK(void);
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
	isc_result_t result, eresult;
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

client_t *
new_client(void)
{
	client_t *client;

	client = isc_mempool_get(cmp);
	INSIST(client != NULL);
	dns_name_init(&client->name, NULL);
	ISC_LINK_INIT(client, link);
	client->find = NULL;

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
	INSIST(client->find == NULL);

	isc_mempool_put(cmp, client);
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
	client_t *client;

	client = ev->arg;
	INSIST(client->find == ev->sender);

	printf("Task %p got event %p type %08x from %p, client %p\n",
	       task, ev, ev->type, client->find, client);

	isc_event_free(&ev);

	CLOCK();

	dns_adb_dumpfind(client->find, stderr);
	dns_adb_destroyfind(&client->find);

	ISC_LIST_UNLINK(clients, client, link);
	free_client(&client);

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
	dns_cache_t *cache;
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
	cache = NULL;
	result = dns_cache_create(mctx, taskmgr, timermgr, dns_rdataclass_in,
				  "rbt", 0, NULL, &cache);
	check_result(result, "dns_cache_create");
	dns_view_setcache(view, cache);
	dns_cache_detach(&cache);

	/*
	 * Resolver.
	 *
	 * XXXRTH hardwired number of tasks.  Also, we'll need to
	 * see if we are dealing with a shared dispatcher in this view.
	 */
	result = dns_view_createresolver(view, taskmgr, 16, socketmgr,
					 timermgr, NULL);
	check_result(result, "dns_view_createresolver()");

	result = ns_rootns_init();
	check_result(result, "ns_rootns_init()");
	dns_view_sethints(view, rootdb);
	dns_db_detach(&rootdb);

	dns_view_freeze(view);
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
	result = _dns_adb_insert(adb, &name, &sockaddr, ttl, now);
	check_result(result, "_dns_adb_insert %s -> %s", target, addr);
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
	unsigned int options;

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

	options = 0;
	options |= DNS_ADBFIND_INET;
	options |= DNS_ADBFIND_INET6;
	options |= DNS_ADBFIND_WANTEVENT;
	result = dns_adb_createfind(adb, t2, lookup_callback, client,
				    &client->name, dns_rootname, options,
				    now, &client->find);
	check_result(result, "dns_adb_lookup()");
	dns_adb_dumpfind(client->find, stderr);

	if ((client->find->options & DNS_ADBFIND_WANTEVENT) != 0)
		ISC_LIST_APPEND(clients, client, link);
	else {
		dns_adb_destroyfind(&client->find);
		free_client(&client);
	}
}

int
main(int argc, char **argv)
{
	isc_result_t result;
	isc_logdestination_t destination;

	(void)argc;
	(void)argv;

	dns_result_register();
	result = isc_app_start();
	check_result(result, "isc_app_start()");

	isc_stdtime_get(&now);

	result = isc_mutex_init(&client_lock);
	check_result(result, "isc_mutex_init(&client_lock)");
	ISC_LIST_INIT(clients);

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	cmp = NULL;
	RUNTIME_CHECK(isc_mempool_create(mctx, sizeof(client_t), &cmp)
		      == ISC_R_SUCCESS);
	isc_mempool_setname(cmp, "adb test clients");

	result = isc_log_create(mctx, &lctx);
	check_result(result, "isc_log_create()");

	result = dns_log_init(lctx);
	check_result(result, "dns_log_init()");

	/*
	 * Create and install the default channel.
	 */
	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	result = isc_log_createchannel(lctx, "_default",
				       ISC_LOG_TOFILEDESC,
				       ISC_LOG_DYNAMIC,
				       &destination, ISC_LOG_PRINTTIME);
	check_result(result, "isc_log_createchannel()");
	result = isc_log_usechannel(lctx, "_default", NULL, NULL);
	check_result(result, "isc_log_usechannel()");

	/*
	 * Set the initial debug level.
	 */
	isc_log_setdebuglevel(lctx, 99);

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

	adb = view->adb;

	/*
	 * Lock the entire client list here.  This will cause all events
	 * for found names to block as well.
	 */
	CLOCK();
	lookup("f.root-servers.net.");		/* Should be in hints */
	lookup("www.iengines.com");		/* should fetch */
	lookup("www.isc.org");			/* should fetch */
	lookup("www.flame.org");		/* should fetch */
	lookup("kechara.flame.org.");		/* should fetch */
	lookup("moghedien.flame.org.");		/* should fetch */
	lookup("mailrelay.flame.org.");		/* should fetch */
	lookup("ipv4v6.flame.org.");		/* should fetch */
	lookup("nonexistant.flame.org.");	/* should fail to be found */
	lookup("foobar.badns.flame.org.");	/* should fail utterly (NS) */
	lookup("i.root-servers.net.");		/* Should be in hints */
	CUNLOCK();

	sleep(5);

	dns_adb_dump(adb, stderr);

	sleep (5);

	CLOCK();
	lookup("f.root-servers.net.");		/* Should be in hints */
	lookup("www.iengines.com");		/* should fetch */
	lookup("www.isc.org");			/* should fetch */
	lookup("www.flame.org");		/* should fetch */
	lookup("kechara.flame.org.");		/* should fetch */
	lookup("moghedien.flame.org.");		/* should fetch */
	lookup("mailrelay.flame.org.");		/* should fetch */
	lookup("ipv4v6.flame.org.");		/* should fetch */
	lookup("nonexistant.flame.org.");	/* should fail to be found */
	lookup("foobar.badns.flame.org.");	/* should fail utterly (NS) */
	lookup("i.root-servers.net.");		/* Should be in hints */
	CUNLOCK();

	dns_adb_dump(adb, stderr);

	isc_task_detach(&t1);
	isc_task_detach(&t2);

	isc_mem_stats(mctx, stdout);
	dns_adb_dump(adb, stderr);

	isc_app_run();

	dns_adb_dump(adb, stderr);

	dns_view_detach(&view);
	adb = NULL;

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&taskmgr);

	isc_log_destroy(&lctx);

	isc_mempool_destroy(&cmp);
	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
