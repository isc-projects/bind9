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

#include <sys/types.h>

#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/event.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <lwres/lwres.h>

#include "client.h"

/*
 * The goal number of clients we can handle will be NTASKS * NRECVS.
 */
#define NTASKS		10	/* tasks to create to handle lwres queries */
#define NRECVS		 5	/* max clients per task */
#define NTHREADS	 1	/* # threads to create in thread manager */

/*
 * Array of client managers.  Each of these will have a task associated
 * with it.
 */
clientmgr_t    *cmgr;
unsigned int	ntasks;	/* number of tasks actually created */

dns_view_t *view;
dns_db_t *rootdb;

isc_taskmgr_t *taskmgr;
isc_socketmgr_t *sockmgr;
isc_timermgr_t *timermgr;

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

static isc_result_t
ns_rootns_init(isc_mem_t *mctx)
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

static isc_result_t
create_view(isc_mem_t *mctx)
{
	dns_cache_t *cache;
	isc_result_t result;

	view = NULL;
	cache = NULL;

	/*
	 * View.
	 */
	result = dns_view_create(mctx, dns_rdataclass_in, "_default", &view);
	if (result != ISC_R_SUCCESS)
		goto out;

	/*
	 * Cache.
	 */
	result = dns_cache_create(mctx, taskmgr, timermgr, dns_rdataclass_in,
				  "rbt", 0, NULL, &cache);
	if (result != ISC_R_SUCCESS)
		goto out;
	dns_view_setcache(view, cache);
	dns_cache_detach(&cache);

	/*
	 * Resolver.
	 *
	 * XXXMLG hardwired number of tasks.
	 */
	result = dns_view_createresolver(view, taskmgr, 16, sockmgr,
					 timermgr, NULL);
	if (result != ISC_R_SUCCESS)
		goto out;

	result = ns_rootns_init(mctx);
	if (result != ISC_R_SUCCESS)
		goto out;
	dns_view_sethints(view, rootdb);

	dns_view_freeze(view);

	dns_db_detach(&rootdb);

	return (ISC_R_SUCCESS);

out:
	if (view != NULL)
		dns_view_detach(&view);

	dns_db_detach(&rootdb);

	return (result);
}

int
main(int argc, char **argv)
{
	isc_mem_t *mem;
	isc_socket_t *sock;
	isc_sockaddr_t localhost;
	struct in_addr lh_addr;
	isc_result_t result;
	unsigned int i, j;
	client_t *client;

	UNUSED(argc);
	UNUSED(argv);

	dns_result_register();

	result = isc_app_start();
	INSIST(result == ISC_R_SUCCESS);

	mem = NULL;
	result = isc_mem_create(0, 0, &mem);
	INSIST(result == ISC_R_SUCCESS);

	cmgr = isc_mem_get(mem, sizeof(clientmgr_t) * NTASKS);
	INSIST(cmgr != NULL);

	/*
	 * Create a task manager.
	 */
	taskmgr = NULL;
	result = isc_taskmgr_create(mem, NTHREADS, 0, &taskmgr);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Create a socket manager.
	 */
	sockmgr = NULL;
	result = isc_socketmgr_create(mem, &sockmgr);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Create a timer manager.
	 */
	timermgr = NULL;
	result = isc_timermgr_create(mem, &timermgr);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Initialize the DNS bits.  Start by loading our built-in
	 * root hints.  This should come from a file, eventually.
	 * XXXMLG
	 */
	result = create_view(mem);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * We'll need a socket.  It will be a UDP socket, and bound to
	 * 127.0.0.1 port LWRES_UDP_PORT.
	 */
	sock = NULL;
	result = isc_socket_create(sockmgr, AF_INET, isc_sockettype_udp,
				   &sock);
	INSIST(result == ISC_R_SUCCESS);

	lh_addr.s_addr = htonl(INADDR_LOOPBACK);
	isc_sockaddr_fromin(&localhost, &lh_addr, LWRES_UDP_PORT);

	result = isc_socket_bind(sock, &localhost);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Create one task for each client manager.
	 */
	for (i = 0 ; i < NTASKS ; i++) {
		cmgr[i].task = NULL;
		cmgr[i].sock = sock;
		dns_view_attach(view, &cmgr[i].view);
		cmgr[i].flags = 0;
		ISC_EVENT_INIT(&cmgr[i].sdev, sizeof(isc_event_t),
			       ISC_EVENTATTR_NOPURGE,
			       0, LWRD_SHUTDOWN,
			       client_shutdown, &cmgr[i], main,
			       NULL, NULL);
		ISC_LIST_INIT(cmgr[i].idle);
		ISC_LIST_INIT(cmgr[i].running);
		result = isc_task_create(taskmgr, mem, 0, &cmgr[i].task);
		INSIST(result == ISC_R_SUCCESS);
	}
	INSIST(i > 0);
	ntasks = i;  /* remember how many we managed to create */

	/*
	 * Now, run through each client manager and populate it with
	 * client structures.  Do this by creating one receive for each
	 * task, in a loop, so each task has a chance of getting at least
	 * one client structure.
	 */
	for (i = 0 ; i < NRECVS ; i++) {
		client = isc_mem_get(mem, sizeof(client_t) * ntasks);
		if (client == NULL)
			break;
		for (j = 0 ; j < ntasks ; j++) {
			client[j].clientmgr = &cmgr[j];
			ISC_LINK_INIT(&client[j], link);
			ISC_LIST_APPEND(cmgr[j].idle, &client[j], link);
			client[j].isidle = ISC_TRUE;
		}
	}
	INSIST(i > 0);

	/*
	 * Issue one read request for each task we have.
	 */
	for (j = 0 ; j < ntasks ; j++) {
		result = client_start_recv(&cmgr[j]);
		INSIST(result == ISC_R_SUCCESS);
	}

	/*
	 * Wait for ^c or kill.
	 */
	isc_mem_stats(mem, stdout);
	isc_app_run();
	isc_mem_stats(mem, stdout);

	/*
	 * Send a shutdown event to every task.
	 */
	for (j = 0 ; j < ntasks ; j++) {
		isc_event_t *ev;

		ev = &cmgr[j].sdev;
		isc_task_send(cmgr[j].task, &ev);
		printf("Sending shutdown events to task %p\n", cmgr[j].task);
	}

	/*
	 * Kill off the view.
	 */
	dns_view_detach(&view);

	/*
	 * Wait for the tasks to all die.
	 */
	printf("Waiting for task manager to die...\n");
	isc_taskmgr_destroy(&taskmgr);

	/*
	 * Wait for everything to die off by waiting for the sockets
	 * to be detached.
	 */
	printf("Waiting for socket manager to die...\n");
	isc_socket_detach(&sock);
	isc_socketmgr_destroy(&sockmgr);

	isc_timermgr_destroy(&timermgr);

	/*
	 * Free up memory allocated.  This is somewhat magical.  We allocated
	 * the client_t's in blocks, but the first task always has the
	 * first pointer.  Just loop here, freeing them.
	 */
	client = ISC_LIST_HEAD(cmgr[0].idle);
	while (client != NULL) {
		ISC_LIST_UNLINK(cmgr[0].idle, client, link);
		isc_mem_put(mem, client, sizeof(client_t) * ntasks);
		client = ISC_LIST_HEAD(cmgr[0].idle);
	}
	INSIST(ISC_LIST_EMPTY(cmgr[0].running));

	/*
	 * Now, kill off the client manager structures.
	 */
	isc_mem_put(mem, cmgr, sizeof(clientmgr_t) * NTASKS);
	cmgr = NULL;

	/*
	 * Clean up hints database.
	 */
	

	/*
	 * Kill the memory system.
	 */
	isc_mem_stats(mem, stdout);
	isc_mem_destroy(&mem);

	isc_app_finish();

	return (0);
}
