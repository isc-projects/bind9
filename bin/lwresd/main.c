/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/*
 * Main program for the Lightweight Resolver Daemon.
 *
 * To paraphrase the old saying about X11, "It's not a lightweight deamon 
 * for resolvers, it's a deamon for lightweight resolvers".
 */

#include <config.h>

#include <stdlib.h>

#include <isc/app.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/cache.h>
#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/log.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/rootns.h>
#include <dns/view.h>

#include "client.h"

/*
 * The goal number of clients we can handle will be NTASKS * NRECVS.
 */
#define NTASKS		20	/* tasks to create to handle lwres queries */
#define NRECVS		 5	/* max clients per task */
#define NTHREADS	 1	/* # threads to create in thread manager */

/*
 * Array of client managers.  Each of these will have a task associated
 * with it.
 */
clientmgr_t    *cmgr;
unsigned int	ntasks;	/* number of tasks actually created */

dns_view_t *view;

isc_taskmgr_t *taskmgr;
isc_socketmgr_t *sockmgr;
isc_timermgr_t *timermgr;
dns_dispatchmgr_t *dispatchmgr;

isc_sockaddrlist_t forwarders;

static isc_logmodule_t logmodules[] = {
	{ "main",	 		0 },
	{ NULL, 			0 }
};

#define LWRES_LOGMODULE_MAIN		(&logmodules[0])

static isc_logcategory_t logcategories[] = {
	{ "network",	 		0 },
	{ NULL, 			0 }
};

#define LWRES_LOGCATEGORY_NETWORK	(&logcategories[0])
	

static isc_result_t
create_view(isc_mem_t *mctx) {
	dns_cache_t *cache;
	isc_result_t result;
	dns_db_t *rootdb;
	unsigned int attrs;
	dns_dispatch_t *disp4 = NULL;
	dns_dispatch_t *disp6 = NULL;		
	
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

	if (isc_net_probeipv4() == ISC_R_SUCCESS) {
		isc_sockaddr_t any4;
		
		isc_sockaddr_any(&any4);
		attrs = DNS_DISPATCHATTR_IPV4 | DNS_DISPATCHATTR_UDP;
		result = dns_dispatch_getudp(dispatchmgr, sockmgr,
					     taskmgr, &any4, 512, 6, 1024,
					     17, 19, attrs, attrs, &disp4);
		if (result != ISC_R_SUCCESS)
			goto out;
	}

	if (isc_net_probeipv6() == ISC_R_SUCCESS) {
		isc_sockaddr_t any6;
		
		isc_sockaddr_any6(&any6);
		
		attrs = DNS_DISPATCHATTR_IPV6 | DNS_DISPATCHATTR_UDP;
		result = dns_dispatch_getudp(dispatchmgr, sockmgr,
					     taskmgr, &any6, 512, 6, 1024,
					     17, 19, attrs, attrs, &disp6);
		if (result != ISC_R_SUCCESS)
			goto out;
	}
	
	result = dns_view_createresolver(view, taskmgr, 16, sockmgr,
					 timermgr, 0, dispatchmgr,
					 disp4, disp6);

	if (disp4 != NULL)
		dns_dispatch_detach(&disp4);
	if (disp6 != NULL)
		dns_dispatch_detach(&disp6);
	
	if (result != ISC_R_SUCCESS)
		goto out;

	rootdb = NULL;
	result = dns_rootns_create(mctx, dns_rdataclass_in, NULL, &rootdb);
	if (result != ISC_R_SUCCESS)
		goto out;
	dns_view_sethints(view, rootdb);
	dns_db_detach(&rootdb);

	/*
	 * If we have forwarders, set them here.
	 */
	if (ISC_LIST_HEAD(forwarders) != NULL) {
		isc_sockaddr_t *sa;

		dns_resolver_setforwarders(view->resolver, &forwarders);
		dns_resolver_setfwdpolicy(view->resolver, dns_fwdpolicy_only);
		sa = ISC_LIST_HEAD(forwarders);
		while (sa != NULL) {
			ISC_LIST_UNLINK(forwarders, sa, link);
			isc_mem_put(mctx, sa, sizeof (*sa));
			sa = ISC_LIST_HEAD(forwarders);
		}
			
	}

	dns_view_freeze(view);

	return (ISC_R_SUCCESS);

out:
	if (view != NULL)
		dns_view_detach(&view);

	return (result);
}

/*
 * Wrappers around our memory management stuff, for the lwres functions.
 */
static void *
mem_alloc(void *arg, size_t size) {
	return (isc_mem_get(arg, size));
}

static void
mem_free(void *arg, void *mem, size_t size) {
	isc_mem_put(arg, mem, size);
}

static void
parse_resolv_conf(isc_mem_t *mem) {
	lwres_context_t *lwctx;
	lwres_conf_t *lwc;
	int lwresult;
	struct in_addr ina;
	struct in6_addr ina6;
	isc_sockaddr_t *sa;
	int i;

	lwctx = NULL;
	lwresult = lwres_context_create(&lwctx, mem, mem_alloc, mem_free);
	if (lwresult != LWRES_R_SUCCESS)
		return;

	lwresult = lwres_conf_parse(lwctx, "/etc/resolv.conf");
	if (lwresult != LWRES_R_SUCCESS)
		goto out;

#if 1
	lwres_conf_print(lwctx, stderr);
#endif

	lwc = lwres_conf_get(lwctx);
	INSIST(lwc != NULL);

	/*
	 * Run through the list of nameservers, and set them to be our
	 * forwarders.
	 */
	for (i = 0 ; i < lwc->nsnext ; i++) {
		switch (lwc->nameservers[i].family) {
		case AF_INET:
			sa = isc_mem_get(mem, sizeof *sa);
			INSIST(sa != NULL);
			memcpy(&ina.s_addr, lwc->nameservers[i].address, 4);
			isc_sockaddr_fromin(sa, &ina, 53);
			ISC_LIST_APPEND(forwarders, sa, link);
			sa = NULL;
			break;
		case AF_INET6:
			sa = isc_mem_get(mem, sizeof *sa);
			INSIST(sa != NULL);
			memcpy(&ina6.s6_addr, lwc->nameservers[i].address, 16);
			isc_sockaddr_fromin6(sa, &ina6, 53);
			ISC_LIST_APPEND(forwarders, sa, link);
			sa = NULL;
			break;
		default:
			break;
		}
	}

 out:
	lwres_conf_clear(lwctx);
	lwres_context_destroy(&lwctx);
}

int
main(int argc, char **argv) {
	isc_mem_t *mem;
	isc_socket_t *sock;
	isc_sockaddr_t localhost;
	struct in_addr lh_addr;
	isc_result_t result;
	unsigned int i, j;
	client_t *client;
	isc_logdestination_t destination;
	isc_log_t *lctx;
	isc_logconfig_t *lcfg;

	UNUSED(argc);
	UNUSED(argv);

	dns_result_register();

	result = isc_app_start();
	INSIST(result == ISC_R_SUCCESS);

	mem = NULL;
	result = isc_mem_create(0, 0, &mem);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Set up logging.
	 */
	lctx = NULL;
        result = isc_log_create(mem, &lctx, &lcfg);
	INSIST(result == ISC_R_SUCCESS);
	isc_log_registermodules(lctx, logmodules);
	isc_log_registercategories(lctx, logcategories);
	isc_log_setcontext(lctx);
	dns_log_init(lctx);
	dns_log_setcontext(lctx);

	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	result = isc_log_createchannel(lcfg, "_default",
				       ISC_LOG_TOFILEDESC,
				       ISC_LOG_DYNAMIC,
				       &destination, ISC_LOG_PRINTTIME);
	INSIST(result == ISC_R_SUCCESS);
	result = isc_log_usechannel(lcfg, "_default", NULL, NULL);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Set the initial debug level.
	 */
	isc_log_setdebuglevel(lctx, 99);

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
	 * Create a dispatch manager.
	 */
	dispatchmgr = NULL;
	result = dns_dispatchmgr_create(mem, &dispatchmgr);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Read resolv.conf to get our forwarders.
	 */
	ISC_LIST_INIT(forwarders);
	parse_resolv_conf(mem);

	/*
	 * Initialize the DNS bits.  Start by loading our built-in
	 * root hints.
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
	if (result != ISC_R_SUCCESS) {
		isc_log_write(lctx, LWRES_LOGCATEGORY_NETWORK,
			      LWRES_LOGMODULE_MAIN, ISC_LOG_ERROR,
			      "binding lwres protocol socket to port %d: %s",
			      LWRES_UDP_PORT,
			      isc_result_totext(result));
		exit(1);
	}
			      
	INSIST(result == ISC_R_SUCCESS);

	cmgr = isc_mem_get(mem, sizeof(clientmgr_t) * NTASKS);
	INSIST(cmgr != NULL);

	/*
	 * Create one task for each client manager.
	 */
	for (i = 0 ; i < NTASKS ; i++) {
		cmgr[i].task = NULL;
		cmgr[i].sock = sock;
		cmgr[i].view = NULL;
		cmgr[i].flags = 0;
		result = isc_task_create(taskmgr, 0, &cmgr[i].task);
		if (result != ISC_R_SUCCESS)
			break;
		ISC_EVENT_INIT(&cmgr[i].sdev, sizeof(isc_event_t),
			       ISC_EVENTATTR_NOPURGE,
			       0, LWRD_SHUTDOWN,
			       client_shutdown, &cmgr[i], cmgr[i].task,
			       NULL, NULL);
		ISC_LIST_INIT(cmgr[i].idle);
		ISC_LIST_INIT(cmgr[i].running);
		isc_task_setname(cmgr[i].task, "lwresd client", &cmgr[i]);
		cmgr[i].mctx = mem;
		cmgr[i].lwctx = NULL;
		result = lwres_context_create(&cmgr[i].lwctx, mem,
					      mem_alloc, mem_free);
		if (result != ISC_R_SUCCESS) {
			isc_task_detach(&cmgr[i].task);
			break;
		}
		dns_view_attach(view, &cmgr[i].view);
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
		for (j = 0 ; j < ntasks ; j++)
			client_initialize(&client[j], &cmgr[j]);
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
	isc_app_run();

	/*
	 * Send a shutdown event to every task.
	 */
	for (j = 0 ; j < ntasks ; j++) {
		isc_event_t *ev;

		ev = &cmgr[j].sdev;
		isc_task_send(cmgr[j].task, &ev);
	}

	/*
	 * Kill off the view.
	 */
	dns_view_detach(&view);

	/*
	 * Wait for the tasks to all die.
	 */
	isc_taskmgr_destroy(&taskmgr);

	/*
	 * Wait for everything to die off by waiting for the sockets
	 * to be detached.
	 */
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

	dns_dispatchmgr_destroy(&dispatchmgr);
	
	isc_log_destroy(&lctx);

	/*
	 * Kill the memory system.
	 */
	isc_mem_destroy(&mem);

	isc_app_finish();

	return (0);
}
