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

/* $Id: lwresd.c,v 1.8.2.2 2000/06/28 00:19:05 gson Exp $ */

/*
 * Main program for the Lightweight Resolver Daemon.
 *
 * To paraphrase the old saying about X11, "It's not a lightweight deamon 
 * for resolvers, it's a deamon for lightweight resolvers".
 */

#include <config.h>

#include <stdlib.h>

#include <isc/app.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/print.h>
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

#include <named/globals.h>
#include <named/log.h>
#include <named/lwresd.h>
#include <named/lwdclient.h>
#include <named/server.h>
#include <named/os.h>

#define LWRESD_MAGIC		ISC_MAGIC('L', 'W', 'R', 'D')
#define VALID_LWRESD(l)		ISC_MAGIC_VALID(l, LWRESD_MAGIC)

/*
 * The goal number of clients we can handle will be NTASKS * NRECVS.
 */
#define NTASKS		20	/* tasks to create to handle lwres queries */
#define NRECVS		 5	/* max clients per task */
#define NTHREADS	 1	/* # threads to create in thread manager */

static void
fatal(const char *msg, isc_result_t result) {
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_LWRESD,
		      ISC_LOG_CRITICAL, "%s: %s", msg,
		      isc_result_totext(result));
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_LWRESD,
		      ISC_LOG_CRITICAL, "exiting (due to fatal error)");
		      exit(1);
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
shutdown_lwresd(isc_task_t *task, isc_event_t *event) {
	ns_lwresd_t *lwresd = event->ev_arg;
	unsigned int i;

	UNUSED(task);

	dns_dispatchmgr_destroy(&lwresd->dispmgr);

	for (i = 0; i < lwresd->ntasks; i++)
		isc_task_shutdown(lwresd->cmgr[i].task);

	/*
	 * Wait for everything to die off by waiting for the sockets
	 * to be detached.
	 */
	isc_socket_detach(&lwresd->sock);

	/*
	 * Kill off the view.
	 */
	dns_view_detach(&lwresd->view);

	isc_task_detach(&lwresd->task);

	isc_event_free(&event);
}


static void
parse_resolv_conf(isc_mem_t *mctx, isc_sockaddrlist_t *forwarders) {
	lwres_context_t *lwctx;
	lwres_conf_t *lwc;
	int lwresult;
	struct in_addr ina;
	struct in6_addr ina6;
	isc_sockaddr_t *sa;
	int i;
	in_port_t port;

	lwctx = NULL;
	lwresult = lwres_context_create(&lwctx, mctx, mem_alloc, mem_free,
					LWRES_CONTEXT_SERVERMODE);
	if (lwresult != LWRES_R_SUCCESS)
		return;

	lwresult = lwres_conf_parse(lwctx, lwresd_g_conffile);
	if (lwresult != LWRES_R_SUCCESS)
		goto out;

	lwc = lwres_conf_get(lwctx);
	INSIST(lwc != NULL);

	if (lwresd_g_queryport == 0)
		port = 53;
	else
		port = lwresd_g_queryport;

	/*
	 * Run through the list of nameservers, and set them to be our
	 * forwarders.
	 */
	for (i = 0 ; i < lwc->nsnext ; i++) {
		switch (lwc->nameservers[i].family) {
		case LWRES_ADDRTYPE_V4:
			sa = isc_mem_get(mctx, sizeof *sa);
			INSIST(sa != NULL);
			memcpy(&ina.s_addr, lwc->nameservers[i].address, 4);
			isc_sockaddr_fromin(sa, &ina, port);
			ISC_LIST_APPEND(*forwarders, sa, link);
			sa = NULL;
			break;
		case LWRES_ADDRTYPE_V6:
			sa = isc_mem_get(mctx, sizeof *sa);
			INSIST(sa != NULL);
			memcpy(&ina6.s6_addr, lwc->nameservers[i].address, 16);
			isc_sockaddr_fromin6(sa, &ina6, port);
			ISC_LIST_APPEND(*forwarders, sa, link);
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

static isc_result_t
ns_lwresd_createview(ns_lwresd_t *lwresd, dns_view_t **viewp) {
	dns_cache_t *cache;
	isc_result_t result;
	dns_db_t *rootdb;
	unsigned int attrs;
	isc_sockaddr_t any4, any6;
	dns_dispatch_t *disp4 = NULL;
	dns_dispatch_t *disp6 = NULL;		
	isc_sockaddrlist_t forwarders;
	dns_view_t *view;

	REQUIRE(viewp != NULL && *viewp == NULL);
	cache = NULL;

	result = dns_dispatchmgr_create(lwresd->mctx, ns_g_entropy,
					&lwresd->dispmgr);

	if (result != ISC_R_SUCCESS)
		fatal("creating dispatch manager", result);

	/*
	 * View.
	 */
	view = NULL;
	result = dns_view_create(lwresd->mctx, dns_rdataclass_in, "_default",
				 &view);
	if (result != ISC_R_SUCCESS)
		return (result);

	/*
	 * Cache.
	 */
	result = dns_cache_create(lwresd->mctx, ns_g_taskmgr, ns_g_timermgr,
				  dns_rdataclass_in, "rbt", 0, NULL, &cache);
	if (result != ISC_R_SUCCESS)
		goto out;
	dns_view_setcache(view, cache);
	dns_cache_detach(&cache);

	/*
	 * Resolver.
	 *
	 * XXXMLG hardwired number of tasks.
	 */

	if (isc_net_probeipv6() == ISC_R_SUCCESS) {
		isc_sockaddr_any6(&any6);

		attrs = DNS_DISPATCHATTR_IPV6 | DNS_DISPATCHATTR_UDP;
		result = dns_dispatch_getudp(lwresd->dispmgr, ns_g_socketmgr,
					     ns_g_taskmgr, &any6, 512, 6, 1024,
					     17, 19, attrs, attrs, &disp6);
		if (result != ISC_R_SUCCESS)
		goto out;
	}
	if (isc_net_probeipv4() == ISC_R_SUCCESS) {
		isc_sockaddr_any(&any4);

		attrs = DNS_DISPATCHATTR_IPV4 | DNS_DISPATCHATTR_UDP;
		result = dns_dispatch_getudp(lwresd->dispmgr, ns_g_socketmgr,
					     ns_g_taskmgr, &any4, 512, 6, 1024,
					     17, 19, attrs, attrs, &disp4);
		if (result != ISC_R_SUCCESS)
			goto out;
	}
	if (disp4 == NULL && disp6 == NULL)
		fatal("not listening on IPv4 or IPv6", ISC_R_FAILURE);
	
	result = dns_view_createresolver(view, ns_g_taskmgr, 16,
					 ns_g_socketmgr, ns_g_timermgr, 0,
					 lwresd->dispmgr, disp4, disp6);
	if (disp4 != NULL)
		dns_dispatch_detach(&disp4);
	if (disp6 != NULL)
		dns_dispatch_detach(&disp6);

	if (result != ISC_R_SUCCESS)
		goto out;

	rootdb = NULL;
	result = dns_rootns_create(lwresd->mctx, dns_rdataclass_in, NULL,
				   &rootdb);
	if (result != ISC_R_SUCCESS)
		goto out;
	dns_view_sethints(view, rootdb);
	dns_db_detach(&rootdb);

	/*
	 * If we have forwarders, set them here.
	 */
	ISC_LIST_INIT(forwarders);
	parse_resolv_conf(lwresd->mctx, &forwarders);
	if (ISC_LIST_HEAD(forwarders) != NULL) {
		isc_sockaddr_t *sa;

		dns_resolver_setforwarders(view->resolver, &forwarders);
		dns_resolver_setfwdpolicy(view->resolver, dns_fwdpolicy_only);
		sa = ISC_LIST_HEAD(forwarders);
		while (sa != NULL) {
			ISC_LIST_UNLINK(forwarders, sa, link);
			isc_mem_put(lwresd->mctx, sa, sizeof (*sa));
			sa = ISC_LIST_HEAD(forwarders);
		}
	}

	dns_view_freeze(view);
	*viewp = view;

	return (ISC_R_SUCCESS);

out:
	dns_view_detach(&view);
	return (result);
}

void
ns_lwresd_create(isc_mem_t *mctx, dns_view_t *view, ns_lwresd_t **lwresdp) {
	ns_lwresd_t *lwresd;
	isc_sockaddr_t localhost;
	struct in_addr lh_addr;
	unsigned int i, j;
	ns_lwdclient_t *client;
	isc_socket_t *sock;
	isc_result_t result;

	sock = NULL;
	result = isc_socket_create(ns_g_socketmgr, AF_INET, isc_sockettype_udp,
				   &sock);
	if (result != ISC_R_SUCCESS)
		fatal("failed to create socket", result);

	lh_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (ns_g_port != 0)
		lwres_udp_port = ns_g_port;
	isc_sockaddr_fromin(&localhost, &lh_addr, lwres_udp_port);

	result = isc_socket_bind(sock, &localhost);
	if (result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);
		fatal("failed to bind lwresd protocol socket", result);
	}

	ns_os_writepidfile(lwresd_g_defaultpidfile);

	lwresd = isc_mem_get(mctx, sizeof(*lwresd));
	if (lwresd == NULL)
		fatal("allocating lightweight resolver object", ISC_R_NOMEMORY);

	lwresd->mctx = NULL;
	isc_mem_attach(mctx, &lwresd->mctx);

	lwresd->sock = sock;

	lwresd->view = NULL;
	lwresd->dispmgr = NULL;
	if (view != NULL)
		dns_view_attach(view, &lwresd->view);
	else {
		result = ns_lwresd_createview(lwresd, &lwresd->view);
		if (result != ISC_R_SUCCESS)
			fatal("failed to create default view", result);
	}

	lwresd->task = NULL;
	result = isc_task_create(ns_g_taskmgr, 0, &lwresd->task);
	if (result != ISC_R_SUCCESS)
		fatal("allocating lightweight resolver task", result);
	isc_task_setname(lwresd->task, "lwresd", lwresd);
	result = isc_task_onshutdown(lwresd->task, shutdown_lwresd, lwresd);
	if (result != ISC_R_SUCCESS)
		fatal("allocating lwresd onshutdown event", result);

	lwresd->cmgr = isc_mem_get(lwresd->mctx,
				   sizeof(ns_lwdclientmgr_t) * NTASKS);
	if (lwresd->cmgr == NULL)
		fatal("allocating lwresd client manager", ISC_R_NOMEMORY);

	/*
	 * Create one task for each client manager.
	 */
	for (i = 0 ; i < NTASKS ; i++) {
		char name[16];
		lwresd->cmgr[i].task = NULL;
		lwresd->cmgr[i].sock = NULL;
		isc_socket_attach(lwresd->sock, &lwresd->cmgr[i].sock);
		lwresd->cmgr[i].view = NULL;
		lwresd->cmgr[i].flags = 0;
		result = isc_task_create(ns_g_taskmgr, 0,
					 &lwresd->cmgr[i].task);
		if (result != ISC_R_SUCCESS)
			break;
		result = isc_task_onshutdown(lwresd->cmgr[i].task,
					     ns_lwdclient_shutdown,
					     &lwresd->cmgr[i]);
		if (result != ISC_R_SUCCESS)
			break;
		ISC_LIST_INIT(lwresd->cmgr[i].idle);
		ISC_LIST_INIT(lwresd->cmgr[i].running);
		snprintf(name, sizeof(name), "lwd client %d", i);
		isc_task_setname(lwresd->cmgr[i].task, name, &lwresd->cmgr[i]);
		lwresd->cmgr[i].mctx = lwresd->mctx;
		lwresd->cmgr[i].lwctx = NULL;
		result = lwres_context_create(&lwresd->cmgr[i].lwctx,
					      lwresd->mctx,
					      mem_alloc, mem_free,
					      LWRES_CONTEXT_SERVERMODE);
		if (result != ISC_R_SUCCESS) {
			isc_task_detach(&lwresd->cmgr[i].task);
			break;
		}
		dns_view_attach(lwresd->view, &lwresd->cmgr[i].view);
	}
	INSIST(i > 0);
	lwresd->ntasks = i;  /* remember how many we managed to create */

	/*
	 * Now, run through each client manager and populate it with
	 * client structures.  Do this by creating one receive for each
	 * task, in a loop, so each task has a chance of getting at least
	 * one client structure.
	 */
	for (i = 0 ; i < NRECVS ; i++) {
		client = isc_mem_get(lwresd->mctx,
				     sizeof(ns_lwdclient_t) * lwresd->ntasks);
		if (client == NULL)
			break;
		for (j = 0 ; j < lwresd->ntasks ; j++)
			ns_lwdclient_initialize(&client[j], &lwresd->cmgr[j]);
	}
	INSIST(i > 0);

	/*
	 * Issue one read request for each task we have.
	 */
	for (j = 0 ; j < lwresd->ntasks ; j++) {
		result = ns_lwdclient_startrecv(&lwresd->cmgr[j]);
		INSIST(result == ISC_R_SUCCESS);
	}

	lwresd->magic = LWRESD_MAGIC;
	*lwresdp = lwresd;
}

void
ns_lwresd_destroy(ns_lwresd_t **lwresdp) {
	ns_lwresd_t *lwresd;
	ns_lwdclient_t *client;
	isc_mem_t *mctx;

	REQUIRE(lwresdp != NULL);
	lwresd = *lwresdp;
	REQUIRE(VALID_LWRESD(lwresd));

	mctx = lwresd->mctx;

	/*
	 * Free up memory allocated.  This is somewhat magical.  We allocated
	 * the ns_lwdclient_t's in blocks, but the first task always has the
	 * first pointer.  Just loop here, freeing them.
	 */
	client = ISC_LIST_HEAD(lwresd->cmgr[0].idle);
	while (client != NULL) {
		ISC_LIST_UNLINK(lwresd->cmgr[0].idle, client, link);
		isc_mem_put(mctx, client,
			    sizeof(ns_lwdclient_t) * lwresd->ntasks);
		client = ISC_LIST_HEAD(lwresd->cmgr[0].idle);
	}
	INSIST(ISC_LIST_EMPTY(lwresd->cmgr[0].running));

	isc_mem_put(mctx, lwresd->cmgr, sizeof(ns_lwdclientmgr_t) * NTASKS);
	lwresd->magic = 0;
	isc_mem_put(mctx, lwresd, sizeof(*lwresd));
	isc_mem_detach(&mctx);
	*lwresdp = NULL;
}
