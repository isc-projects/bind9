/*
 * Copyright (C) 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: lwresd.c,v 1.15 2000/09/07 21:54:36 explorer Exp $ */

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
#include <dns/forward.h>
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
#define NTASKS		2	/* tasks to create to handle lwres queries */
#define NRECVS		 2	/* max clients per task */

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
void *
ns_lwresd_memalloc(void *arg, size_t size) {
	return (isc_mem_get(arg, size));
}

void
ns_lwresd_memfree(void *arg, void *mem, size_t size) {
	isc_mem_put(arg, mem, size);
}

void
lwresd_destroy(ns_lwresd_t *lwresd) {
	isc_mem_t *mctx;

	LOCK(&lwresd->lock);
	if (!ISC_LIST_EMPTY(lwresd->cmgrs) || (!lwresd->shutting_down)) {
		UNLOCK(&lwresd->lock);
		return;
	}

	/*
	 * At this point, nothing can have the lwresd locked, since there
	 * are no clients running.
	 */
	UNLOCK(&lwresd->lock);

	dns_dispatchmgr_destroy(&lwresd->dispmgr);
	isc_socket_detach(&lwresd->sock);
	dns_view_detach(&lwresd->view);

	mctx = lwresd->mctx;

	lwresd->magic = 0;
	isc_mem_put(mctx, lwresd, sizeof(*lwresd));
	isc_mem_detach(&mctx);
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
	lwresult = lwres_context_create(&lwctx, mctx, ns_lwresd_memalloc, ns_lwresd_memfree,
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

		result = dns_fwdtable_add(view->fwdtable, dns_rootname,
					  &forwarders, dns_fwdpolicy_only);
		sa = ISC_LIST_HEAD(forwarders);
		while (sa != NULL) {
			ISC_LIST_UNLINK(forwarders, sa, link);
			isc_mem_put(lwresd->mctx, sa, sizeof (*sa));
			sa = ISC_LIST_HEAD(forwarders);
		}
		if (result != ISC_R_SUCCESS)
			goto out;
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
	unsigned int i;
	ns_lwdclientmgr_t *cm;
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
		fatal("allocating lightweight resolver object",
		      ISC_R_NOMEMORY);

	lwresd->mctx = NULL;
	isc_mem_attach(mctx, &lwresd->mctx);

	result = isc_mutex_init(&lwresd->lock);
	if (result != ISC_R_SUCCESS)
		fatal("creating lock", result);

	lwresd->shutting_down = ISC_FALSE;
	lwresd->sock = sock;
	lwresd->view = NULL;
	lwresd->dispmgr = NULL;
	ISC_LIST_INIT(lwresd->cmgrs);
	if (view != NULL)
		dns_view_attach(view, &lwresd->view);
	else {
		result = ns_lwresd_createview(lwresd, &lwresd->view);
		if (result != ISC_R_SUCCESS)
			fatal("failed to create default view", result);
	}

	/*
	 * Create the managers.
	 */
	for (i = 0 ; i < NTASKS ; i++)
		ns_lwdclientmgr_create(lwresd, NRECVS, ns_g_taskmgr);

	/*
	 * Ensure that we have created at least one.
	 */
	INSIST(!ISC_LIST_EMPTY(lwresd->cmgrs));

	/*
	 * Walk the list of clients and start each one up.
	 */
	LOCK(&lwresd->lock);
	cm = ISC_LIST_HEAD(lwresd->cmgrs);
	while (cm != NULL) {
		ns_lwdclient_startrecv(cm);
		cm = ISC_LIST_NEXT(cm, link);
	}
	UNLOCK(&lwresd->lock);

	lwresd->magic = LWRESD_MAGIC;
	*lwresdp = lwresd;
}

void
ns_lwresd_shutdown(ns_lwresd_t **lwresdp) {
	ns_lwdclientmgr_t *cm;
	ns_lwresd_t *lwresd;

	INSIST(lwresdp != NULL && VALID_LWRESD(*lwresdp));

	lwresd = *lwresdp;
	*lwresdp = NULL;

	LOCK(&lwresd->lock);
	lwresd->shutting_down = ISC_TRUE;
	cm = ISC_LIST_HEAD(lwresd->cmgrs);
	while (cm != NULL) {
		isc_task_shutdown(cm->task);
		cm = ISC_LIST_NEXT(cm, link);
	}
	UNLOCK(&lwresd->lock);

	lwresd_destroy(lwresd);
}
