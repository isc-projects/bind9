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

/* $Id: lwresd.c,v 1.19 2000/10/19 02:55:20 explorer Exp $ */

/*
 * Main program for the Lightweight Resolver Daemon.
 *
 * To paraphrase the old saying about X11, "It's not a lightweight deamon
 * for resolvers, it's a deamon for lightweight resolvers".
 *
 * A lot of this code was copied from omapi.
 */

#include <config.h>

#include <stdlib.h>

#include <isc/app.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/cache.h>
#include <dns/confctx.h>
#include <dns/conflwres.h>
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
#define NTASKS		2	/* tasks to create to handle lwres queries */
#define NRECVS		2	/* max clients per task */

typedef struct ns_lwreslistener ns_lwreslistener_t;

typedef ISC_LIST(ns_lwreslistener_t) ns_lwreslistenerlist_t;

struct ns_lwreslistener {
	isc_mem_t *			mctx;
	isc_sockaddr_t			address;
	ns_lwresd_t			*manager;
	dns_view_t			*view;
	LINK(ns_lwreslistener_t)        link;
};

static ns_lwreslistenerlist_t listeners;
static isc_mutex_t listeners_lock;
static isc_once_t once = ISC_ONCE_INIT;

static void
lwresd_shutdown(ns_lwresd_t **lwresdp);


static void
initialize_mutex(void) {
	RUNTIME_CHECK(isc_mutex_init(&listeners_lock) == ISC_R_SUCCESS);
}


/*
 * Wrappers around our memory management stuff, for the lwres functions.
 */
void *
ns__lwresd_memalloc(void *arg, size_t size) {
	return (isc_mem_get(arg, size));
}

void
ns__lwresd_memfree(void *arg, void *mem, size_t size) {
	isc_mem_put(arg, mem, size);
}

void
ns__lwresd_destroy(ns_lwresd_t *lwresd) {
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

	isc_socket_detach(&lwresd->sock);
	dns_view_detach(&lwresd->view);

	mctx = lwresd->mctx;

	lwresd->magic = 0;
	isc_mem_put(mctx, lwresd, sizeof(*lwresd));
	isc_mem_detach(&mctx);
}

isc_result_t
ns_lwresd_parseresolvconf(isc_mem_t *mctx, dns_c_ctx_t **ctxp) {
	dns_c_ctx_t *ctx = NULL;
	lwres_context_t *lwctx = NULL;
	lwres_conf_t *lwc = NULL;
	isc_sockaddr_t sa;
	int i;
	in_port_t port;
	dns_c_iplist_t *forwarders = NULL;
	dns_c_iplist_t *locallist = NULL;
	dns_c_lwreslist_t *lwreslist = NULL;
	dns_c_lwres_t *lwres = NULL;
	isc_result_t result;
	lwres_result_t lwresult;
	struct in_addr localhost;

	result = dns_c_ctx_new(mctx, &ctx);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	
	lwctx = NULL;
	lwresult = lwres_context_create(&lwctx, mctx, ns__lwresd_memalloc,
					ns__lwresd_memfree,
					LWRES_CONTEXT_SERVERMODE);
	if (lwresult != LWRES_R_SUCCESS)
		goto cleanup;

	lwresult = lwres_conf_parse(lwctx, lwresd_g_resolvconffile);
	if (lwresult != LWRES_R_SUCCESS)
		goto cleanup;

	lwc = lwres_conf_get(lwctx);
	INSIST(lwc != NULL);

	/*
	 * Build the list of forwarders.
	 */
	result = dns_c_iplist_new(mctx, lwc->nsnext, &forwarders);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	if (ns_g_port != 0)
		port = ns_g_port;
	else
		port = 53;

	for (i = 0 ; i < lwc->nsnext ; i++) {
		if (lwc->nameservers[i].family != LWRES_ADDRTYPE_V4 &&
		    lwc->nameservers[i].family != LWRES_ADDRTYPE_V6)
			continue;

		if (lwc->nameservers[i].family == LWRES_ADDRTYPE_V4) {
			struct in_addr ina;
			memcpy(&ina.s_addr, lwc->nameservers[i].address, 4);
			isc_sockaddr_fromin(&sa, &ina, port);
		} else {
			struct in6_addr ina6;
			memcpy(&ina6.s6_addr, lwc->nameservers[i].address, 16);
			isc_sockaddr_fromin6(&sa, &ina6, port);
		}
#ifndef NOMINUM_PUBLIC
		result = dns_c_iplist_append(forwarders, sa, NULL);
#else /* NOMINUM_PUBLIC */
		result = dns_c_iplist_append(forwarders, sa);
#endif /* NOMINUM_PUBLIC */
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	}

	if (forwarders->nextidx != 0) {
		result = dns_c_ctx_setforwarders(ctx, ISC_FALSE, forwarders);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		forwarders = NULL;
		result = dns_c_ctx_setforward(ctx, dns_c_forw_first);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	}

	result = dns_c_lwreslist_new(mctx, &lwreslist);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_c_lwres_new(mctx, &lwres);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	port = lwresd_g_listenport;
	if (port == 0)
		port = LWRES_UDP_PORT;

	if (lwc->lwnext == 0) {
		localhost.s_addr = htonl(INADDR_LOOPBACK);
		isc_sockaddr_fromin(&sa, &localhost, port);
	} else {
		if (lwc->lwservers[0].family != LWRES_ADDRTYPE_V4 &&
		    lwc->lwservers[0].family != LWRES_ADDRTYPE_V6)
		{
			result = ISC_R_FAMILYNOSUPPORT;
			goto cleanup;
		}

		if (lwc->lwservers[0].family == LWRES_ADDRTYPE_V4) {
			struct in_addr ina;
			memcpy(&ina.s_addr, lwc->lwservers[0].address, 4);
			isc_sockaddr_fromin(&sa, &ina, port);
		} else {
			struct in6_addr ina6;
			memcpy(&ina6.s6_addr, lwc->lwservers[0].address, 16);
			isc_sockaddr_fromin6(&sa, &ina6, port);
		}
	}

	result = dns_c_iplist_new(mctx, 1, &locallist);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
#ifndef NOMINUM_PUBLIC
	result = dns_c_iplist_append(locallist, sa, NULL);
#else /* NOMINUM_PUBLIC */
	result = dns_c_iplist_append(locallist, sa);
#endif /* NOMINUM_PUBLIC */
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_c_lwres_setlistenon(lwres, locallist);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	dns_c_iplist_detach(&locallist);

	result = dns_c_lwreslist_append(lwreslist, lwres);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	lwres = NULL;

	result = dns_c_ctx_setlwres(ctx, lwreslist);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	lwreslist = NULL;

	*ctxp = ctx;

	result = ISC_R_SUCCESS;

 cleanup:
	if (result != ISC_R_SUCCESS) {
		if (forwarders != NULL)
			dns_c_iplist_detach(&forwarders);
		if (locallist != NULL)
			dns_c_iplist_detach(&locallist);
		if (lwres != NULL)
			dns_c_lwres_delete(&lwres);
		if (lwreslist != NULL)
			dns_c_lwreslist_delete(&lwreslist);
		dns_c_ctx_delete(&ctx);
	}

	if (lwctx != NULL) {
		lwres_conf_clear(lwctx);
		lwres_context_destroy(&lwctx);
	}

	return (result);
}

static isc_result_t
lwresd_create(isc_mem_t *mctx, dns_view_t *view,
	      isc_sockaddr_t *address, ns_lwresd_t **lwresdp) {
	ns_lwresd_t *lwresd;
	unsigned int i;
	ns_lwdclientmgr_t *cm;
	isc_socket_t *sock;
	isc_result_t result;

	REQUIRE(view != NULL);

	sock = NULL;
	result = isc_socket_create(ns_g_socketmgr, isc_sockaddr_pf(address),
				   isc_sockettype_udp, &sock);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "failed to create socket: %s",
			      isc_result_totext(result));
		return (result);
	}

	if (isc_sockaddr_getport(address) == 0) {
		in_port_t port;
		port = lwresd_g_listenport;
		if (port == 0)
			port = LWRES_UDP_PORT;
		isc_sockaddr_setport(address, port);
	}

	result = isc_socket_bind(sock, address);
	if (result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "failed to bind socket: %s",
			      isc_result_totext(result));
		return (result);
	}

	lwresd = isc_mem_get(mctx, sizeof(*lwresd));
	if (lwresd == NULL) {
		isc_socket_detach(&sock);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "failed to allocate lwres object");
		return (ISC_R_NOMEMORY);
	}

	lwresd->mctx = NULL;
	isc_mem_attach(mctx, &lwresd->mctx);

	RUNTIME_CHECK(isc_mutex_init(&lwresd->lock) == ISC_R_SUCCESS);

	lwresd->shutting_down = ISC_FALSE;
	lwresd->sock = sock;
	lwresd->view = NULL;
	ISC_LIST_INIT(lwresd->cmgrs);
	dns_view_attach(view, &lwresd->view);

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

	return (ISC_R_SUCCESS);
}

static void
free_listener(ns_lwreslistener_t **listenerp) {
	ns_lwreslistener_t *listener = *listenerp;

	if (listener->view != NULL)
		dns_view_detach(&listener->view);
	if (listener->manager != NULL)
		lwresd_shutdown(&listener->manager);

	isc_mem_put(listener->mctx, listener, sizeof(*listener));
	*listenerp = NULL;
}

static isc_result_t
lwres_listen(ns_lwreslistener_t *listener) {
	isc_result_t result;

	REQUIRE(listener->manager == NULL);

	result = lwresd_create(listener->mctx, listener->view,
			       &listener->address, &listener->manager);

	return (result);
}

static void
update_listener(ns_lwreslistener_t **listenerp, dns_c_lwres_t *lwres,
		isc_sockaddr_t *address)
{
	ns_lwreslistener_t *listener;
	isc_result_t result;
	const char *vname;
	dns_view_t *view;

	for (listener = ISC_LIST_HEAD(listeners);
	     listener != NULL;
	     listener = ISC_LIST_NEXT(listener, link))
	{
		if (isc_sockaddr_equal(address, &listener->address)) {
			/*
			 * There is already a listener for this sockaddr.
			 * Update the other values.
			 */
			if (lwres->view == NULL)
				vname = "_default";
			else
				vname = lwres->view;
			if (listener->view == NULL ||
			    strcmp(vname, listener->view->name) != 0)
			{
				if (listener->view != NULL)
					dns_view_detach(&listener->view);
				view = NULL;
				result = dns_viewlist_find(
							&ns_g_server->viewlist,
							lwres->view,
							lwres->viewclass,
							&view);
				if (result != ISC_R_SUCCESS) {
					isc_log_write(ns_g_lctx,
						      NS_LOGCATEGORY_GENERAL,
						      NS_LOGMODULE_LWRESD,
						      ISC_LOG_WARNING,
						      "couldn't find view %s",
						      lwres->view);
					return;
				}
				dns_view_attach(view, &listener->view);
				dns_view_detach(&view);
			}
			break;
		}

	}

	*listenerp = listener;
}

static void
add_listener(isc_mem_t *mctx, ns_lwreslistener_t **listenerp,
	     dns_c_lwres_t *lwres, isc_sockaddr_t *address)
{
	ns_lwreslistener_t *listener;
	isc_result_t result = ISC_R_SUCCESS;
	dns_view_t *view;
	const char *vname;

	listener = isc_mem_get(mctx, sizeof(ns_lwreslistener_t));
	if (listener == NULL)
		result = ISC_R_NOMEMORY;

	if (result == ISC_R_SUCCESS) {
		listener->mctx = mctx;
		listener->view = NULL;
		listener->manager = NULL;
		listener->address = *address;
	}

	view = NULL;
	if (lwres->view == NULL)
		vname = "_default";
	else
		vname = lwres->view;
	result = dns_viewlist_find(&ns_g_server->viewlist, vname,
				   lwres->viewclass, &view);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "couldn't find view %s", lwres->view);
		return;
	}
	dns_view_attach(view, &listener->view);
	dns_view_detach(&view);

	if (result == ISC_R_SUCCESS)
		result = lwres_listen(listener);

	if (result == ISC_R_SUCCESS) {
		char socktext[ISC_SOCKADDR_FORMATSIZE];
		isc_sockaddr_format(address, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_NOTICE,
			      "lwres listening on %s", socktext);
		*listenerp = listener;

	} else {
		char socktext[ISC_SOCKADDR_FORMATSIZE];
		if (listener != NULL)
			free_listener(&listener);

		isc_sockaddr_format(address, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "couldn't add lwres channel %s: %s",
			      socktext, isc_result_totext(result));
	}
}

isc_result_t
ns_lwresd_configure(isc_mem_t *mctx, dns_c_ctx_t *cctx) {
	dns_c_lwres_t *lwres = NULL;
	dns_c_lwreslist_t *list = NULL;
	ns_lwreslistener_t *listener;
	ns_lwreslistenerlist_t new_listeners;
	isc_result_t result;

	REQUIRE(mctx != NULL);
	REQUIRE(cctx != NULL);

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	ISC_LIST_INIT(new_listeners);

	result = dns_c_ctx_getlwres(cctx, &list);

	LOCK(&listeners_lock);
	/*
	 * Run through the new lwres address list, noting sockets that
	 * are already being listened on and moving them to the new list.
	 *
	 * Identifying duplicates addr/port combinations is left to either
	 * the underlying config code, or to the bind attempt getting an
	 * address-in-use error.
	 */
	if (result == ISC_R_SUCCESS) {
		for (lwres = dns_c_lwreslist_head(list);
		     lwres != NULL;
		     lwres = dns_c_lwreslist_next(lwres))
		{
			unsigned int i;
			isc_sockaddr_t *address;

			for (i = 0; i < lwres->listeners->nextidx; i++) {
				address = &lwres->listeners->ips[i];
				update_listener(&listener, lwres, address);
				if (listener != NULL)
					/*
					 * Remove the listener from the old
					 * list, so it won't be shut down.
					 */
					ISC_LIST_UNLINK(listeners, listener,
							link);
				else
					/*
					 * This is a new listener.
					 */
					add_listener(mctx, &listener, lwres,
						     address);
	
				if (listener != NULL)
					ISC_LIST_APPEND(new_listeners,
							listener, link);
			}
		}
	}

	/*
	 * Put all of the valid listeners on the listeners list.
	 * Anything already on listeners in the process of shutting down
	 * will be taken care of by listen_done().
	 */
	ISC_LIST_APPENDLIST(listeners, new_listeners, link);

	UNLOCK(&listeners_lock);

	return (ISC_R_SUCCESS);
}

static void
lwresd_shutdown(ns_lwresd_t **lwresdp) {
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

	ns__lwresd_destroy(lwresd);
}

void
ns_lwresd_shutdown(void) {
	ns_lwreslistener_t *listener;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	while (!ISC_LIST_EMPTY(listeners)) {
		listener = ISC_LIST_HEAD(listeners);
		ISC_LIST_UNLINK(listeners, listener, link);
		free_listener(&listener);
	}
}
