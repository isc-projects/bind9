/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: lwresd.c,v 1.27.2.2 2001/01/19 02:37:51 gson Exp $ */

/*
 * Main program for the Lightweight Resolver Daemon.
 *
 * To paraphrase the old saying about X11, "It's not a lightweight deamon
 * for resolvers, it's a deamon for lightweight resolvers".
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/list.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/confctx.h>
#include <dns/conflwres.h>
#include <dns/log.h>
#include <dns/result.h>
#include <dns/view.h>

#include <named/globals.h>
#include <named/log.h>
#include <named/lwaddr.h>
#include <named/lwresd.h>
#include <named/lwdclient.h>
#include <named/lwsearch.h>
#include <named/server.h>

#define LWRESD_MAGIC		ISC_MAGIC('L', 'W', 'R', 'D')
#define VALID_LWRESD(l)		ISC_MAGIC_VALID(l, LWRESD_MAGIC)

#define LWRESLISTENER_MAGIC	ISC_MAGIC('L', 'W', 'R', 'L')
#define VALID_LWRESLISTENER(l)	ISC_MAGIC_VALID(l, LWRESLISTENER_MAGIC)

/*
 * The total number of clients we can handle will be NTASKS * NRECVS.
 */
#define NTASKS		2	/* tasks to create to handle lwres queries */
#define NRECVS		2	/* max clients per task */

typedef ISC_LIST(ns_lwreslistener_t) ns_lwreslistenerlist_t;

static ns_lwreslistenerlist_t listeners;
static isc_mutex_t listeners_lock;
static isc_once_t once = ISC_ONCE_INIT;


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


#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

static isc_result_t
parse_sortlist(lwres_conf_t *lwc, isc_mem_t *mctx,
	       dns_c_ipmatchlist_t **sortlist)
{
	dns_c_ipmatchlist_t *inner = NULL, *middle = NULL, *outer = NULL;
	dns_c_ipmatchelement_t *element = NULL;
	int i;
	isc_result_t result;

	REQUIRE(sortlist != NULL && *sortlist == NULL);

	REQUIRE (lwc->sortlistnxt > 0);

	CHECK(dns_c_ipmatchlist_new(mctx, &middle));

	CHECK(dns_c_ipmatchany_new(mctx, &element));
	ISC_LIST_APPEND(middle->elements, element, next);
	element = NULL;

	CHECK(dns_c_ipmatchlist_new(mctx, &inner));
	for (i = 0; i < lwc->sortlistnxt; i++) {
		isc_sockaddr_t sa;
		isc_netaddr_t ma;
		unsigned int mask;

		CHECK(lwaddr_sockaddr_fromlwresaddr(&sa,
						    &lwc->sortlist[i].addr,
						    0));
		CHECK(lwaddr_netaddr_fromlwresaddr(&ma,
						   &lwc->sortlist[i].mask));
		CHECK(isc_netaddr_masktoprefixlen(&ma, &mask));
		CHECK(dns_c_ipmatchpattern_new(mctx, &element, sa, mask));
		ISC_LIST_APPEND(inner->elements, element, next);
		element = NULL;
	}

	CHECK(dns_c_ipmatchindirect_new(mctx, &element, inner, NULL));
	dns_c_ipmatchlist_detach(&inner);
	ISC_LIST_APPEND(middle->elements, element, next);
	element = NULL;

	CHECK(dns_c_ipmatchlist_new(mctx, &outer));
	CHECK(dns_c_ipmatchindirect_new(mctx, &element, middle, NULL));
	dns_c_ipmatchlist_detach(&middle);
	ISC_LIST_APPEND(outer->elements, element, next);

	*sortlist = outer;

	return (ISC_R_SUCCESS);
 cleanup:
	if (inner != NULL)
		dns_c_ipmatchlist_detach(&inner);
	if (outer != NULL)
		dns_c_ipmatchlist_detach(&outer);
	if (element != NULL)
		dns_c_ipmatchelement_delete(mctx, &element);
	return (result);
}

/*
 * Convert a resolv.conf file into a config structure.
 */
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
	dns_c_search_t *search = NULL;
	dns_c_searchlist_t *searchlist = NULL;
	dns_c_ipmatchlist_t *sortlist = NULL;
	isc_result_t result;
	lwres_result_t lwresult;
	struct in_addr localhost;

	CHECK(dns_c_ctx_new(mctx, &ctx));
	
	lwctx = NULL;
	lwresult = lwres_context_create(&lwctx, mctx, ns__lwresd_memalloc,
					ns__lwresd_memfree,
					LWRES_CONTEXT_SERVERMODE);
	if (lwresult != LWRES_R_SUCCESS) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	lwresult = lwres_conf_parse(lwctx, lwresd_g_resolvconffile);
	if (lwresult != LWRES_R_SUCCESS) {
		result = DNS_R_SYNTAX;
		goto cleanup;
	}

	lwc = lwres_conf_get(lwctx);
	INSIST(lwc != NULL);

	/*
	 * Build the list of forwarders.
	 */
	if (lwc->nsnext > 0) {
		CHECK(dns_c_iplist_new(mctx, lwc->nsnext, &forwarders));

		if (ns_g_port != 0)
			port = ns_g_port;
		else
			port = 53;

		for (i = 0 ; i < lwc->nsnext ; i++) {
			CHECK(lwaddr_sockaddr_fromlwresaddr(
							&sa,
							&lwc->nameservers[i],
							port));
			if (result != ISC_R_SUCCESS)
				continue;
			CHECK(dns_c_iplist_append(forwarders, sa, NULL));
		}
	
		if (forwarders->nextidx != 0) {
			CHECK(dns_c_ctx_setforwarders(ctx, ISC_FALSE,
						      forwarders));
			forwarders = NULL;
			CHECK(dns_c_ctx_setforward(ctx, dns_c_forw_first));
		}
	}

	/*
	 * Build the search path
	 */
	if (lwc->searchnxt > 0) {
		CHECK(dns_c_searchlist_new(mctx, &searchlist));
		for (i = 0; i < lwc->searchnxt; i++) {
			search = NULL;
			CHECK(dns_c_search_new(mctx, lwc->search[i], &search));
			dns_c_searchlist_append(searchlist, search);
		}
	}

	/*
	 * Build the sortlist
	 */
	if (lwc->sortlistnxt > 0) {
		CHECK(parse_sortlist(lwc, mctx, &sortlist));
		CHECK(dns_c_ctx_setsortlist(ctx, sortlist));
		dns_c_ipmatchlist_detach(&sortlist);
	}

	CHECK(dns_c_lwreslist_new(mctx, &lwreslist));
	CHECK(dns_c_lwres_new(mctx, &lwres));

	port = lwresd_g_listenport;
	if (port == 0)
		port = LWRES_UDP_PORT;

	if (lwc->lwnext == 0) {
		localhost.s_addr = htonl(INADDR_LOOPBACK);
		isc_sockaddr_fromin(&sa, &localhost, port);
	} else {
		CHECK(lwaddr_sockaddr_fromlwresaddr(&sa, &lwc->lwservers[0],
						    port));
	}

	CHECK(dns_c_iplist_new(mctx, 1, &locallist));
	CHECK(dns_c_iplist_append(locallist, sa, NULL));

	CHECK(dns_c_lwres_setlistenon(lwres, locallist));
	dns_c_iplist_detach(&locallist);

	CHECK(dns_c_lwres_setsearchlist(lwres, searchlist));
	searchlist = NULL;

	CHECK(dns_c_lwres_setndots(lwres, lwc->ndots));

	CHECK(dns_c_lwreslist_append(lwreslist, lwres));
	lwres = NULL;

	CHECK(dns_c_ctx_setlwres(ctx, lwreslist));
	lwreslist = NULL;

	*ctxp = ctx;

	result = ISC_R_SUCCESS;

 cleanup:
	if (result != ISC_R_SUCCESS) {
		if (forwarders != NULL)
			dns_c_iplist_detach(&forwarders);
		if (locallist != NULL)
			dns_c_iplist_detach(&locallist);
		if (searchlist != NULL)
			dns_c_searchlist_delete(&searchlist);
		if (sortlist != NULL)
			dns_c_ipmatchlist_detach(&sortlist);
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


/*
 * Handle lwresd manager objects
 */
isc_result_t
ns_lwdmanager_create(isc_mem_t *mctx, dns_c_lwres_t *lwres,
		     ns_lwresd_t **lwresdp)
{
	ns_lwresd_t *lwresd;
	const char *vname;
	dns_c_search_t *search;
	isc_result_t result;

	INSIST(lwresdp != NULL && *lwresdp == NULL);

	lwresd = isc_mem_get(mctx, sizeof(ns_lwresd_t));
	if (lwresd == NULL)
		return (ISC_R_NOMEMORY);

	lwresd->mctx = NULL;
	isc_mem_attach(mctx, &lwresd->mctx);
	lwresd->view = NULL;
	lwresd->ndots = lwres->ndots;
	lwresd->search = NULL;
	lwresd->refs = 1;

	RUNTIME_CHECK(isc_mutex_init(&lwresd->lock) == ISC_R_SUCCESS);

	lwresd->shutting_down = ISC_FALSE;

	if (lwres->view == NULL)
		vname = "_default";
	else
		vname = lwres->view;

	result = dns_viewlist_find(&ns_g_server->viewlist, vname,
				   lwres->viewclass, &lwresd->view);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "couldn't find view %s", lwres->view);
		goto fail;
	}

	if (lwres->searchlist != NULL) {
		lwresd->search = NULL;
		result = ns_lwsearchlist_create(lwresd->mctx,
						&lwresd->search);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
				      "couldn't create searchlist");
			goto fail;
		}
		for (search = ISC_LIST_HEAD(lwres->searchlist->searches);
		     search != NULL;
		     search = ISC_LIST_NEXT(search, next))
		{
			isc_buffer_t namebuf;
			dns_fixedname_t fname;
			dns_name_t *name;

			dns_fixedname_init(&fname);
			name = dns_fixedname_name(&fname);
			isc_buffer_init(&namebuf, search->search,
					strlen(search->search));
			isc_buffer_add(&namebuf, strlen(search->search));
			result = dns_name_fromtext(name, &namebuf,
						   dns_rootname, ISC_FALSE,
						   NULL);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_LWRESD,
					      ISC_LOG_WARNING,
					      "invalid name %s in searchlist",
					      search->search);
				continue;
			}

			result = ns_lwsearchlist_append(lwresd->search, name);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_LWRESD,
					      ISC_LOG_WARNING,
					      "couldn't update searchlist");
				goto fail;
			}
		}
	}

	lwresd->magic = LWRESD_MAGIC;

	*lwresdp = lwresd;
	return (ISC_R_SUCCESS);

 fail:
	if (lwresd->view != NULL)
		dns_view_detach(&lwresd->view);
	if (lwresd->search != NULL)
		ns_lwsearchlist_detach(&lwresd->search);
	if (lwresd->mctx != NULL)
		isc_mem_detach(&lwresd->mctx);
	return (result);
}

void
ns_lwdmanager_attach(ns_lwresd_t *source, ns_lwresd_t **targetp) {
	INSIST(VALID_LWRESD(source));
	INSIST(targetp != NULL && *targetp == NULL);

	LOCK(&source->lock);
	source->refs++;
	UNLOCK(&source->lock);

	*targetp = source;
}

void
ns_lwdmanager_detach(ns_lwresd_t **lwresdp) {
	ns_lwresd_t *lwresd;
	isc_mem_t *mctx;
	isc_boolean_t done = ISC_FALSE;

	INSIST(lwresdp != NULL && *lwresdp != NULL);
	INSIST(VALID_LWRESD(*lwresdp));

	lwresd = *lwresdp;

	LOCK(&lwresd->lock);
	INSIST(lwresd->refs > 0);
	lwresd->refs--;
	if (lwresd->refs == 0)
		done = ISC_TRUE;
	UNLOCK(&lwresd->lock);

	if (!done)
		return;

	dns_view_detach(&lwresd->view);
	if (lwresd->search != NULL)
		ns_lwsearchlist_detach(&lwresd->search);
	mctx = lwresd->mctx;
	lwresd->magic = 0;
	isc_mem_put(mctx, lwresd, sizeof(*lwresd));
	isc_mem_detach(&mctx);
	lwresdp = NULL;
}


/*
 * Handle listener objects
 */
void
ns_lwreslistener_attach(ns_lwreslistener_t *source,
			ns_lwreslistener_t **targetp)
{
	INSIST(VALID_LWRESLISTENER(source));
	INSIST(targetp != NULL && *targetp == NULL);

	LOCK(&source->lock);
	source->refs++;
	UNLOCK(&source->lock);

	*targetp = source;
}

void
ns_lwreslistener_detach(ns_lwreslistener_t **listenerp) {
	ns_lwreslistener_t *listener;
	isc_mem_t *mctx;
	isc_boolean_t done = ISC_FALSE;

	INSIST(listenerp != NULL && *listenerp != NULL);
	INSIST(VALID_LWRESLISTENER(*listenerp));

	listener = *listenerp;

	LOCK(&listener->lock);
	INSIST(listener->refs > 0);
	listener->refs--;
	if (listener->refs == 0)
		done = ISC_TRUE;
	UNLOCK(&listener->lock);

	if (!done)
		return;

	if (listener->manager != NULL)
		ns_lwdmanager_detach(&listener->manager);

	if (listener->sock != 0)
		isc_socket_detach(&listener->sock);

	listener->magic = 0;
	mctx = listener->mctx;
	isc_mem_put(mctx, listener, sizeof(*listener));
	isc_mem_detach(&mctx);
	listenerp = NULL;
}

static isc_result_t
listener_create(isc_mem_t *mctx, ns_lwresd_t *lwresd,
		ns_lwreslistener_t **listenerp)
{
	ns_lwreslistener_t *listener;

	REQUIRE(listenerp != NULL && *listenerp == NULL);

	listener = isc_mem_get(mctx, sizeof(ns_lwreslistener_t));
	if (listener == NULL)
		return (ISC_R_NOMEMORY);
	RUNTIME_CHECK(isc_mutex_init(&listener->lock) == ISC_R_SUCCESS);

	listener->magic = LWRESLISTENER_MAGIC;
	listener->refs = 1;

	listener->sock = NULL;

	listener->manager = NULL;
	ns_lwdmanager_attach(lwresd, &listener->manager);

	listener->mctx = NULL;
	isc_mem_attach(mctx, &listener->mctx);

	ISC_LINK_INIT(listener, link);
	ISC_LIST_INIT(listener->cmgrs);

	*listenerp = listener;
	return (ISC_R_SUCCESS);
}

static isc_result_t
listener_bind(ns_lwreslistener_t *listener, isc_sockaddr_t *address) {
	isc_socket_t *sock = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	listener->address = *address;

	if (isc_sockaddr_getport(&listener->address) == 0) {
		in_port_t port;
		port = lwresd_g_listenport;
		if (port == 0)
			port = LWRES_UDP_PORT;
		isc_sockaddr_setport(&listener->address, port);
	}

	sock = NULL;
	result = isc_socket_create(ns_g_socketmgr,
				   isc_sockaddr_pf(&listener->address),
				   isc_sockettype_udp, &sock);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "failed to create socket: %s",
			      isc_result_totext(result));
		return (result);
	}

	result = isc_socket_bind(sock, &listener->address);
	if (result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "failed to bind socket: %s",
			      isc_result_totext(result));
		return (result);
	}
	listener->sock = sock;
	return (ISC_R_SUCCESS);
}

static void
listener_copysock(ns_lwreslistener_t *oldlistener,
		  ns_lwreslistener_t *newlistener)
{
	newlistener->address = oldlistener->address;
	isc_socket_attach(oldlistener->sock, &newlistener->sock);
}

static isc_result_t
listener_startclients(ns_lwreslistener_t *listener) {
	ns_lwdclientmgr_t *cm;
	unsigned int i;
	isc_result_t result;

	/*
	 * Create the client managers.
	 */
	result = ISC_R_SUCCESS;
	for (i = 0 ; i < NTASKS && result == ISC_R_SUCCESS; i++)
		result = ns_lwdclientmgr_create(listener, NRECVS,
						ns_g_taskmgr);

	/*
	 * Ensure that we have created at least one.
	 */
	if (ISC_LIST_EMPTY(listener->cmgrs))
		return (result);

	/*
	 * Walk the list of clients and start each one up.
	 */
	LOCK(&listener->lock);
	cm = ISC_LIST_HEAD(listener->cmgrs);
	while (cm != NULL) {
		ns_lwdclient_startrecv(cm);
		cm = ISC_LIST_NEXT(cm, link);
	}
	UNLOCK(&listener->lock);

	return (ISC_R_SUCCESS);
}

static void
listener_shutdown(ns_lwreslistener_t *listener) {
	ns_lwdclientmgr_t *cm;

	cm = ISC_LIST_HEAD(listener->cmgrs);
	while (cm != NULL) {
		isc_task_shutdown(cm->task);
		cm = ISC_LIST_NEXT(cm, link);
	}
}

static isc_result_t
find_listener(isc_sockaddr_t *address, ns_lwreslistener_t **listenerp) {
	ns_lwreslistener_t *listener;

	INSIST(listenerp != NULL && *listenerp == NULL);

	for (listener = ISC_LIST_HEAD(listeners);
	     listener != NULL;
	     listener = ISC_LIST_NEXT(listener, link))
	{
		if (!isc_sockaddr_equal(address, &listener->address))
			continue;
		*listenerp = listener;
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_NOTFOUND);
}

void
ns_lwreslistener_unlinkcm(ns_lwreslistener_t *listener, ns_lwdclientmgr_t *cm)
{
	REQUIRE(VALID_LWRESLISTENER(listener));

	LOCK(&listener->lock);
	ISC_LIST_UNLINK(listener->cmgrs, cm, link);
	UNLOCK(&listener->lock);
}

void
ns_lwreslistener_linkcm(ns_lwreslistener_t *listener, ns_lwdclientmgr_t *cm) {
	REQUIRE(VALID_LWRESLISTENER(listener));

	/*
	 * This does no locking, since it's called early enough that locking
	 * isn't needed.
	 */
	ISC_LIST_APPEND(listener->cmgrs, cm, link);
}

static isc_result_t
configure_listener(isc_sockaddr_t *address, ns_lwresd_t *lwresd,
		   isc_mem_t *mctx, ns_lwreslistenerlist_t *newlisteners)
{
	ns_lwreslistener_t *listener, *oldlistener = NULL;
	char socktext[ISC_SOCKADDR_FORMATSIZE];
	isc_result_t result;

	(void)find_listener(address, &oldlistener);
	listener = NULL;
	result = listener_create(mctx, lwresd, &listener);
	if (result != ISC_R_SUCCESS) {
		isc_sockaddr_format(address, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "lwres failed to configure %s: %s",
			      socktext, isc_result_totext(result));
		return (result);
	}

	/*
	 * If there's already a listener, don't rebind the socket.
	 */
	if (oldlistener == NULL) {
		result = listener_bind(listener, address);
		if (result != ISC_R_SUCCESS)
			return (result);
	} else
		listener_copysock(oldlistener, listener);

	result = listener_startclients(listener);
	if (result != ISC_R_SUCCESS) {
		isc_sockaddr_format(address, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_WARNING,
			      "lwres: failed to start %s: %s", socktext,
			      isc_result_totext(result));
		ns_lwreslistener_detach(&listener);
		return (result);
	}

	if (oldlistener != NULL) {
		/*
		 * Remove the old listener from the old list and shut it down.
		 */
		ISC_LIST_UNLINK(listeners, oldlistener, link);
		listener_shutdown(oldlistener);
		ns_lwreslistener_detach(&oldlistener);
	} else {
		isc_sockaddr_format(address, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_NOTICE,
			      "lwres listening on %s", socktext);
	}

	ISC_LIST_APPEND(*newlisteners, listener, link);
	return (result);
}

isc_result_t
ns_lwresd_configure(isc_mem_t *mctx, dns_c_ctx_t *cctx) {
	dns_c_lwres_t *lwres = NULL;
	dns_c_lwreslist_t *list = NULL;
	ns_lwreslistener_t *listener;
	ns_lwreslistenerlist_t newlisteners;
	isc_result_t result;
	char socktext[ISC_SOCKADDR_FORMATSIZE];

	REQUIRE(mctx != NULL);
	REQUIRE(cctx != NULL);

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	ISC_LIST_INIT(newlisteners);

	result = dns_c_ctx_getlwres(cctx, &list);
	if (result != ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);

	LOCK(&listeners_lock);
	/*
	 * Run through the new lwres address list, noting sockets that
	 * are already being listened on and moving them to the new list.
	 *
	 * Identifying duplicates addr/port combinations is left to either
	 * the underlying config code, or to the bind attempt getting an
	 * address-in-use error.
	 */
	for (lwres = dns_c_lwreslist_head(list);
	     lwres != NULL;
	     lwres = dns_c_lwreslist_next(lwres))
	{
		unsigned int i;
		ns_lwresd_t *lwresd;

		lwresd = NULL;
		result = ns_lwdmanager_create(mctx, lwres, &lwresd);
		if (result != ISC_R_SUCCESS)
			return (result);

		if (lwres->listeners == NULL) {
			struct in_addr localhost;
			in_port_t port;
			isc_sockaddr_t address;

			port = lwresd_g_listenport;
			if (port == 0)
				port = LWRES_UDP_PORT;
			localhost.s_addr = htonl(INADDR_LOOPBACK);
			isc_sockaddr_fromin(&address, &localhost, port);
			result = configure_listener(&address, lwresd,
						    mctx, &newlisteners);
		} else {
			isc_sockaddr_t *address;
			for (i = 0; i < lwres->listeners->nextidx; i++) {
				address = &lwres->listeners->ips[i];
				result = configure_listener(address, lwresd,
							    mctx,
							    &newlisteners);
				if (result != ISC_R_SUCCESS)
					break;
			}
		}

		ns_lwdmanager_detach(&lwresd);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	/*
	 * Shutdown everything on the listeners list, and remove them from
	 * the list.  Then put all of the new listeners on it.
	 */

	while (!ISC_LIST_EMPTY(listeners)) {
		listener = ISC_LIST_HEAD(listeners);
		ISC_LIST_UNLINK(listeners, listener, link);
		listener_shutdown(listener);
		ns_lwreslistener_detach(&listener);

		isc_sockaddr_format(&listener->address,
				    socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_LWRESD, ISC_LOG_NOTICE,
			      "lwres no longer listening on %s", socktext);

	}
	ISC_LIST_APPENDLIST(listeners, newlisteners, link);

	UNLOCK(&listeners_lock);

	return (ISC_R_SUCCESS);
}

void
ns_lwresd_shutdown(void) {
	ns_lwreslistener_t *listener;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	while (!ISC_LIST_EMPTY(listeners)) {
		listener = ISC_LIST_HEAD(listeners);
		ISC_LIST_UNLINK(listeners, listener, link);
		ns_lwreslistener_detach(&listener);
	}
}
