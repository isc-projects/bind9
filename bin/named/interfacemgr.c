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
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/types.h>
#include <isc/inet.h>
#include <isc/interfaceiter.h>

#include "interfacemgr.h"
#include "udpclient.h"
#include "tcpclient.h"

typedef struct ns_interface ns_interface_t;

#define IFMGR_MAGIC		0x49464D47U	/* IFMG. */	
#define VALID_IFMGR(t)		((t) != NULL && (t)->magic == IFMGR_MAGIC)

struct ns_interfacemgr {
	unsigned int		magic;		/* Magic number. */
	isc_mem_t *		mctx;		/* Memory context. */
	isc_taskmgr_t *		taskmgr;	/* Task manager. */
	isc_socketmgr_t *	socketmgr;	/* Socket manager. */
	ns_dispatch_func *	dispatch;	/* Dispatch function */
	unsigned int		generation;	/* Current generation no. */
	ISC_LIST(ns_interface_t) interfaces;	/* List of interfaces. */
};

#define IFACE_MAGIC		0x493A2D29U	/* I:-). */	
#define VALID_IFACE(t)		((t) != NULL && (t)->magic == IFACE_MAGIC)

struct ns_interface {
	unsigned int		magic;		/* Magic number. */
	ns_interfacemgr_t *	mgr;		/* Interface manager. */
	unsigned int		generation;     /* Generation number. */
	isc_sockaddr_t		addr;           /* Address and port. */
	isc_socket_t		*udpsocket; 	/* UDP socket. */
	isc_socket_t		*tcpsocket;	/* TCP socket. */
	ISC_LINK(ns_interface_t) link;
};

dns_result_t
ns_interfacemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		       isc_socketmgr_t *socketmgr,
		       ns_dispatch_func *dispatch,
		       ns_interfacemgr_t **mgrp)
{
	ns_interfacemgr_t *mgr;
	
	REQUIRE(mctx != NULL);
	REQUIRE(mgrp != NULL);
	REQUIRE(*mgrp == NULL);
	
	mgr = isc_mem_get(mctx, sizeof(*mgr));
	if (mgr == NULL)
		return (DNS_R_NOMEMORY);

	mgr->mctx = mctx;
	mgr->taskmgr = taskmgr;
	mgr->socketmgr = socketmgr;
	mgr->dispatch = dispatch;
	mgr->generation = 1;
	ISC_LIST_INIT(mgr->interfaces);

	mgr->magic = IFMGR_MAGIC;
	*mgrp = mgr;
	return (DNS_R_SUCCESS);
}

static dns_result_t
ns_interface_create(ns_interfacemgr_t *mgr, isc_sockaddr_t *addr,
		    ns_interface_t **ifpret) {
        ns_interface_t *ifp;
	isc_result_t iresult;
	udp_listener_t *udpl;
	tcp_listener_t *tcpl;
	
	REQUIRE(VALID_IFMGR(mgr));
	ifp = isc_mem_get(mgr->mctx, sizeof(*ifp));
	if (ifp == NULL)
		return (DNS_R_NOMEMORY);
	ifp->mgr = mgr;
	ifp->generation = mgr->generation;
	
	ifp->addr = *addr;

	/*
	 * Open a UDP socket.
	 */
	ifp->udpsocket = NULL;
	iresult = isc_socket_create(mgr->socketmgr, isc_socket_udp,
				    &ifp->udpsocket);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "creating udp socket: %s",
				 isc_result_totext(iresult));
		goto udp_socket_failure;
	}
	
	RUNTIME_CHECK(iresult == ISC_R_SUCCESS);
	iresult = isc_socket_bind(ifp->udpsocket, &ifp->addr,
				  sizeof(ifp->addr));
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "binding udp socket: %s",
				 isc_result_totext(iresult));
		goto udp_bind_failure;
	}

	udpl = udp_listener_allocate(mgr->mctx, 2); /* XXX configurable */
	RUNTIME_CHECK(udpl != NULL);
	iresult = udp_listener_start(udpl, ifp->udpsocket,
				     mgr->taskmgr,
				     2, 2, /* XXX configurable */
				     0, mgr->dispatch);
	RUNTIME_CHECK(iresult == ISC_R_SUCCESS);

	/*
	 * Open a TCP socket.
	 */
	ifp->tcpsocket = NULL;
	iresult = isc_socket_create(mgr->socketmgr, isc_socket_tcp,
				    &ifp->tcpsocket);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "creating tcp socket: %s",
				 isc_result_totext(iresult));
		goto tcp_socket_failure;
	}

	iresult = isc_socket_bind(ifp->tcpsocket, &ifp->addr,
				  sizeof(ifp->addr));
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "binding tcpp socket: %s",
				 isc_result_totext(iresult));
		goto tcp_bind_failure;
	}

	tcpl = tcp_listener_allocate(mgr->mctx, 2); /* XXX configurable */
	RUNTIME_CHECK(tcpl != NULL);
	iresult = tcp_listener_start(tcpl, ifp->tcpsocket,
				     mgr->taskmgr,
				     2, 2, /* XXX configurable */
				     0, mgr->dispatch);
	RUNTIME_CHECK(iresult == ISC_R_SUCCESS);
	
	ISC_LIST_APPEND(mgr->interfaces, ifp, link);

	ifp->magic = IFACE_MAGIC;
	*ifpret = ifp;
	return (DNS_R_SUCCESS);

 tcp_bind_failure:
	isc_socket_detach(&ifp->tcpsocket);
 tcp_socket_failure:
 udp_bind_failure:
	isc_socket_detach(&ifp->udpsocket);
 udp_socket_failure:
	ifp->magic = 0;
	isc_mem_put(mgr->mctx, ifp, sizeof(*ifp));
	return (DNS_R_UNEXPECTED);
	
}

static dns_result_t
ns_interface_destroy(ns_interface_t **ifpret) {
        ns_interface_t *ifp;	
	REQUIRE(ifpret != NULL);
	REQUIRE(VALID_IFACE(*ifpret));
	ifp = *ifpret;
	printf("destroying interface\n");	
	isc_mem_put(ifp->mgr->mctx, ifp, sizeof(*ifp));

	isc_socket_cancel(ifp->udpsocket, NULL, ISC_SOCKCANCEL_ALL);
	isc_socket_detach(&ifp->udpsocket);

	isc_socket_cancel(ifp->tcpsocket, NULL, ISC_SOCKCANCEL_ALL);
	isc_socket_detach(&ifp->tcpsocket);
	
	/* The listener will go away by itself when the socket shuts down. */

	ISC_LIST_UNLINK(ifp->mgr->interfaces, ifp, link);

	ifp->magic = 0;	
	*ifpret = NULL;
	return (DNS_R_SUCCESS);
}

/*
 * Determine whether two socket addresses of type isc_sockaddr_t have 
 * the same address and port.
 */

static isc_boolean_t
sockaddr_same(isc_sockaddr_t *a, isc_sockaddr_t *b) {
	INSIST(a->type.sin.sin_family == AF_INET); /* XXX IPv6 */
	INSIST(b->type.sin.sin_family == AF_INET); /* XXX IPv6 */	
	return ((a->type.sin.sin_addr.s_addr == b->type.sin.sin_addr.s_addr &&
		 a->type.sin.sin_port == b->type.sin.sin_port) ?
		ISC_TRUE : ISC_FALSE);
}

/*
 * Search the interface list for an interface whose address and port
 * both match those of 'addr'.  Return a pointer to it, or NULL if not found.
 */
static ns_interface_t *
find_matching_interface(ns_interfacemgr_t *mgr, isc_sockaddr_t *addr) {
        ns_interface_t *ifp;
        for (ifp = ISC_LIST_HEAD(mgr->interfaces); ifp != NULL;
	     ifp = ISC_LIST_NEXT(ifp, link)) {
		if (sockaddr_same(&ifp->addr, addr))
			break;
	}
        return (ifp);
}

/*
 * Remove any interfaces whose generation number is not the current one.
 */
static void
purge_old_interfaces(ns_interfacemgr_t *mgr) {
        ns_interface_t *ifp, *next;
        for (ifp = ISC_LIST_HEAD(mgr->interfaces); ifp != NULL; ifp = next) {
		INSIST(VALID_IFACE(ifp));
		next = ISC_LIST_NEXT(ifp, link);
		if (ifp->generation != mgr->generation)  {
			dns_result_t result = ns_interface_destroy(&ifp);
			RUNTIME_CHECK(result == DNS_R_SUCCESS);
		}
	}
}

dns_result_t
ns_interfacemgr_scan(ns_interfacemgr_t *mgr) {
	isc_interfaceiter_t *iter = NULL;
	isc_result_t iter_result;
	
	mgr->generation++;	/* Increment the generation count. */ 

	isc_interfaceiter_create(mgr->mctx, &iter);

	iter_result = isc_interfaceiter_first(iter);
	while (iter_result == ISC_R_SUCCESS) {
		ns_interface_t *ifp;
		int listen_port = 5544; /* XXX from configuration */
		isc_interface_t interface;
		isc_sockaddr_t listen_addr;

		/*
		 * XXX insert code to match against named.conf "listen-on"
		 * statements here.  Also build list of local addresses
		 * and local networks.
		 */

		iter_result = isc_interfaceiter_current(iter, &interface);
		INSIST(iter_result == ISC_R_SUCCESS);

		listen_addr = interface.address;
		INSIST(listen_addr.type.sin.sin_family == AF_INET);
		listen_addr.type.sin.sin_port = htons(listen_port);

		ifp = find_matching_interface(mgr, &listen_addr);
		if (ifp) {
			ifp->generation = mgr->generation;
		} else {
			dns_result_t result;
			char buf[128];
			const char *addrstr;
			/* XXX IPv6 */
			addrstr = isc_inet_ntop(listen_addr.type.sin.sin_family,
						&listen_addr.type.sin.sin_addr,
						buf, sizeof(buf));
			if (addrstr == NULL)
				addrstr = "(bad address)";
			printf("listening on %s (%s port %d)\n",
			       interface.name, addrstr,
			       ntohs(listen_addr.type.sin.sin_port));
				/* XXX IPv6 */
			
			result = ns_interface_create(mgr, &listen_addr, &ifp);
			if (result != DNS_R_SUCCESS) {
				UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "listening on interface %s failed, "
					 "interface ignored", interface.name);
			}
		}
		iter_result = isc_interfaceiter_next(iter);
	}
	INSIST(iter_result == ISC_R_NOMORE);

	isc_interfaceiter_destroy(&iter);

        /*
         * Now go through the interface list and delete anything that
         * does not have the current generation number.  This is
         * how we catch interfaces that go away or change their
         * addresses.
	 */
	purge_old_interfaces(mgr);

	if (ISC_LIST_EMPTY(mgr->interfaces)) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "warning: not listening on any interfaces");
		/* Continue anyway. */
	}
	
	return (DNS_R_SUCCESS);
}

void
ns_interfacemgr_destroy(ns_interfacemgr_t **mgrp)
{
	ns_interfacemgr_t *mgr;

	REQUIRE(mgrp != NULL);
	mgr = *mgrp;
	REQUIRE(VALID_IFMGR(mgr));

	/*
	 * Destroy all interfaces.  By incrementing the generation count,
	 * we make purge_old_interfaces() consider all interfaces "old"
	 * and destroy all of them.
	 */
	mgr->generation++;
	purge_old_interfaces(mgr);
	INSIST(ISC_LIST_EMPTY(mgr->interfaces));

	mgr->magic = 0;
	isc_mem_put(mgr->mctx, mgr, sizeof *mgr);
	*mgrp = NULL;
}
