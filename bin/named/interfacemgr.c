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

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/types.h>
#include <isc/net.h>
#include <isc/interfaceiter.h>

#include <dns/dispatch.h>

#include <named/client.h>
#include <named/globals.h>
#include <named/log.h>
#include <named/interfacemgr.h>

typedef struct ns_interface ns_interface_t;

#define IFMGR_MAGIC		0x49464D47U	/* IFMG. */	
#define VALID_IFMGR(t)		((t) != NULL && (t)->magic == IFMGR_MAGIC)

struct ns_interfacemgr {
	unsigned int		magic;		/* Magic number. */
	isc_mem_t *		mctx;		/* Memory context. */
	isc_taskmgr_t *		taskmgr;	/* Task manager. */
	isc_socketmgr_t *	socketmgr;	/* Socket manager. */
	ns_clientmgr_t *	clientmgr;	/* Client manager. */
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
	isc_socket_t *		udpsocket; 	/* UDP socket. */
	dns_dispatch_t *	udpdispatch;	/* UDP dispatcher. */
	isc_socket_t *		tcpsocket;	/* TCP socket. */
	isc_task_t *		task;
	ISC_LINK(ns_interface_t) link;
};

isc_result_t
ns_interfacemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		       isc_socketmgr_t *socketmgr, ns_clientmgr_t *clientmgr,
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
	mgr->clientmgr = clientmgr;
	mgr->generation = 1;
	ISC_LIST_INIT(mgr->interfaces);

	mgr->magic = IFMGR_MAGIC;
	*mgrp = mgr;
	return (DNS_R_SUCCESS);
}

static isc_result_t
ns_interface_create(ns_interfacemgr_t *mgr, isc_sockaddr_t *addr,
		    isc_boolean_t udp_only, ns_interface_t **ifpret) {
        ns_interface_t *ifp;
	isc_result_t result;
	
	REQUIRE(VALID_IFMGR(mgr));
	ifp = isc_mem_get(mgr->mctx, sizeof(*ifp));
	if (ifp == NULL)
		return (DNS_R_NOMEMORY);
	ifp->mgr = mgr;
	ifp->generation = mgr->generation;
	ifp->addr = *addr;

	/*
	 * Create a task.
	 */
	ifp->task = NULL;
	result = isc_task_create(mgr->taskmgr, mgr->mctx, 0, &ifp->task);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_task_create() failed: %s",
				 isc_result_totext(result));
		goto task_create_failure;
	}

	/*
	 * Open a UDP socket.
	 */
	ifp->udpsocket = NULL;
	result = isc_socket_create(mgr->socketmgr,
				   isc_sockaddr_pf(addr),
				   isc_sockettype_udp,
				   &ifp->udpsocket);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "creating UDP socket: %s",
				 isc_result_totext(result));
		goto udp_socket_failure;
	}
	result = isc_socket_bind(ifp->udpsocket, &ifp->addr);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "binding UDP socket: %s",
				 isc_result_totext(result));
		goto udp_bind_failure;
	}
	/* 
	 * XXXRTH hardwired constants.  We're going to need to determine if
	 * this UDP socket will be shared with the resolver, and if so, we
	 * need to set the hashsize to be be something bigger than 17.
	 */
	ifp->udpdispatch = NULL;
	result = dns_dispatch_create(mgr->mctx, ifp->udpsocket, ifp->task,
				     4096, 50, 50, 17, 19, &ifp->udpdispatch);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "UDP dns_dispatch_create(): %s",
				 isc_result_totext(result));
		goto udp_dispatch_failure;
	}
	result = ns_clientmgr_addtodispatch(mgr->clientmgr, ns_g_cpus,
					    ifp->udpdispatch);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "UDP ns_clientmgr_addtodispatch(): %s",
				 isc_result_totext(result));
		goto addtodispatch_failure;
	}

	ifp->tcpsocket = NULL;
	if (!udp_only) {
		/*
		 * Open a TCP socket.
		 */
		result = isc_socket_create(mgr->socketmgr,
					   isc_sockaddr_pf(addr),
					   isc_sockettype_tcp,
					   &ifp->tcpsocket);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "creating TCP socket: %s",
					 isc_result_totext(result));
			goto tcp_socket_failure;
		}
		result = isc_socket_bind(ifp->tcpsocket, &ifp->addr);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "binding TCP socket: %s",
					 isc_result_totext(result));
			goto tcp_bind_failure;
		}
		result = isc_socket_listen(ifp->tcpsocket, 0);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "listen TCP socket: %s",
					 isc_result_totext(result));
			goto tcp_listen_failure;
		}
		result = ns_clientmgr_accepttcp(mgr->clientmgr, ifp->tcpsocket,
						ns_g_cpus);
		if (result != ISC_R_SUCCESS) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "TCP ns_clientmgr_accepttcp(): %s",
					 isc_result_totext(result));
			goto accepttcp_failure;
		}
	}

	ISC_LIST_APPEND(mgr->interfaces, ifp, link);

	ifp->magic = IFACE_MAGIC;
	*ifpret = ifp;

	return (DNS_R_SUCCESS);

 accepttcp_failure:
 tcp_listen_failure:
 tcp_bind_failure:
	isc_socket_detach(&ifp->tcpsocket);
 tcp_socket_failure:
	/*
	 * XXXRTH  We don't currently have a way to easily stop dispatch
	 * service, so we return currently return DNS_R_SUCCESS (the UDP
	 * stuff will work even if TCP creation failed).  This will be fixed
	 * later.
	 */
	return (DNS_R_SUCCESS);

 addtodispatch_failure:
	dns_dispatch_detach(&ifp->udpdispatch);
 udp_dispatch_failure:
 udp_bind_failure:
	isc_socket_detach(&ifp->udpsocket);
 udp_socket_failure:
	isc_task_detach(&ifp->task);
 task_create_failure:
	ifp->magic = 0;
	isc_mem_put(mgr->mctx, ifp, sizeof(*ifp));

	return (DNS_R_UNEXPECTED);
}

static isc_result_t
ns_interface_destroy(ns_interface_t **ifpret) {
        ns_interface_t *ifp;	
	REQUIRE(ifpret != NULL);
	REQUIRE(VALID_IFACE(*ifpret));
	ifp = *ifpret;

	ISC_LIST_UNLINK(ifp->mgr->interfaces, ifp, link);

	dns_dispatch_detach(&ifp->udpdispatch);
	isc_socket_cancel(ifp->udpsocket, NULL, ISC_SOCKCANCEL_ALL);
	isc_socket_detach(&ifp->udpsocket);

	if (ifp->tcpsocket != NULL) {
		isc_socket_cancel(ifp->tcpsocket, NULL, ISC_SOCKCANCEL_ALL);
		isc_socket_detach(&ifp->tcpsocket);
	}

	isc_task_detach(&ifp->task);
	
	ifp->magic = 0;
	isc_mem_put(ifp->mgr->mctx, ifp, sizeof(*ifp));
	
	*ifpret = NULL;
	return (DNS_R_SUCCESS);
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
		if (isc_sockaddr_equal(&ifp->addr, addr))
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
			isc_result_t result = ns_interface_destroy(&ifp);
			RUNTIME_CHECK(result == DNS_R_SUCCESS);
		}
	}
}

static void
do_ipv4(ns_interfacemgr_t *mgr, isc_boolean_t udp_only) {
	isc_interfaceiter_t *iter = NULL;
	isc_result_t result;

	result = isc_interfaceiter_create(mgr->mctx, &iter);
	if (result != ISC_R_SUCCESS)
		return;
	
	result = isc_interfaceiter_first(iter);
	while (result == ISC_R_SUCCESS) {
		ns_interface_t *ifp;
		isc_interface_t interface;
		isc_sockaddr_t listen_addr;

		/*
		 * XXX insert code to match against named.conf
		 * "listen-on" statements here.  Also build list of
		 * local addresses and local networks.
		 */
		
		result = isc_interfaceiter_current(iter, &interface);
		if (result != ISC_R_SUCCESS)
			break;
		
		isc_sockaddr_fromin(&listen_addr,
				    &interface.address.type.in,
				    ns_g_port);

		ifp = find_matching_interface(mgr, &listen_addr);
		if (ifp != NULL) {
			ifp->generation = mgr->generation;
		} else {
			char buf[128];
			const char *addrstr;

			addrstr = inet_ntop(listen_addr.type.sin.sin_family,
					    &listen_addr.type.sin.sin_addr,
					    buf, sizeof(buf));
			if (addrstr == NULL)
				addrstr = "(bad address)";
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_NETWORK,
				      NS_LOGMODULE_INTERFACEMGR,
				      ISC_LOG_INFO,
				"listening on IPv4 interface %s, %s port %u",
				      interface.name, addrstr,
				      ntohs(listen_addr.type.sin.sin_port));
		
			result = ns_interface_create(mgr, &listen_addr,
						     udp_only, &ifp);
			if (result != DNS_R_SUCCESS) {
				UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "listening on IPv4 interface %s"
					 " failed; interface ignored",
						 interface.name);
			}
		}
		result = isc_interfaceiter_next(iter);
	}
	if (result != ISC_R_NOMORE)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "IPv4: interface iteration failed: %s",
				 isc_result_totext(result));

	isc_interfaceiter_destroy(&iter);
}

static void
do_ipv6(ns_interfacemgr_t *mgr) {
	isc_result_t result;
	ns_interface_t *ifp;
	isc_sockaddr_t listen_addr;
	struct in6_addr in6a;

	in6a = in6addr_any;
	isc_sockaddr_fromin6(&listen_addr, &in6a, ns_g_port);

	ifp = find_matching_interface(mgr, &listen_addr);
	if (ifp != NULL) {
		ifp->generation = mgr->generation;
	} else {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_NETWORK,
			      NS_LOGMODULE_INTERFACEMGR, ISC_LOG_INFO,
			      "listening on IPv6 interfaces, port %u",
			      ns_g_port);
		result = ns_interface_create(mgr, &listen_addr, ISC_FALSE,
					     &ifp);
		if (result != DNS_R_SUCCESS)
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "listening on IPv6 interfaces failed");
	}
}

void
ns_interfacemgr_scan(ns_interfacemgr_t *mgr) {
	isc_boolean_t udp_only = ISC_FALSE;

	REQUIRE(VALID_IFMGR(mgr));

	mgr->generation++;	/* Increment the generation count. */ 

	if (isc_net_probeipv6() == ISC_R_SUCCESS) {
		do_ipv6(mgr);
		udp_only = ISC_TRUE;
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_NETWORK,
			      NS_LOGMODULE_INTERFACEMGR, ISC_LOG_INFO,
			      "no IPv6 interfaces found");
	if (isc_net_probeipv4() == ISC_R_SUCCESS)
		do_ipv4(mgr, udp_only);
	else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_NETWORK,
			      NS_LOGMODULE_INTERFACEMGR, ISC_LOG_INFO,
			      "no IPv4 interfaces found");

        /*
         * Now go through the interface list and delete anything that
         * does not have the current generation number.  This is
         * how we catch interfaces that go away or change their
         * addresses.
	 */
	purge_old_interfaces(mgr);

	if (ISC_LIST_EMPTY(mgr->interfaces)) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_NETWORK,
			      NS_LOGMODULE_INTERFACEMGR, ISC_LOG_WARNING,
			      "not listening on any interfaces");
		/*
		 * Continue anyway.
		 */
	}
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
