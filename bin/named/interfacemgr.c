/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <isc/interfaceiter.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/dispatch.h>

#include <named/client.h>
#include <named/log.h>
#include <named/interfacemgr.h>

#define IFMGR_MAGIC		0x49464D47U	/* IFMG. */	
#define NS_INTERFACEMGR_VALID(t) ISC_MAGIC_VALID(t, IFMGR_MAGIC)

#define IFMGR_COMMON_LOGARGS \
	ns_g_lctx, NS_LOGCATEGORY_NETWORK, NS_LOGMODULE_INTERFACEMGR

struct ns_interfacemgr {
	unsigned int		magic;		/* Magic number. */
	int			references;
	isc_mutex_t		lock;
	isc_mem_t *		mctx;		/* Memory context. */
	isc_taskmgr_t *		taskmgr;	/* Task manager. */
	isc_socketmgr_t *	socketmgr;	/* Socket manager. */
	dns_dispatchmgr_t *	dispatchmgr;
	ns_clientmgr_t *	clientmgr;	/* Client manager. */
	unsigned int		generation;	/* Current generation no. */
	ns_listenlist_t *	listenon4;
	ns_listenlist_t *	listenon6;
	dns_aclenv_t		aclenv;		/* Localhost/localnets ACLs */
	ISC_LIST(ns_interface_t) interfaces;	/* List of interfaces. */
};

static void
purge_old_interfaces(ns_interfacemgr_t *mgr);

isc_result_t
ns_interfacemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		       isc_socketmgr_t *socketmgr,
		       dns_dispatchmgr_t *dispatchmgr,
		       ns_clientmgr_t *clientmgr, ns_interfacemgr_t **mgrp)
{
	isc_result_t result;
	ns_interfacemgr_t *mgr;

	REQUIRE(mctx != NULL);
	REQUIRE(mgrp != NULL);
	REQUIRE(*mgrp == NULL);
	
	mgr = isc_mem_get(mctx, sizeof(*mgr));
	if (mgr == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_mutex_init(&mgr->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_mem;

	mgr->mctx = mctx;
	mgr->taskmgr = taskmgr;
	mgr->socketmgr = socketmgr;
	mgr->dispatchmgr = dispatchmgr;
	mgr->clientmgr = clientmgr;
	mgr->generation = 1;
	mgr->listenon4 = NULL;
	mgr->listenon6 = NULL;	
	ISC_LIST_INIT(mgr->interfaces);

	/*
	 * The listen-on lists are initially empty.
	 */
	result = ns_listenlist_create(mctx, &mgr->listenon4);
	if (result != ISC_R_SUCCESS)
		goto cleanup_mem;
	ns_listenlist_attach(mgr->listenon4, &mgr->listenon6);

	result = dns_aclenv_init(mctx, &mgr->aclenv);
	if (result != ISC_R_SUCCESS)
		goto cleanup_listenon;
	
	mgr->references = 1;
	mgr->magic = IFMGR_MAGIC;
	*mgrp = mgr;
	return (ISC_R_SUCCESS);

 cleanup_listenon:
	ns_listenlist_detach(&mgr->listenon4);
	ns_listenlist_detach(&mgr->listenon6);
 cleanup_mem:
	isc_mem_put(mctx, mgr, sizeof(*mgr));
	return (result);
}

static void
ns_interfacemgr_destroy(ns_interfacemgr_t *mgr) {
	REQUIRE(NS_INTERFACEMGR_VALID(mgr));
	dns_aclenv_destroy(&mgr->aclenv);
	ns_listenlist_detach(&mgr->listenon4);
	ns_listenlist_detach(&mgr->listenon6);
	isc_mutex_destroy(&mgr->lock);
	mgr->magic = 0;
	isc_mem_put(mgr->mctx, mgr, sizeof *mgr);
}

dns_aclenv_t *
ns_interfacemgr_getaclenv(ns_interfacemgr_t *mgr) {
	return (&mgr->aclenv);
}

void
ns_interfacemgr_attach(ns_interfacemgr_t *source, ns_interfacemgr_t **target) {
	REQUIRE(NS_INTERFACEMGR_VALID(source));
	LOCK(&source->lock);
	INSIST(source->references > 0);
	source->references++;
	UNLOCK(&source->lock);
	*target = source;
}

void 
ns_interfacemgr_detach(ns_interfacemgr_t **targetp) {
	isc_result_t need_destroy = ISC_FALSE;
	ns_interfacemgr_t *target = *targetp;
	REQUIRE(target != NULL);
	REQUIRE(NS_INTERFACEMGR_VALID(target));
	LOCK(&target->lock);
	REQUIRE(target->references > 0);
	target->references--;
	if (target->references == 0)
		need_destroy = ISC_TRUE;
	UNLOCK(&target->lock);
	if (need_destroy)
		ns_interfacemgr_destroy(target);
	*targetp = NULL;
}

void
ns_interfacemgr_shutdown(ns_interfacemgr_t *mgr) {
	REQUIRE(NS_INTERFACEMGR_VALID(mgr));

	LOCK(&mgr->lock);
	/*
	 * Shut down and detach all interfaces.
	 * By incrementing the generation count, we make purge_old_interfaces()
	 * consider all interfaces "old".
	 */
	mgr->generation++;
	purge_old_interfaces(mgr);
	INSIST(ISC_LIST_EMPTY(mgr->interfaces));
	UNLOCK(&mgr->lock);	
}


static isc_result_t
ns_interface_create(ns_interfacemgr_t *mgr, isc_sockaddr_t *addr,
		    const char *name, ns_interface_t **ifpret)
{
        ns_interface_t *ifp;
	isc_result_t result;
	
	REQUIRE(NS_INTERFACEMGR_VALID(mgr));
	ifp = isc_mem_get(mgr->mctx, sizeof(*ifp));
	if (ifp == NULL)
		return (ISC_R_NOMEMORY);
	ifp->mgr = NULL;
	ifp->generation = mgr->generation;
	ifp->addr = *addr;
	strncpy(ifp->name, name, sizeof(ifp->name));
	ifp->name[sizeof(ifp->name)-1] = '\0';

	result = isc_mutex_init(&ifp->lock);
	if (result != ISC_R_SUCCESS)
		goto lock_create_failure;

	/*
	 * Create a task.
	 */
	ifp->task = NULL;
	result = isc_task_create(mgr->taskmgr, 0, &ifp->task);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(IFMGR_COMMON_LOGARGS, ISC_LOG_ERROR,
				 "isc_task_create() failed: %s",
				 isc_result_totext(result));
		goto task_create_failure;
	}
	isc_task_setname(ifp->task, "ifp", ifp);

	ifp->udpdispatch = NULL;
	
	ifp->tcpsocket = NULL;
	/*
	 * Create a single TCP client object.  It will replace itself
	 * with a new one as soon as it gets a connection, so the actual
	 * connections will be handled in parallel even though there is
	 * only one client initially.
	 */
	ifp->ntcptarget = 1;
	ifp->ntcpcurrent = 0;

	ns_interfacemgr_attach(mgr, &ifp->mgr);	
	ISC_LIST_APPEND(mgr->interfaces, ifp, link);

	ifp->references = 1;
	ifp->magic = IFACE_MAGIC;
	*ifpret = ifp;

	return (ISC_R_SUCCESS);

 task_create_failure:
	isc_mutex_destroy(&ifp->lock);
 lock_create_failure:
	ifp->magic = 0;
	isc_mem_put(mgr->mctx, ifp, sizeof(*ifp));

	return (ISC_R_UNEXPECTED);
}

static isc_result_t
ns_interface_listenudp(ns_interface_t *ifp) {
	isc_result_t result;
	unsigned int attrs;
	unsigned int attrmask;
	
	attrs = 0;
	attrs |= DNS_DISPATCHATTR_UDP;
	if (isc_sockaddr_pf(&ifp->addr) == AF_INET)
		attrs |= DNS_DISPATCHATTR_IPV4;
	else
		attrs |= DNS_DISPATCHATTR_IPV6;
	attrmask = 0;
	attrmask |= DNS_DISPATCHATTR_UDP | DNS_DISPATCHATTR_TCP;
	attrmask |= DNS_DISPATCHATTR_IPV4 | DNS_DISPATCHATTR_IPV6;
	result = dns_dispatch_getudp(ifp->mgr->dispatchmgr, ns_g_socketmgr,
				     ns_g_taskmgr, &ifp->addr,
				     4096, 1000, 32768, 8219, 8237,
				     attrs, attrmask, &ifp->udpdispatch);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "UDP dns_dispatch_create(): %s",
				 isc_result_totext(result));
		goto udp_dispatch_failure;
	}

	result = ns_clientmgr_createclients(ifp->mgr->clientmgr, ns_g_cpus,
					    ifp, ISC_FALSE);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "UDP ns_clientmgr_createclients(): %s",
				 isc_result_totext(result));
		goto addtodispatch_failure;
	}
	return (ISC_R_SUCCESS);

 addtodispatch_failure:
	dns_dispatch_detach(&ifp->udpdispatch);
 udp_dispatch_failure:
	return (result);
}

static isc_result_t
ns_interface_accepttcp(ns_interface_t *ifp) {
	isc_result_t result;
	
	/*
	 * Open a TCP socket.
	 */
	result = isc_socket_create(ifp->mgr->socketmgr,
				   isc_sockaddr_pf(&ifp->addr),
				   isc_sockettype_tcp,
				   &ifp->tcpsocket);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(IFMGR_COMMON_LOGARGS, ISC_LOG_ERROR,
				 "creating TCP socket: %s",
				 isc_result_totext(result));
		goto tcp_socket_failure;
	}
	result = isc_socket_bind(ifp->tcpsocket, &ifp->addr);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(IFMGR_COMMON_LOGARGS, ISC_LOG_ERROR,
				 "binding TCP socket: %s",
				 isc_result_totext(result));
		goto tcp_bind_failure;
	}
	result = isc_socket_listen(ifp->tcpsocket, 0);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(IFMGR_COMMON_LOGARGS, ISC_LOG_ERROR,
				 "listening on TCP socket: %s",
				 isc_result_totext(result));
		goto tcp_listen_failure;
	}

	result = ns_clientmgr_createclients(ifp->mgr->clientmgr,
					    ifp->ntcptarget, ifp,
					    ISC_TRUE);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "TCP ns_clientmgr_createclients(): %s",
				 isc_result_totext(result));
		goto accepttcp_failure;
	}
	return (ISC_R_SUCCESS);

 accepttcp_failure:
 tcp_listen_failure:
 tcp_bind_failure:
	isc_socket_detach(&ifp->tcpsocket);
 tcp_socket_failure:
	return (ISC_R_SUCCESS);
}

static isc_result_t
ns_interface_setup(ns_interfacemgr_t *mgr, isc_sockaddr_t *addr,
		   const char *name, ns_interface_t **ifpret)
{
	isc_result_t result;
	ns_interface_t *ifp = NULL;
	REQUIRE(ifpret != NULL && *ifpret == NULL);
	
	result = ns_interface_create(mgr, addr, name, &ifp);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = ns_interface_listenudp(ifp);
	if (result != ISC_R_SUCCESS)
		goto cleanup_interface;

	result = ns_interface_accepttcp(ifp);
	if (result != ISC_R_SUCCESS) {
		/*
		 * XXXRTH We don't currently have a way to easily stop dispatch
		 * service, so we return currently return ISC_R_SUCCESS (the
		 * UDP stuff will work even if TCP creation failed).  This will
		 * be fixed later.
		 */
		result = ISC_R_SUCCESS;
	}
	*ifpret = ifp;
	return (ISC_R_SUCCESS);
	
 cleanup_interface:
	ISC_LIST_UNLINK(ifp->mgr->interfaces, ifp, link);	
	ns_interface_detach(&ifp);
	return (result);
}

static void
ns_interface_destroy(ns_interface_t *ifp) {
	isc_mem_t *mctx = ifp->mgr->mctx;
	REQUIRE(NS_INTERFACE_VALID(ifp));

	if (ifp->udpdispatch != NULL)
		dns_dispatch_detach(&ifp->udpdispatch);
	if (ifp->tcpsocket != NULL) {
		isc_socket_cancel(ifp->tcpsocket, NULL, ISC_SOCKCANCEL_ALL);
		isc_socket_detach(&ifp->tcpsocket);
	}

	isc_task_detach(&ifp->task);
	isc_mutex_destroy(&ifp->lock);

	ns_interfacemgr_detach(&ifp->mgr);
	
	ifp->magic = 0;
	isc_mem_put(mctx, ifp, sizeof(*ifp));
}

void
ns_interface_attach(ns_interface_t *source, ns_interface_t **target) {
	REQUIRE(NS_INTERFACE_VALID(source));
	LOCK(&source->lock);
	INSIST(source->references > 0);
	source->references++;
	UNLOCK(&source->lock);
	*target = source;
}

void 
ns_interface_detach(ns_interface_t **targetp) {
	isc_result_t need_destroy = ISC_FALSE;
	ns_interface_t *target = *targetp;
	REQUIRE(target != NULL);
	REQUIRE(NS_INTERFACE_VALID(target));
	LOCK(&target->lock);
	REQUIRE(target->references > 0);
	target->references--;
	if (target->references == 0)
		need_destroy = ISC_TRUE;
	UNLOCK(&target->lock);
	if (need_destroy)
		ns_interface_destroy(target);
	*targetp = NULL;
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
		INSIST(NS_INTERFACE_VALID(ifp));
		next = ISC_LIST_NEXT(ifp, link);
		if (ifp->generation != mgr->generation) {
			char sabuf[256];
			ISC_LIST_UNLINK(ifp->mgr->interfaces, ifp, link);
			isc_sockaddr_format(&ifp->addr, sabuf, sizeof(sabuf));
			isc_log_write(IFMGR_COMMON_LOGARGS,
				      ISC_LOG_INFO,
				      "no longer listening on %s", sabuf);
			ns_interface_detach(&ifp);
		}
	}
}

static isc_result_t
clearacl(isc_mem_t *mctx, dns_acl_t **aclp) {
	dns_acl_t *newacl = NULL;
	isc_result_t result;
	result = dns_acl_create(mctx, 10, &newacl);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_acl_detach(aclp);
	dns_acl_attach(newacl, aclp);
	dns_acl_detach(&newacl);
	return (ISC_R_SUCCESS);
}

static void
do_ipv4(ns_interfacemgr_t *mgr) {
	isc_interfaceiter_t *iter = NULL;
	isc_result_t result;

	result = isc_interfaceiter_create(mgr->mctx, &iter);
	if (result != ISC_R_SUCCESS)
		return;

	result = clearacl(mgr->mctx, &mgr->aclenv.localhost);
	if (result != ISC_R_SUCCESS)
		goto cleanup_iter;
	result = clearacl(mgr->mctx, &mgr->aclenv.localnets);
	if (result != ISC_R_SUCCESS)
		goto cleanup_iter;
	
	for (result = isc_interfaceiter_first(iter);
	     result == ISC_R_SUCCESS;
	     result = isc_interfaceiter_next(iter))
	{
		ns_interface_t *ifp;
		isc_interface_t interface;
		ns_listenelt_t *le;
		dns_aclelement_t elt;
		unsigned int prefixlen;
		
		result = isc_interfaceiter_current(iter, &interface);
		if (result != ISC_R_SUCCESS)
			break;

		if (interface.address.family != AF_INET)
			continue;

		if ((interface.flags & INTERFACE_F_UP) == 0)
			continue;

		result = isc_netaddr_masktoprefixlen(&interface.netmask,
						     &prefixlen);
		if (result != ISC_R_SUCCESS)
			goto ignore_interface;
		elt.type = dns_aclelementtype_ipprefix;
		elt.negative = ISC_FALSE;
		elt.u.ip_prefix.address = interface.address;
		elt.u.ip_prefix.prefixlen = prefixlen;
		/* XXX suppress duplicates */
		result = dns_acl_appendelement(mgr->aclenv.localnets, &elt);
		if (result != ISC_R_SUCCESS)
			goto ignore_interface;
		elt.u.ip_prefix.prefixlen = 32;
		result = dns_acl_appendelement(mgr->aclenv.localhost, &elt);
		if (result != ISC_R_SUCCESS)
			goto ignore_interface;
		
		for (le = ISC_LIST_HEAD(mgr->listenon4->elts);
		     le != NULL;
		     le = ISC_LIST_NEXT(le, link))
		{
			int match;
			isc_netaddr_t listen_netaddr;
			isc_sockaddr_t listen_sockaddr;

			/*
			 * Construct a socket address for this IP/port
			 * combination.
			 */
			isc_netaddr_fromin(&listen_netaddr,
					   &interface.address.type.in);
			isc_sockaddr_fromnetaddr(&listen_sockaddr,
						 &listen_netaddr,
						 le->port);

			/*
			 * See if the address matches the listen-on statement;
			 * if not, ignore the interface.
			 */
			result = dns_acl_match(&listen_netaddr, NULL,
					       le->acl, &mgr->aclenv,
					       &match, NULL);
			if (match <= 0)
				continue;
			
			ifp = find_matching_interface(mgr, &listen_sockaddr);
			if (ifp != NULL) {
				ifp->generation = mgr->generation;
			} else {
				char sabuf[256];
				isc_sockaddr_format(&listen_sockaddr,
						    sabuf, sizeof(sabuf));
				isc_log_write(IFMGR_COMMON_LOGARGS,
					      ISC_LOG_INFO,
					      "listening on IPv4 interface "
					      "%s, %s", interface.name, sabuf);
				
				result = ns_interface_setup(mgr,
							    &listen_sockaddr,
							    interface.name,
							    &ifp);
				if (result != ISC_R_SUCCESS) {
					isc_log_write(IFMGR_COMMON_LOGARGS,
						 ISC_LOG_ERROR,
						 "creating IPv4 interface %s "
						 "failed; interface ignored",
						 interface.name);
				}
				/* Continue. */
			}

		}
		continue;

	ignore_interface:
		isc_log_write(IFMGR_COMMON_LOGARGS,
			      ISC_LOG_ERROR,
			      "ignoring IPv4 interface %s: %s",
			      interface.name, isc_result_totext(result));
		continue;
	}
	if (result != ISC_R_NOMORE)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "IPv4: interface iteration failed: %s",
				 isc_result_totext(result));
 cleanup_iter:
	isc_interfaceiter_destroy(&iter);
}

static isc_boolean_t
listenon_is_ip6_none(ns_listenlist_t *p) {
	ns_listenelt_t *elt;
	if (ISC_LIST_EMPTY(p->elts))
		return (ISC_TRUE); /* No listen-on-v6 statements */
	elt = ISC_LIST_HEAD(p->elts);
	if (ISC_LIST_NEXT(elt, link) != NULL)
		return (ISC_FALSE); /* More than one listen-on-v6 stmt */
	if (elt->acl->length == 0)
		return (ISC_TRUE); /* listen-on-v6 { } */
	if (elt->acl->length > 1)
		return (ISC_FALSE);  /* listen-on-v6 { ...; ...; } */
	if (elt->acl->elements[0].negative == ISC_TRUE &&
	    elt->acl->elements[0].type == dns_aclelementtype_any)
		return (ISC_TRUE);  /* listen-on-v6 { none; } */
	return (ISC_FALSE); /* All others */
}

static isc_boolean_t
listenon_is_ip6_any(ns_listenlist_t *p, in_port_t *portp) {
	ns_listenelt_t *elt;
	if (ISC_LIST_EMPTY(p->elts))
		return (ISC_FALSE); /* No listen-on-v6 statements */
	elt = ISC_LIST_HEAD(p->elts);
	if (ISC_LIST_NEXT(elt, link) != NULL)
		return (ISC_FALSE); /* More than one listen-on-v6 stmt */
	if (elt->acl->length != 1)
		return (ISC_FALSE); 
	if (elt->acl->elements[0].negative == ISC_FALSE &&
	    elt->acl->elements[0].type == dns_aclelementtype_any) {
		*portp = elt->port;
		return (ISC_TRUE);  /* listen-on-v6 { any; } */
	}
	return (ISC_FALSE); /* All others */
}

static void
do_ipv6(ns_interfacemgr_t *mgr) {
	isc_result_t result;
	ns_interface_t *ifp;
	isc_sockaddr_t listen_addr;
	struct in6_addr in6a;
	in_port_t port;

	if (listenon_is_ip6_none(mgr->listenon6))
		return;
	
	if (! listenon_is_ip6_any(mgr->listenon6, &port)) {
		isc_log_write(IFMGR_COMMON_LOGARGS,
		      ISC_LOG_ERROR,			
		      "bad IPv6 listen-on list: must be 'any' or 'none'");
		return;
	}
		
	in6a = in6addr_any;
	isc_sockaddr_fromin6(&listen_addr, &in6a, port);

	ifp = find_matching_interface(mgr, &listen_addr);
	if (ifp != NULL) {
		ifp->generation = mgr->generation;
	} else {
		isc_log_write(IFMGR_COMMON_LOGARGS, ISC_LOG_INFO,
			      "listening on IPv6 interfaces, port %u", port);
		result = ns_interface_setup(mgr, &listen_addr, "<any>", &ifp);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(IFMGR_COMMON_LOGARGS,
				      ISC_LOG_ERROR,			
				      "listening on IPv6 interfaces failed");
			/* Continue. */
		}
	}
}

void
ns_interfacemgr_scan(ns_interfacemgr_t *mgr, isc_boolean_t verbose) {

	REQUIRE(NS_INTERFACEMGR_VALID(mgr));

	mgr->generation++;	/* Increment the generation count. */ 

	if (isc_net_probeipv6() == ISC_R_SUCCESS) {
		do_ipv6(mgr);
	} else
		isc_log_write(IFMGR_COMMON_LOGARGS,
			      verbose ? ISC_LOG_INFO : ISC_LOG_DEBUG(1),
			      "no IPv6 interfaces found");
	if (isc_net_probeipv4() == ISC_R_SUCCESS)
		do_ipv4(mgr);
	else
		isc_log_write(IFMGR_COMMON_LOGARGS,
			      verbose ? ISC_LOG_INFO : ISC_LOG_DEBUG(1),
			      "no IPv4 interfaces found");

        /*
         * Now go through the interface list and delete anything that
         * does not have the current generation number.  This is
         * how we catch interfaces that go away or change their
         * addresses.
	 */
	purge_old_interfaces(mgr);

	if (ISC_LIST_EMPTY(mgr->interfaces)) {
		isc_log_write(IFMGR_COMMON_LOGARGS, ISC_LOG_WARNING,
			      "not listening on any interfaces");
		/*
		 * Continue anyway.
		 */
	}
}

void
ns_interfacemgr_setlistenon4(ns_interfacemgr_t *mgr, ns_listenlist_t *value) {
	LOCK(&mgr->lock);
	ns_listenlist_detach(&mgr->listenon4);
	ns_listenlist_attach(value, &mgr->listenon4);
	UNLOCK(&mgr->lock);
}

void
ns_interfacemgr_setlistenon6(ns_interfacemgr_t *mgr, ns_listenlist_t *value) {
	LOCK(&mgr->lock);
	ns_listenlist_detach(&mgr->listenon6);
	ns_listenlist_attach(value, &mgr->listenon6);
	UNLOCK(&mgr->lock);
}

isc_result_t
ns_interfacemgr_findudpdispatcher(ns_interfacemgr_t *mgr,
				  isc_sockaddr_t *address,
				  dns_dispatch_t **dispatchp)
{
	ns_interface_t *ifp;

	/*
	 * Find a UDP dispatcher matching 'address', if it exists.
	 */

	ifp = find_matching_interface(mgr, address);
	if (ifp == NULL || ifp->udpdispatch == NULL)
		return (ISC_R_NOTFOUND);
	dns_dispatch_attach(ifp->udpdispatch, dispatchp);

	return (ISC_R_SUCCESS);
}
