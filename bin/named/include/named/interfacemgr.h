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

#ifndef NAMED_INTERFACEMGR_H
#define NAMED_INTERFACEMGR_H 1

/*****
 ***** Module Info
 *****/

/*
 * Interface manager
 *
 * The interface manager monitors the operating system's list 
 * of network interfaces, creating and destroying listeners 
 * as needed.
 *
 * Reliability:
 *	No impact expected.
 *
 * Resources:
 *
 * Security:
 * 	The server will only be able to bind to the DNS port on
 *	newly discovered interfaces if it is running as root.
 *
 * Standards:
 *	The API for scanning varies greatly among operating systems.
 *	This module attempts to hide the differences.
 */

/***
 *** Imports
 ***/

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/socket.h>

#include <dns/result.h>

#include <named/listenlist.h>
#include <named/types.h>

/***
 *** Types
 ***/

#define IFACE_MAGIC		0x493A2D29U	/* I:-). */	
#define NS_INTERFACE_VALID(t)	ISC_MAGIC_VALID(t, IFACE_MAGIC)

struct ns_interface {
	unsigned int		magic;		/* Magic number. */
	ns_interfacemgr_t *	mgr;		/* Interface manager. */
	isc_mutex_t		lock;
	int			references;	/* Locked */
	unsigned int		generation;     /* Generation number. */
	isc_sockaddr_t		addr;           /* Address and port. */
	char 			name[32];	/* Null terminated. */
	isc_socket_t *		udpsocket; 	/* UDP socket. */
	dns_dispatch_t *	udpdispatch;	/* UDP dispatcher. */
	isc_socket_t *		tcpsocket;	/* TCP socket. */
	isc_task_t *		task;
	int			ntcptarget;	/* Desired number of concurrent
						   TCP accepts */
	int			ntcpcurrent;	/* Current ditto, locked */
	ISC_LINK(ns_interface_t) link;
};

/***
 *** Functions
 ***/

isc_result_t
ns_interfacemgr_create(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		       isc_socketmgr_t *socketmgr,
		       dns_dispatchmgr_t *dispatchmgr,
		       ns_clientmgr_t *clientmgr, ns_interfacemgr_t **mgrp);

void
ns_interfacemgr_attach(ns_interfacemgr_t *source, ns_interfacemgr_t **target);

void 
ns_interfacemgr_detach(ns_interfacemgr_t **targetp);

void
ns_interfacemgr_shutdown(ns_interfacemgr_t *mgr);

void
ns_interfacemgr_scan(ns_interfacemgr_t *mgr);
/*
 * Scan the operatings system's list of network interfaces
 * and create listeners when new interfaces are discovered.
 * Shut down the sockets for interfaces that go away.
 *
 * This should be called once on server startup and then
 * periodically according to the 'interface-interval' option
 * in named.conf.
 */

void
ns_interfacemgr_setlistenon(ns_interfacemgr_t *mgr, ns_listenlist_t *value);
/*
 * Set the "listen-on" list of 'mgr' to 'value'.
 * The previous listen-on list is freed.
 */

isc_result_t
ns_interfacemgr_findudpdispatcher(ns_interfacemgr_t *mgr,
				  isc_sockaddr_t *address,
				  dns_dispatch_t **dispatchp);
/*
 * Find a UDP dispatcher matching 'address', if it exists.
 */

dns_aclenv_t *
ns_interfacemgr_getaclenv(ns_interfacemgr_t *mgr);

void
ns_interface_attach(ns_interface_t *source, ns_interface_t **target);

void 
ns_interface_detach(ns_interface_t **targetp);

#endif /* NAMED_INTERFACEMGR_H */
