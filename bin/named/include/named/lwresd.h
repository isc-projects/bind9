/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef NAMED_LWRESD_H
#define NAMED_LWRESD_H 1

/*! \file */

#include <isc/types.h>
#include <isc/sockaddr.h>

#include <isccfg/cfg.h>

#include <dns/types.h>

struct ns_lwresd {
	unsigned int magic;

	isc_mutex_t lock;
	dns_view_t *view;
	ns_lwsearchlist_t *search;
	unsigned int ndots;
	unsigned int ntasks;
	unsigned int nclients;
	isc_mem_t *mctx;
	bool shutting_down;
	unsigned int refs;
};

struct ns_lwreslistener {
	unsigned int magic;

	isc_mutex_t lock;
	isc_mem_t *mctx;
	isc_sockaddr_t address;
	ns_lwresd_t *manager;
	isc_socket_t *sock;
	unsigned int refs;
	ISC_LIST(ns_lwdclientmgr_t) cmgrs;
	ISC_LINK(ns_lwreslistener_t) link;
};

/*%
 * Configure lwresd.
 */
isc_result_t
ns_lwresd_configure(isc_mem_t *mctx, const cfg_obj_t *config);

isc_result_t
ns_lwresd_parseeresolvconf(isc_mem_t *mctx, cfg_parser_t *pctx,
			   cfg_obj_t **configp);

/*%
 * Trigger shutdown.
 */
void
ns_lwresd_shutdown(void);

/*
 * Manager functions
 */
/*% create manager */
isc_result_t
ns_lwdmanager_create(isc_mem_t *mctx, const cfg_obj_t *lwres,
		      ns_lwresd_t **lwresdp);

/*% attach to manager */
void
ns_lwdmanager_attach(ns_lwresd_t *source, ns_lwresd_t **targetp);

/*% detach from manager */
void
ns_lwdmanager_detach(ns_lwresd_t **lwresdp);

/*
 * Listener functions
 */
/*% attach to listener */
void
ns_lwreslistener_attach(ns_lwreslistener_t *source,
			ns_lwreslistener_t **targetp);

/*% detach from lister */
void
ns_lwreslistener_detach(ns_lwreslistener_t **listenerp);

/*% link client manager */
void
ns_lwreslistener_unlinkcm(ns_lwreslistener_t *listener, ns_lwdclientmgr_t *cm);

/*% unlink client manager */
void
ns_lwreslistener_linkcm(ns_lwreslistener_t *listener, ns_lwdclientmgr_t *cm);




/*
 * INTERNAL FUNCTIONS.
 */
void *
ns__lwresd_memalloc(void *arg, size_t size);

void
ns__lwresd_memfree(void *arg, void *mem, size_t size);

#endif /* NAMED_LWRESD_H */
