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

#ifndef NS_LISTENLIST_H
#define NS_LISTENLIST_H 1

/*****
***** Module Info
*****/

/*! \file
 * \brief
 * "Listen lists", as in the "listen-on" configuration statement.
 */

/***
 *** Imports
 ***/

#include <stdbool.h>

#include <isc/net.h>
#include <isc/tls.h>

#include <dns/types.h>

/***
 *** Types
 ***/

typedef struct ns_listenelt  ns_listenelt_t;
typedef struct ns_listenlist ns_listenlist_t;

struct ns_listenelt {
	isc_mem_t *   mctx;
	in_port_t     port;
	bool	      is_http;
	isc_dscp_t    dscp; /* -1 = not set, 0..63 */
	dns_acl_t *   acl;
	isc_tlsctx_t *sslctx;
	char **	      http_endpoints;
	size_t	      http_endpoints_number;
	isc_quota_t * http_quota;
	uint32_t      max_concurrent_streams;
	ISC_LINK(ns_listenelt_t) link;
};

struct ns_listenlist {
	isc_mem_t *mctx;
	int	   refcount;
	ISC_LIST(ns_listenelt_t) elts;
};

typedef struct ns_listen_tls_params {
	const char *key;
	const char *cert;
	uint32_t    protocols;
	const char *dhparam_file;
	const char *ciphers;
	bool	    prefer_server_ciphers;
	bool	    prefer_server_ciphers_set;
	bool	    session_tickets;
	bool	    session_tickets_set;
} ns_listen_tls_params_t;

/***
 *** Functions
 ***/

isc_result_t
ns_listenelt_create(isc_mem_t *mctx, in_port_t port, isc_dscp_t dscp,
		    dns_acl_t *acl, bool tls,
		    const ns_listen_tls_params_t *tls_params,
		    ns_listenelt_t **		  target);
/*%<
 * Create a listen-on list element.
 *
 * Requires:
 * \li	'targetp' is a valid pointer to a pointer containing 'NULL';
 * \li	'tls_params' is a valid, non-'NULL' pointer if 'tls' equals 'true'.
 */

isc_result_t
ns_listenelt_create_http(isc_mem_t *mctx, in_port_t http_port, isc_dscp_t dscp,
			 dns_acl_t *acl, bool tls,
			 const ns_listen_tls_params_t *tls_params,
			 char **endpoints, size_t nendpoints,
			 isc_quota_t *quota, const uint32_t max_streams,
			 ns_listenelt_t **target);
/*%<
 * Create a listen-on list element for HTTP(S).
 */

void
ns_listenelt_destroy(ns_listenelt_t *elt);
/*%<
 * Destroy a listen-on list element.
 */

isc_result_t
ns_listenlist_create(isc_mem_t *mctx, ns_listenlist_t **target);
/*%<
 * Create a new, empty listen-on list.
 */

void
ns_listenlist_attach(ns_listenlist_t *source, ns_listenlist_t **target);
/*%<
 * Attach '*target' to '*source'.
 */

void
ns_listenlist_detach(ns_listenlist_t **listp);
/*%<
 * Detach 'listp'.
 */

isc_result_t
ns_listenlist_default(isc_mem_t *mctx, in_port_t port, isc_dscp_t dscp,
		      bool enabled, ns_listenlist_t **target);
/*%<
 * Create a listen-on list with default contents, matching
 * all addresses with port 'port' (if 'enabled' is true),
 * or no addresses (if 'enabled' is false).
 */

#endif /* NS_LISTENLIST_H */
