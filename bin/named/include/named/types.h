/*
 * Copyright (C) 1999-2001, 2004-2009, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: types.h,v 1.31 2009/01/09 23:47:45 tbox Exp $ */

#ifndef NAMED_TYPES_H
#define NAMED_TYPES_H 1

/*! \file */

#include <dns/types.h>

typedef struct ns_cache			ns_cache_t;
typedef ISC_LIST(ns_cache_t)		ns_cachelist_t;
typedef struct ns_client		ns_client_t;
typedef struct ns_clientmgr		ns_clientmgr_t;
typedef struct ns_query			ns_query_t;
typedef struct ns_server 		ns_server_t;
typedef struct ns_xmld			ns_xmld_t;
typedef struct ns_xmldmgr		ns_xmldmgr_t;
typedef struct ns_interface 		ns_interface_t;
typedef struct ns_interfacemgr		ns_interfacemgr_t;
typedef struct ns_lwresd		ns_lwresd_t;
typedef struct ns_lwreslistener		ns_lwreslistener_t;
typedef struct ns_lwdclient		ns_lwdclient_t;
typedef struct ns_lwdclientmgr		ns_lwdclientmgr_t;
typedef struct ns_lwsearchlist		ns_lwsearchlist_t;
typedef struct ns_lwsearchctx		ns_lwsearchctx_t;
typedef struct ns_controls		ns_controls_t;
typedef struct ns_dispatch		ns_dispatch_t;
typedef ISC_LIST(ns_dispatch_t)		ns_dispatchlist_t;
typedef struct ns_statschannel		ns_statschannel_t;
typedef ISC_LIST(ns_statschannel_t)	ns_statschannellist_t;

typedef enum {
	ns_cookiealg_aes,
	ns_cookiealg_sha1,
	ns_cookiealg_sha256
} ns_cookiealg_t;

#endif /* NAMED_TYPES_H */
