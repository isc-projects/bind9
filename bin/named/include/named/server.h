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

#ifndef NS_SERVER_H
#define NS_SERVER_H 1

#include <isc/types.h>
#include <isc/log.h>

#include <dns/types.h>

/*
 * Name server state.  Better here than in lots of separate global variables.
 */
struct ns_server {
	isc_uint32_t		magic;
	isc_mem_t *		mctx;

	/* Configurable data. */
	isc_boolean_t		recursion;
	isc_boolean_t		auth_nxdomain;
	dns_transfer_format_t	transfer_format;
	dns_acl_t *		queryacl;
	dns_acl_t *		recursionacl;
	dns_acl_t *		transferacl;

	/* Server data structures. */
	dns_viewlist_t		viewlist;
	isc_rwlock_t		viewlock;
	ns_interfacemgr_t *	interfacemgr;
};

#define NS_SERVER_MAGIC			0x53564552	/* SVER */
#define NS_SERVER_VALID(s)		((s) != NULL && \
					 (s)->magic == NS_SERVER_MAGIC)

isc_result_t
ns_server_create(isc_mem_t *mctx, ns_server_t **serverp);
/*
 * Create a server object with default settings.
 */

void
ns_server_destroy(ns_server_t **serverp);
/*
 * Destroy a server object, freeing its memory.
 */
     
isc_result_t ns_server_init(void);
/*
 * Create the singleton names server object of BIND 9.
 */

void
ns_server_fatal(isc_logmodule_t *module, isc_boolean_t want_core,
		const char *format, ...);

#endif /* NS_SERVER_H */
