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

/* $Id: lwresd.h,v 1.6 2000/09/07 21:54:40 explorer Exp $ */

#ifndef NAMED_LWRESD_H
#define NAMED_LWRESD_H 1

#include <isc/types.h>
#include <isc/sockaddr.h>

#include <dns/types.h>

struct ns_lwresd {
	isc_uint32_t magic;

	isc_mutex_t lock;
	ISC_LIST(ns_lwdclientmgr_t) cmgrs;
	isc_socket_t *sock;
	dns_view_t *view;
	isc_mem_t *mctx;
	dns_dispatchmgr_t *dispmgr;
	isc_boolean_t shutting_down;
};

void
ns_lwresd_create(isc_mem_t *mctx, dns_view_t *view, ns_lwresd_t **lwresdp);

/*
 * Trigger shutdown.
 */
void
ns_lwresd_shutdown(ns_lwresd_t **lwresdp);

/*
 * INTERNAL FUNCTIONS.
 */
void
lwresd_destroy(ns_lwresd_t *lwresdp);

void *
ns_lwresd_memalloc(void *arg, size_t size);

void
ns_lwresd_memfree(void *arg, void *mem, size_t size);

#endif /* NAMED_LWRESD_H */
