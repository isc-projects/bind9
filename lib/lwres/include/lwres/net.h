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

/* $Id: net.h,v 1.8 2000/08/01 01:32:42 tale Exp $ */

#ifndef LWRES_NET_H
#define LWRES_NET_H 1

/*****
 ***** Module Info
 *****/

/*
 * Basic Networking Types
 *
 * This module is responsible for defining the following basic networking
 * types:
 *
 *		struct in_addr
 *		struct in6_addr
 *		struct sockaddr
 *		struct sockaddr_in
 *		struct sockaddr_in6
 *
 * It ensures that the AF_ and PF_ macros are defined.
 *
 * It declares ntoh[sl]() and hton[sl]().
 *
 * It declares lwres_net_aton(), lwres_net_ntop(), and lwres_net_pton().
 *
 * It ensures that INADDR_ANY and IN6ADDR_ANY_INIT are defined.
 */

/***
 *** Imports.
 ***/

#include <lwres/platform.h>	/* Required for LWRES_PLATFORM_*. */

#include <sys/types.h>
#include <sys/socket.h>		/* Contractual promise. */

#include <netinet/in.h>		/* Contractual promise. */
#include <arpa/inet.h>		/* Contractual promise. */
#ifdef LWRES_PLATFORM_NEEDNETINETIN6H
#include <netinet/in6.h>	/* Required on UnixWare. */
#endif
#ifdef LWRES_PLATFORM_NEEDNETINET6IN6H
#include <netinet6/in6.h>	/* Required on BSD/OS for in6_pktinfo. */
#endif

#include <lwres/lang.h>

#ifndef AF_INET6
#define AF_INET6 99
#endif

#ifndef PF_INET6
#define PF_INET6 AF_INET6
#endif

#ifndef LWRES_PLATFORM_HAVEIPV6
#include <lwres/ipv6.h>		/* Contractual promise. */
#endif

LWRES_LANG_BEGINDECLS

const char *
lwres_net_ntop(int af, const void *src, char *dst, size_t size);

int
lwres_net_pton(int af, const char *src, void *dst);

int
lwres_net_aton(const char *cp, struct in_addr *addr);

LWRES_LANG_ENDDECLS

#endif /* LWRES_NET_H */
