/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: net.h,v 1.24.4.1 2001/01/03 20:37:58 gson Exp $ */

#ifndef ISC_NET_H
#define ISC_NET_H 1

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
 *		struct in6_pktinfo
 *		struct sockaddr
 *		struct sockaddr_in
 *		struct sockaddr_in6
 *		in_port_t
 *
 * It ensures that the AF_ and PF_ macros are defined.
 *
 * It declares ntoh[sl]() and hton[sl]().
 *
 * It declares inet_aton(), inet_ntop(), and inet_pton().
 *
 * It ensures that INADDR_ANY, IN6ADDR_ANY_INIT, in6addr_any, and
 * in6addr_loopback are available.
 *
 * It ensures that IN_MULTICAST() is available to check for multicast
 * addresses.
 *
 * MP:
 *	No impact.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	N/A.
 *
 * Security:
 *	No anticipated impact.
 *
 * Standards:
 *	BSD Socket API
 *	RFC 2553
 */

/***
 *** Imports.
 ***/
#include <isc/platform.h>

#include <sys/types.h>
#include <sys/socket.h>		/* Contractual promise. */

#include <netinet/in.h>		/* Contractual promise. */
#include <arpa/inet.h>		/* Contractual promise. */
#ifdef ISC_PLATFORM_NEEDNETINETIN6H
#include <netinet/in6.h>	/* Required on UnixWare. */
#endif
#ifdef ISC_PLATFORM_NEEDNETINET6IN6H
#include <netinet6/in6.h>	/* Required on BSD/OS for in6_pktinfo. */
#endif

#include <isc/lang.h>
#include <isc/types.h>

#ifndef AF_INET6
#define AF_INET6 99
#endif

#ifndef PF_INET6
#define PF_INET6 AF_INET6
#endif

#ifndef ISC_PLATFORM_HAVEIPV6
#include <isc/ipv6.h>		/* Contractual promise. */
#endif

#ifndef ISC_PLATFORM_HAVEIN6PKTINFO
struct in6_pktinfo {
	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
	unsigned int    ipi6_ifindex; /* send/recv interface index */
};
#endif

/*
 * Cope with a missing in6addr_any.
 */
#if defined(ISC_PLATFORM_HAVEIPV6) && defined(ISC_PLATFORM_NEEDIN6ADDRANY)
extern const struct in6_addr isc_net_in6addrany;
#define in6addr_any isc_net_in6addrany
#endif

/*
 * Fix UnixWare 7.1.1's broken IN6_IS_ADDR_* definitions.
 */
#ifdef ISC_PLATFORM_FIXIN6ISADDR
#undef  IN6_IS_ADDR_GEOGRAPHIC
#define IN6_IS_ADDR_GEOGRAPHIC(a) (((a)->S6_un.S6_l[0] & 0xE0) == 0x80)
#undef  IN6_IS_ADDR_IPX
#define IN6_IS_ADDR_IPX(a)        (((a)->S6_un.S6_l[0] & 0xFE) == 0x04)
#undef  IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a)  (((a)->S6_un.S6_l[0] & 0xC0FF) == 0x80FE)
#undef  IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a)  (((a)->S6_un.S6_l[0] & 0xFF) == 0xFF)
#undef  IN6_IS_ADDR_NSAP
#define IN6_IS_ADDR_NSAP(a)       (((a)->S6_un.S6_l[0] & 0xFE) == 0x02)
#undef  IN6_IS_ADDR_PROVIDER
#define IN6_IS_ADDR_PROVIDER(a)   (((a)->S6_un.S6_l[0] & 0xE0) == 0x40)
#undef  IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a)  (((a)->S6_un.S6_l[0] & 0xC0FF) == 0xC0FE)
#endif /* ISC_PLATFORM_FIXIN6ISADDR */

/*
 * Ensure type in_port_t is defined.
 */
#ifdef ISC_PLATFORM_NEEDPORTT
typedef isc_uint16_t in_port_t;
#endif

/*
 * If this system does not have MSG_TRUNC (as returned from recvmsg())
 * ISC_PLATFORM_RECVOVERFLOW will be defined.  This will enable the MSG_TRUNC
 * faking code in socket.c.
 */
#ifndef MSG_TRUNC
#define ISC_PLATFORM_RECVOVERFLOW
#endif

#define ISC__IPADDR(x)	((isc_uint32_t)htonl((isc_uint32_t)(x)))

#define ISC_IPADDR_ISMULTICAST(i) \
		(((isc_uint32_t)(i) & ISC__IPADDR(0xf0000000)) \
		 == ISC__IPADDR(0xe0000000))

/***
 *** Functions.
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
isc_net_probeipv4(void);
/*
 * Check if the system's kernel supports IPv4.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS		IPv4 is supported.
 *	ISC_R_NOTFOUND		IPv4 is not supported.
 *	ISC_R_UNEXPECTED
 */

isc_result_t
isc_net_probeipv6(void);
/*
 * Check if the system's kernel supports IPv6.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS		IPv6 is supported.
 *	ISC_R_NOTFOUND		IPv6 is not supported.
 *	ISC_R_UNEXPECTED
 */

#ifdef ISC_PLATFORM_NEEDNTOP
const char *
isc_net_ntop(int af, const void *src, char *dst, size_t size);
#define inet_ntop isc_net_ntop
#endif

#ifdef ISC_PLATFORM_NEEDPTON
int
isc_net_pton(int af, const char *src, void *dst);
#define inet_pton isc_net_pton
#endif

#ifdef ISC_PLATFORM_NEEDATON
int
isc_net_aton(const char *cp, struct in_addr *addr);
#define inet_aton isc_net_aton
#endif

ISC_LANG_ENDDECLS

#endif /* ISC_NET_H */
