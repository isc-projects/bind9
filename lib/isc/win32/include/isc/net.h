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
 *		struct sockaddr
 *		struct sockaddr_in
 *		struct sockaddr_in6
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
 *** Defines.
 ***/

/*
 * If this system has the IPv6 structure definitions, ISC_NET_HAVEIPV6
 * will be defined.
 */
#undef ISC_NET_HAVEIPV6

/*
 * If this system needs inet_ntop(), ISC_NET_NEEDNTOP will be defined.
 */
#define ISC_NET_NEEDNTOP 1

/*
 * If this system needs inet_pton(), ISC_NET_NEEDPTON will be defined.
 */
#define ISC_NET_NEEDPTON 1

/*
 * If this system needs inet_aton(), ISC_NET_NEEDATON will be defined.
 */
#define ISC_NET_NEEDATON 1

/*
 * If this system needs in_port_t, ISC_NET_NEEDPORTT will be defined.
 */
#define ISC_NET_NEEDPORTT 1

/***
 *** Imports.
 ***/

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400	/* Ensures windows.h includes winsock2.h. */
#endif

/*
 * Because of some sort of problem in the MS header files, this cannot
 * be simple "#include <winsock2.h>", because winsock2.h tries to include
 * windows.h, which then generates an error out of mswsock.h.  _You_
 * figure it out.
 */
#include <windows.h>

#include <sys/types.h>

#include <isc/lang.h>
#include <isc/result.h>

#ifndef AF_INET6
#define AF_INET6 99
#endif

#ifndef PF_INET6
#define PF_INET6 AF_INET6
#endif

#ifndef ISC_NET_HAVEIPV6
#include <isc/ipv6.h>
#endif

/*
 * Ensure type in_port_t is defined.
 */
#ifdef ISC_NET_NEEDPORTT
#include <isc/int.h>

typedef isc_uint16_t in_port_t;
#endif

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

#ifdef ISC_NET_NEEDNTOP
const char *isc_net_ntop(int af, const void *src, char *dst, size_t size);
#define inet_ntop isc_net_ntop
#endif

#ifdef ISC_NET_NEEDPTON
int isc_net_pton(int af, const char *src, void *dst);
#define inet_pton isc_net_pton
#endif

#ifdef ISC_NET_NEEDATON
int isc_net_aton(const char *cp, struct in_addr *addr);
#define inet_aton isc_net_aton
#endif

ISC_LANG_ENDDECLS

#endif /* ISC_NET_H */
