/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: ipv6.h,v 1.10 2002/08/01 03:56:08 mayer Exp $ */

#ifndef ISC_IPV6_H
#define ISC_IPV6_H 1

/*****
 ***** Module Info
 *****/

/*
 * IPv6 definitions for systems which do not support IPv6.
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
 *	RFC 2553.
 */

#define s6_addr8	s6_addr
#define in6_addr in_addr6

#define IN6ADDR_ANY_INIT 	{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }}
#define IN6ADDR_LOOPBACK_INIT 	{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }}

LIBISC_EXTERNAL_DATA extern const struct in_addr6 in6addr_any;
LIBISC_EXTERNAL_DATA extern const struct in_addr6 in6addr_loopback;

/*
 * Unspecified
 */

#define IN6_IS_ADDR_UNSPECIFIED(a)      \
*((u_long *)((a)->s6_addr)    ) == 0 && \
*((u_long *)((a)->s6_addr) + 1) == 0 && \
*((u_long *)((a)->s6_addr) + 2) == 0 && \
*((u_long *)((a)->s6_addr) + 3) == 0 \
)

/*
 * Loopback
 */
#define IN6_IS_ADDR_LOOPBACK(a) (\
*((u_long *)((a)->s6_addr)    ) == 0 && \
*((u_long *)((a)->s6_addr) + 1) == 0 && \
*((u_long *)((a)->s6_addr) + 2) == 0 && \
*((u_long *)((a)->s6_addr) + 3) == htonl(1) \
)

/*
 * IPv4 compatible
 */
#define IN6_IS_ADDR_V4COMPAT(a)  (\
*((u_long *)((a)->s6_addr)    ) == 0 && \
*((u_long *)((a)->s6_addr) + 1) == 0 && \
*((u_long *)((a)->s6_addr) + 2) == 0 && \
*((u_long *)((a)->s6_addr) + 3) != 0 && \
*((u_long *)((a)->s6_addr) + 3) != htonl(1) \
)

/*
 * Mapped
 */
#define IN6_IS_ADDR_V4MAPPED(a) (\
*((u_long *)((a)->s6_addr)    ) == 0 && \
*((u_long *)((a)->s6_addr) + 1) == 0 && \
*((u_long *)((a)->s6_addr) + 2) == htonl(0x0000ffff))

/*
 * Multicast
 */
#define IN6_IS_ADDR_MULTICAST(a)	\
	((a)->s6_addr8[0] == 0xffU)

/*
 * Unicast link / site local.
 */
#define IN6_IS_ADDR_LINKLOCAL(a)	(\
(*((u_long *)((a)->s6_addr)    ) == 0xfe) && \
((*((u_long *)((a)->s6_addr) + 1) & 0xc0) == 0x80))
#define IN6_IS_ADDR_SITELOCAL(a)	(\
(*((u_long *)((a)->s6_addr)    ) == 0xfe) && \
((*((u_long *)((a)->s6_addr) + 1) & 0xc0) == 0xc0))

#endif /* ISC_IPV6_H */
