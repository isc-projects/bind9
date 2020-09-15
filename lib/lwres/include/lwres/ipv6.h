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

#ifndef LWRES_IPV6_H
#define LWRES_IPV6_H 1

/*****
 ***** Module Info
 *****/

/*! \file lwres/ipv6.h
 * IPv6 definitions for systems which do not support IPv6.
 */

/***
 *** Imports.
 ***/

#include <inttypes.h>

#include <lwres/platform.h>

/***
 *** Types.
 ***/

/*% in6_addr structure */
struct in6_addr {
	union {
		uint8_t	_S6_u8[16];
		uint16_t	_S6_u16[8];
		uint32_t	_S6_u32[4];
	} _S6_un;
};
/*@{*/
/*% IP v6 types */
#define s6_addr		_S6_un._S6_u8
#define s6_addr8	_S6_un._S6_u8
#define s6_addr16	_S6_un._S6_u16
#define s6_addr32	_S6_un._S6_u32
/*@}*/

#define IN6ADDR_ANY_INIT 	{{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }}}
#define IN6ADDR_LOOPBACK_INIT 	{{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }}}

LIBLWRES_EXTERNAL_DATA extern const struct in6_addr in6addr_any;
LIBLWRES_EXTERNAL_DATA extern const struct in6_addr in6addr_loopback;

/*% used in getaddrinfo.c and getnameinfo.c */
struct sockaddr_in6 {
#ifdef LWRES_PLATFORM_HAVESALEN
	uint8_t		sin6_len;
	uint8_t		sin6_family;
#else
	uint16_t		sin6_family;
#endif
	uint16_t		sin6_port;
	uint32_t		sin6_flowinfo;
	struct in6_addr		sin6_addr;
	uint32_t		sin6_scope_id;
};

#ifdef LWRES_PLATFORM_HAVESALEN
#define SIN6_LEN 1
#endif

/*% in6_pktinfo structure */
struct in6_pktinfo {
	struct in6_addr ipi6_addr;    /*%< src/dst IPv6 address */
	unsigned int    ipi6_ifindex; /*%< send/recv interface index */
};

/*!
 * Unspecified IPv6 address
 */
#define IN6_IS_ADDR_UNSPECIFIED(a)      \
	(((a)->s6_addr32[0] == 0) &&    \
	 ((a)->s6_addr32[1] == 0) &&    \
	 ((a)->s6_addr32[2] == 0) &&    \
	 ((a)->s6_addr32[3] == 0))

/*
 * Loopback
 */
#define IN6_IS_ADDR_LOOPBACK(a)         \
	(((a)->s6_addr32[0] == 0) &&    \
	 ((a)->s6_addr32[1] == 0) &&    \
	 ((a)->s6_addr32[2] == 0) &&    \
	 ((a)->s6_addr32[3] == htonl(1)))

/*
 * IPv4 compatible
 */
#define IN6_IS_ADDR_V4COMPAT(a)         \
	(((a)->s6_addr32[0] == 0) &&    \
	 ((a)->s6_addr32[1] == 0) &&    \
	 ((a)->s6_addr32[2] == 0) &&    \
	 ((a)->s6_addr32[3] != 0) &&    \
	 ((a)->s6_addr32[3] != htonl(1)))

/*
 * Mapped
 */
#define IN6_IS_ADDR_V4MAPPED(a)               \
	(((a)->s6_addr32[0] == 0) &&          \
	 ((a)->s6_addr32[1] == 0) &&          \
	 ((a)->s6_addr32[2] == htonl(0x0000ffff)))

#endif /* LWRES_IPV6_H */
