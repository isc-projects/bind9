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

#ifndef LWRES_PLATFORM_H
#define LWRES_PLATFORM_H 1

/*****
 ***** Platform-dependent defines.
 *****/

/***
 *** Network.
 ***/

/*
 * Define if this system needs the <netinet/in6.h> header file for IPv6.
 */
/*@LWRES_PLATFORM_NEEDNETINETIN6H@ */

/*
 * Define if this system needs the <netinet6/in6.h> header file for IPv6.
 */
/*@LWRES_PLATFORM_NEEDNETINET6IN6H@ */

/*
 * If sockaddrs on this system have an sa_len field, LWRES_PLATFORM_HAVESALEN
 * will be defined.
 */
/*@LWRES_PLATFORM_HAVESALEN@ */

/*
 * If this system has the IPv6 structure definitions, LWRES_PLATFORM_HAVEIPV6
 * will be defined.
 */
/*@LWRES_PLATFORM_HAVEIPV6@ */

/*
 * If this system is missing in6addr_any, LWRES_PLATFORM_NEEDIN6ADDRANY will
 * be defined.
 */
#define LWRES_PLATFORM_NEEDIN6ADDRANY

/*
 * If this system has in_addr6, rather than in6_addr,
 * LWRES_PLATFORM_HAVEINADDR6 will be defined.
 */
/*@LWRES_PLATFORM_HAVEINADDR6@ */

/*
 * Defined if unistd.h does not cause fd_set to be declared.
 */
/*@LWRES_PLATFORM_NEEDSYSSELECTH@ */

/* VS2005 does not provide strlcpy() */
#define LWRES_PLATFORM_NEEDSTRLCPY

/*
 * Define some Macros
 */
#ifdef LIBLWRES_EXPORTS
#define LIBLWRES_EXTERNAL_DATA __declspec(dllexport)
#else
#define LIBLWRES_EXTERNAL_DATA __declspec(dllimport)
#endif

/*
 * Define the MAKE_NONBLOCKING Macro here since it can get used in
 * a number of places.
 */
#define MAKE_NONBLOCKING(sd, retval) \
do { \
	int _on = 1; \
	retval = ioctlsocket((SOCKET) sd, FIONBIO, &_on); \
} while (0)

/*
 * Need to define close here since lwres closes sockets and not files
 */
#undef  close
#define close closesocket

/*
 * Internal to liblwres.
 */
void InitSockets(void);

void DestroySockets(void);

#endif /* LWRES_PLATFORM_H */
