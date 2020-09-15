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

/*! \file */

#include <config.h>

#include <string.h>

#include <isc/result.h>
#include <isc/netaddr.h>
#include <isc/sockaddr.h>

#include <lwres/lwres.h>

#include <named/lwaddr.h>

/*%
 * Convert addresses from lwres to isc format.
 */
isc_result_t
lwaddr_netaddr_fromlwresaddr(isc_netaddr_t *na, lwres_addr_t *la) {
	if (la->family != LWRES_ADDRTYPE_V4 && la->family != LWRES_ADDRTYPE_V6)
		return (ISC_R_FAMILYNOSUPPORT);

	if (la->family == LWRES_ADDRTYPE_V4) {
		struct in_addr ina;
		memmove(&ina.s_addr, la->address, 4);
		isc_netaddr_fromin(na, &ina);
	} else {
		struct in6_addr ina6;
		memmove(&ina6.s6_addr, la->address, 16);
		isc_netaddr_fromin6(na, &ina6);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
lwaddr_sockaddr_fromlwresaddr(isc_sockaddr_t *sa, lwres_addr_t *la,
			      in_port_t port)
{
	isc_netaddr_t na;
	isc_result_t result;

	result = lwaddr_netaddr_fromlwresaddr(&na, la);
	if (result != ISC_R_SUCCESS)
		return (result);
	isc_sockaddr_fromnetaddr(sa, &na, port);
	return (ISC_R_SUCCESS);
}

/*%
 * Convert addresses from isc to lwres format.
 */

isc_result_t
lwaddr_lwresaddr_fromnetaddr(lwres_addr_t *la, isc_netaddr_t *na) {
	if (na->family != AF_INET && na->family != AF_INET6)
		return (ISC_R_FAMILYNOSUPPORT);

	if (na->family == AF_INET) {
		la->family = LWRES_ADDRTYPE_V4;
		la->length = 4;
		memmove(la->address, &na->type.in, 4);
	} else {
		la->family = LWRES_ADDRTYPE_V6;
		la->length = 16;
		memmove(la->address, &na->type.in6, 16);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
lwaddr_lwresaddr_fromsockaddr(lwres_addr_t *la, isc_sockaddr_t *sa) {
	isc_netaddr_t na;
	isc_netaddr_fromsockaddr(&na, sa);
	return (lwaddr_lwresaddr_fromnetaddr(la, &na));
}
