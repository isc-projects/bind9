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

#include <lwres/lwres.h>
#include <lwres/net.h>

isc_result_t
lwaddr_netaddr_fromlwresaddr(isc_netaddr_t *na, lwres_addr_t *la);

isc_result_t
lwaddr_sockaddr_fromlwresaddr(isc_sockaddr_t *sa, lwres_addr_t *la,
			      in_port_t port);

isc_result_t
lwaddr_lwresaddr_fromnetaddr(lwres_addr_t *la, isc_netaddr_t *na);

isc_result_t
lwaddr_lwresaddr_fromsockaddr(lwres_addr_t *la, isc_sockaddr_t *sa);
