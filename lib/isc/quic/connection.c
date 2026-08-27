/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <stdint.h>

#include <ngtcp2/ngtcp2.h>

#include <isc/attributes.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/util.h>

#include "quic_p.h" /* IWYU pragma: keep */

#define VALID_CONNECTION(c) ISC_MAGIC_VALID(c, conn_magic)

constexpr uint32_t conn_magic = ISC_MAGIC('Q', 'U', 'I', 'c');

static void
destroy(isc_quic_conn_t *conn) {
	isc_mem_t *mctx = conn->mem.user_data;

	isc_quic_router_unref(conn->router);

	isc_mem_put(mctx, conn, sizeof(*conn));
	isc_mem_unref(mctx);
}

ISC_REFCOUNT_IMPL(isc_quic_conn, destroy);

isc_result_t
isc_quic_conn_client_create(
	isc_mem_t *mctx, isc_quic_router_t *router,
	const isc_quic_conn_callbacks_t *callbacks, void *callback_arg,
	const isc_quic_conn_options_t *options ISC_ATTR_UNUSED,
	const char *sni ISC_ATTR_UNUSED,
	const isc_sockaddr_t *local ISC_ATTR_UNUSED,
	const isc_sockaddr_t *peer ISC_ATTR_UNUSED, isc_quic_conn_t **connp) {
	isc_quic_conn_t *conn;

	REQUIRE(connp != NULL && *connp == NULL);

	conn = isc_mem_get(mctx, sizeof(*conn));
	*conn = (isc_quic_conn_t){
		.magic = conn_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.router = isc_quic_router_ref(router),
		.cb = callbacks,
		.cbarg = callback_arg,
		.mem = { .user_data = isc_mem_ref(mctx) },
	};

	*connp = conn;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_conn_server_create(
	isc_mem_t *mctx, isc_quic_router_t *router,
	const isc_quic_conn_callbacks_t *callbacks, void *callback_arg,
	const isc_quic_conn_options_t *options ISC_ATTR_UNUSED,
	isc_constregion_t initial_dcid ISC_ATTR_UNUSED,
	isc_constregion_t initial_scid ISC_ATTR_UNUSED,
	const isc_sockaddr_t *local ISC_ATTR_UNUSED,
	const isc_sockaddr_t *peer ISC_ATTR_UNUSED, isc_quic_conn_t **connp) {
	isc_quic_conn_t *conn;

	REQUIRE(connp != NULL && *connp == NULL);

	conn = isc_mem_get(mctx, sizeof(*conn));
	*conn = (isc_quic_conn_t){
		.magic = conn_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.router = isc_quic_router_ref(router),
		.cb = callbacks,
		.cbarg = callback_arg,
		.mem = { .user_data = isc_mem_ref(mctx) },
	};

	*connp = conn;

	return ISC_R_SUCCESS;
}
