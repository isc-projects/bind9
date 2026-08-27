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

#include <inttypes.h>
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h> /* IWYU pragma: keep */
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/urcu.h>

#include <tests/isc.h>

typedef struct endpoint endpoint_t;
typedef struct conn_state conn_state_t;
typedef struct stream_state stream_state_t;

struct stream_state {
	int64_t id;
	uint32_t cursor;
	ISC_LINK(stream_state_t) link;
};

struct conn_state {
	isc_quic_conn_t *conn;
	ISC_LIST(stream_state_t) stream;
};

struct endpoint {
	uint32_t len;
	_Atomic(uint32_t) handshakes;
	_Atomic(uint32_t) timedout;
	_Atomic(uint32_t) dead;
	uint32_t total_read;
	isc_quic_router_t *router;
	isc_quic_conn_options_t opts;
	conn_state_t state[] ISC_ATTR_COUNTED_BY(len);
};

constexpr isc_tid_t connection_tid = 3;

constexpr uint8_t client_dcid[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

constexpr uint8_t unknown_cid[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
};

/* Adapted from https://quic.xargs.org/ */
constexpr uint8_t initial_frame_v1[1200] = {
	/*
	 * Long Header Packet Byte (RFC9000, Section 17.2):
	 * 11000000
	 * ││├┘├┘├┘
	 * │││ │ └── Packet number field length (1-byte)
	 * │││ └──── Reserved Bits (RFC9000, Section 17.2.2)
	 * ││└────── Long Packet Type (RFC9000, Section 17.2, Table 5)
	 * │└─────── Fixed Bit
	 * └──────── Header Form
	 */
	0xc0,
	/* QUIC version v1 */
	0x00, 0x00, 0x00, 0x01,
	/* 8-bytes of DCID to follow */
	0x08,
	/* DCID */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* 5-bytes of SCID to follow */
	0x05,
	/* SCID */
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
	/* 0-bytes of token to follow */
	0x00,
	/* 259-bytes of packet to follow */
	0x41, 0x03,
	/* Packet number */
	0x00
	/* The rest is zero-padded packet information that won't be inspected */
};

constexpr uint8_t initial_frame_reserved_version[1200] = {
	/*
	 * Long Header Packet Byte (RFC9000, Section 17.2):
	 * 11000000
	 * ││├┘├┘├┘
	 * │││ │ └── Packet number field length (1-byte)
	 * │││ └──── Reserved Bits (RFC9000, Section 17.2.2)
	 * ││└────── Long Packet Type (RFC9000, Section 17.2, Table 5)
	 * │└─────── Fixed Bit
	 * └──────── Header Form
	 */
	0xC0,
	/* QUIC reserved version */
	0x0A, 0x0A, 0x0A, 0x0A,
	/* 8-bytes of DCID to follow */
	0x08,
	/* DCID */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* 5-bytes of SCID to follow */
	0x05,
	/* SCID */
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
	/* 0-bytes of token to follow */
	0x00,
	/* 259-bytes of packet to follow */
	0x41, 0x03,
	/* Packet number */
	0x00
	/* The rest is zero-padded packet information that won't be inspected */
};

/*
 * A 1-RTT packet for the connection identified by client_dcid. Its last 16
 * bytes deliberately differ from stateless_reset_token.
 */
constexpr uint8_t short_header_v1[] = {
	/*
	 * Short Header Packet Byte (RFC9000, Section 17.3.1):
	 * 01000000
	 * │││├┘│├┘
	 * ││││ │└── Packet Number Length (1-byte)
	 * ││││ └─── Key Phase
	 * │││└───── Reserved Bits
	 * ││└────── Spin Bit
	 * │└─────── Fixed Bit
	 * └──────── Header Form
	 */
	0x40,
	/* DCID (always router->cidlen bytes in a Short header) */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* Packet number */
	0x00,
	/* Protected payload including the AEAD tag; never inspected */
	0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
	0xAC, 0xAD, 0xAE, 0xAF
};

constexpr uint8_t stateless_reset_token[ISC_QUIC_STATELESS_TOKEN_LENGTH] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

constexpr uint8_t stateless_reset_packet[] = {
	0x40, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint8_t alpn[] = { 0x03, 'O', 'w', 'O' };

static const uint8_t messages[][3] = {
	{ 'H', 'i', '!' },
	{ 'U', 'w', 'U' },
	{ 'O', 'w', 'O' },
	{ 'B', 'y', 'e' },
};

static isc_sockaddr_t client_addr[32];
static isc_sockaddr_t server_addr;

static void
handshake_completed_cb(void *cbarg);

static isc_result_t
stream_opened_cb(isc_quic_conn_t *conn, void *cbarg, void **stream_data,
		 int64_t stream_id);

static isc_result_t
stream_closed_cb(isc_quic_conn_t *conn, void *cbarg, int64_t stream_id,
		 void *stream_data, isc_quic_application_error_kind_t kind,
		 uint64_t rx_application_error_code,
		 uint64_t tx_application_error_code);

static isc_result_t
data_read_cb(isc_quic_conn_t *conn, void *cbarg,
	     isc_quic_stream_data_info_t info, isc_constregion_t data);

static const isc_quic_conn_callbacks_t callbacks = {
	.handshake_completed = handshake_completed_cb,
	.stream_opened = stream_opened_cb,
	.stream_closed = stream_closed_cb,
	.data_read = data_read_cb,
};

static int
global_setup(void **state ISC_ATTR_UNUSED) {
	size_t i;

	isc_sockaddr_fromin6(&server_addr, &in6addr_loopback, 9000);

	for (i = 0; i < ARRAY_SIZE(client_addr); i++) {
		isc_sockaddr_fromin6(&client_addr[i], &in6addr_loopback,
				     9100 + i);
	}

	return 0;
}

static int
global_teardown(void **state ISC_ATTR_UNUSED) {
	rcu_barrier();
	return 0;
}

static void
endpoint_create(bool is_server, size_t len, endpoint_t **ep) {
	isc_quic_router_t *router = NULL;
	isc_tlsctx_t *tlsctx = NULL;
	isc_result_t result;
	endpoint_t *e;

	isc_quic_router_create(isc_g_mctx, ISC_QUIC_CID_MAX_LENGTH, &router);
	assert_non_null(router);

	if (is_server) {
		result = isc_tlsctx_createserver(NULL, NULL, &tlsctx);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_tlsctx_set_random_session_id_context(tlsctx);

		result = isc_quic_tlsctx_server_configure(tlsctx);
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		result = isc_tlsctx_createclient(&tlsctx);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_tlsctx_set_random_session_id_context(tlsctx);

		result = isc_quic_tlsctx_client_configure(tlsctx);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	e = isc_mem_get(isc_g_mctx, STRUCT_FLEX_SIZE(e, state, len));
	*e = (endpoint_t){
		.len = len,
		.router = router,
		.opts = { .tlsctx = tlsctx,
			  .alpn = { .base = alpn, .length = sizeof(alpn) },
			  .idle_timeout = 900000000,
			  .handshake_timeout = 900000000,
		},
	};
	memset(e->state, 0, sizeof(*e->state) * len);

	*ep = e;
}

static void
endpoint_destroy(endpoint_t **ep) {
	endpoint_t *e = MOVE_OWNERSHIP(*ep);
	size_t i;

	isc_tlsctx_free(&e->opts.tlsctx);

	for (i = 0; i < e->len; i++) {
		ISC_LIST_FOREACH(e->state[i].stream, s, link) {
			isc_mem_put(isc_g_mctx, s, sizeof(*s));
		}

		if (e->state[i].conn == NULL) {
			continue;
		}

		isc_quic_conn_shutdown(e->state[i].conn);
		isc_quic_conn_unref(e->state[i].conn);
	}

	isc_quic_router_unref(e->router);

	isc_mem_put(isc_g_mctx, e, STRUCT_FLEX_SIZE(e, state, e->len));
}

static void
handshake_completed_cb(void *cbarg) {
	endpoint_t *e = cbarg;
	atomic_fetch_add_relaxed(&e->handshakes, 1);
}

static isc_result_t
stream_opened_cb(isc_quic_conn_t *conn, void *cbarg, void **stream_data,
		 int64_t stream_id) {
	endpoint_t *e = cbarg;
	stream_state_t *s;
	size_t i;

	for (i = 0; i < e->len; i++) {
		if (e->state[i].conn == conn) {
			s = isc_mem_get(isc_g_mctx, sizeof(*s));
			*s = (stream_state_t){
				.id = stream_id,
				.link = ISC_LINK_INITIALIZER,
			};
			ISC_LIST_APPEND(e->state[i].stream, s, link);
			*stream_data = s;
			return ISC_R_SUCCESS;
		}
	}

	UNREACHABLE();
}

static isc_result_t
stream_closed_cb(isc_quic_conn_t *conn, void *cbarg, int64_t stream_id,
		 void *stream_data,
		 isc_quic_application_error_kind_t kind ISC_ATTR_UNUSED,
		 uint64_t rx_application_error_code ISC_ATTR_UNUSED,
		 uint64_t tx_application_error_code ISC_ATTR_UNUSED) {
	stream_state_t *s = stream_data;
	endpoint_t *e = cbarg;
	size_t i;

	for (i = 0; i < e->len; i++) {
		if (e->state[i].conn == conn) {
			assert_int_not_equal(i, e->len);
			assert_int_equal(s->id, stream_id);

			ISC_LIST_UNLINK(e->state[i].stream, s, link);
			isc_mem_put(isc_g_mctx, s, sizeof(*s));
			return ISC_R_SUCCESS;
		}
	}

	UNREACHABLE();
}

static isc_result_t
data_read_cb(isc_quic_conn_t *conn, void *cbarg,
	     isc_quic_stream_data_info_t info, isc_constregion_t data) {
	stream_state_t *s = info.stream_data;
	endpoint_t *e = cbarg;
	size_t i;

	assert_int_equal(s->id, info.stream_id);

	for (i = 0; i < e->len; i++) {
		if (e->state[i].conn == conn) {
			break;
		}
	}
	assert_int_not_equal(i, e->len);

	assert_memory_equal(data.base, messages[s->cursor], data.length);
	s->cursor = (s->cursor + 1) % ARRAY_SIZE(messages);
	return ISC_R_SUCCESS;
}

static void
try_exchange_packets(isc_quic_conn_t *conn1, isc_quic_conn_t *conn2) {
	uint8_t buf[1200];
	isc_region_t out = { .base = buf, .length = sizeof(buf) };
	isc_sockaddr_t addr1, addr2;
	isc_result_t result;
	size_t len;

	len = 0;
	result = isc_quic_conn_pull_packet(conn1, out, &len, &addr1, &addr2);
	if (result == ISC_R_SUCCESS) {
		isc_quic_conn_push_packet(
			conn2, (isc_constregion_t){ len, buf }, &addr2, &addr1);
	}

	len = 0;
	result = isc_quic_conn_pull_packet(conn2, out, &len, &addr2, &addr1);
	if (result == ISC_R_SUCCESS) {
		isc_quic_conn_push_packet(
			conn1, (isc_constregion_t){ len, buf }, &addr1, &addr2);
	}
}

ISC_RUN_TEST_IMPL(isc_quic_router_cid) {
	isc_quic_router_t *router = NULL;
	isc_quic_conn_t *conn, *found;
	isc_constregion_t cid;
	isc_result_t result;
	isc_tid_t tid = ISC_TID_UNKNOWN;

	isc_quic_conn_options_t opts = {
		.alpn = { sizeof(alpn), alpn },
	};

	isc_quic_router_create(isc_g_mctx, sizeof(client_dcid), &router);

	result = isc_tlsctx_createclient(&opts.tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	conn = NULL;
	result = isc_quic_conn_client_create(
		isc_g_mctx, router, NULL, NULL, &opts, ISC_QUIC_VERSION_V1,
		NULL, &client_addr[0], &server_addr, &conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	cid = (isc_constregion_t){ sizeof(client_dcid), client_dcid };
	result = isc_quic_router_add_cid(router, cid, connection_tid, conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	cid = (isc_constregion_t){ sizeof(client_dcid), client_dcid };
	result = isc_quic_router_add_cid(router, cid, connection_tid, conn);
	assert_int_equal(result, ISC_R_EXISTS);

	found = NULL;
	cid = (isc_constregion_t){ sizeof(client_dcid), client_dcid };
	result = isc_quic_router_get_cid(router, cid, &tid, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(found, conn);
	assert_int_equal(tid, connection_tid);
	isc_quic_conn_unref(found);

	found = NULL;
	cid = (isc_constregion_t){ sizeof(unknown_cid), unknown_cid };
	result = isc_quic_router_get_cid(router, cid, NULL, &found);
	assert_int_equal(result, ISC_R_NOTFOUND);

	cid = (isc_constregion_t){ sizeof(unknown_cid), unknown_cid };
	result = isc_quic_router_add_cid(router, cid, connection_tid, conn);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_quic_router_del_cid(router, cid);
	assert_int_equal(result, ISC_R_SUCCESS);

	cid = (isc_constregion_t){ sizeof(client_dcid), client_dcid };
	result = isc_quic_router_del_cid(router, cid);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_quic_router_del_cid(router, cid);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_quic_router_detach(&router);
	isc_quic_conn_detach(&conn);
}

ISC_RUN_TEST_IMPL(isc_quic_router_stateless_reset) {
	uint8_t token[ISC_QUIC_STATELESS_TOKEN_LENGTH];
	isc_quic_router_t *router = NULL;
	isc_quic_conn_t *conn, *found;
	isc_result_t result;
	isc_tid_t tid = ISC_TID_UNKNOWN;

	isc_quic_conn_options_t opts = {
		.alpn = { sizeof(alpn), alpn },
	};

	isc_quic_router_create(isc_g_mctx, sizeof(client_dcid), &router);

	result = isc_tlsctx_createclient(&opts.tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	conn = NULL;
	result = isc_quic_conn_client_create(
		isc_g_mctx, router, NULL, NULL, &opts, ISC_QUIC_VERSION_V1,
		NULL, &client_addr[0], &server_addr, &conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_random_buf(token, sizeof(token));

	found = NULL;
	result = isc_quic_router_get_stateless_reset(router, token, NULL,
						     &found);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_quic_router_add_stateless_reset(router, token,
						     connection_tid, conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_add_stateless_reset(router, token,
						     connection_tid, conn);
	assert_int_equal(result, ISC_R_EXISTS);

	found = NULL;
	result = isc_quic_router_get_stateless_reset(router, token, &tid,
						     &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(found, conn);
	assert_int_equal(tid, connection_tid);
	isc_quic_conn_unref(found);

	result = isc_quic_router_del_stateless_reset(router, token);
	assert_int_equal(result, ISC_R_SUCCESS);

	found = NULL;
	result = isc_quic_router_get_stateless_reset(router, token, NULL,
						     &found);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_quic_router_del_stateless_reset(router, token);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_quic_router_detach(&router);
	isc_quic_conn_detach(&conn);
}

ISC_RUN_TEST_IMPL(isc_quic_router_packet) {
	isc_quic_router_t *router = NULL;
	isc_quic_conn_t *conn, *found;
	isc_quic_version_t version;
	isc_constregion_t dcid, scid;
	isc_result_t result;
	isc_tid_t tid = ISC_TID_UNKNOWN;

	isc_quic_conn_options_t opts = {
		.alpn = { sizeof(alpn), alpn },
	};

	isc_quic_router_create(isc_g_mctx, sizeof(client_dcid), &router);

	result = isc_tlsctx_createclient(&opts.tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	conn = NULL;
	result = isc_quic_conn_client_create(
		isc_g_mctx, router, NULL, NULL, &opts, ISC_QUIC_VERSION_V1,
		NULL, &client_addr[0], &server_addr, &conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* Initial CRYPTO frames MUST be 1200 bytes */
	found = NULL;
	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ 1199, initial_frame_v1 }, &version,
		&dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_IGNORE);
	assert_int_equal(version, ISC_QUIC_VERSION_V1);
	assert_ptr_equal(found, NULL);

	/* Use reserved version 0x0A0A0A0A */
	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ 1200, initial_frame_reserved_version },
		&version, &dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_NOTIMPLEMENTED);
	assert_int_equal(version, ISC_QUIC_VERSION_UNKNOWN);
	assert_ptr_equal(found, NULL);

	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ 1200, initial_frame_v1 }, &version,
		&dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(version, ISC_QUIC_VERSION_V1);
	assert_int_equal(dcid.length, sizeof(client_dcid));
	assert_memory_equal(dcid.base, client_dcid, dcid.length);
	assert_ptr_equal(found, NULL);

	/* A 1-RTT packet for an unknown connection: caller MAY send a reset */
	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ sizeof(short_header_v1), short_header_v1 },
		NULL, &dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_UNEXPECTED);
	assert_null(found);
	assert_int_equal(dcid.length, sizeof(client_dcid));
	assert_memory_equal(dcid.base, client_dcid, dcid.length);

	result = isc_quic_router_add_cid(router, dcid, connection_tid, conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ 1200, initial_frame_v1 }, &version,
		&dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(version, ISC_QUIC_VERSION_V1);
	assert_ptr_equal(found, conn);
	isc_quic_conn_unref(found);

	found = NULL;
	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ 500, initial_frame_v1 }, &version,
		&dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(found, conn);
	isc_quic_conn_unref(found);

	found = NULL;
	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ sizeof(short_header_v1), short_header_v1 },
		NULL, &dcid, &scid, &tid, &found);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(found, conn);
	assert_int_equal(tid, connection_tid);
	assert_int_equal(dcid.length, sizeof(client_dcid));
	assert_memory_equal(dcid.base, client_dcid, dcid.length);
	isc_quic_conn_unref(found);

	result = isc_quic_router_del_cid(router, dcid);
	assert_int_equal(result, ISC_R_SUCCESS);

	found = NULL;
	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ 1200, initial_frame_v1 }, &version,
		&dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ sizeof(short_header_v1), short_header_v1 },
		NULL, &dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_UNEXPECTED);
	assert_null(found);

	result = isc_quic_router_add_stateless_reset(
		router, stateless_reset_token, connection_tid, conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ sizeof(stateless_reset_packet),
				     stateless_reset_packet },
		NULL, &dcid, &scid, NULL, &found);
	assert_int_equal(result, ISC_R_CONNECTIONRESET);
	isc_quic_conn_unref(found);

	result = isc_quic_router_del_stateless_reset(router,
						     stateless_reset_token);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_quic_conn_detach(&conn);
	isc_quic_router_detach(&router);
}

ISC_LOOP_TEST_IMPL(isc_quic_conn_base) {
	isc_constregion_t dcid, scid;
	isc_quic_conn_t *conn = NULL;
	isc_sockaddr_t from, to;
	isc_result_t result;
	endpoint_t *client, *server;
	struct stream_state *stream;
	isc_quic_version_t version;
	uint8_t buf[1200];
	size_t len, i;

	isc_region_t out = { sizeof(buf), buf };

	constexpr size_t client_len = 16;

	endpoint_create(true, client_len, &server);
	endpoint_create(false, client_len, &client);

	for (i = 0; i < client_len; i++) {
		result = isc_quic_conn_client_create(
			isc_g_mctx, client->router, &callbacks, client,
			&client->opts, ISC_QUIC_VERSION_V1, "bind9.local",
			&client_addr[i], &server_addr, &client->state[i].conn);
		assert_int_equal(result, ISC_R_SUCCESS);

		len = 0;
		result = isc_quic_conn_pull_packet(client->state[i].conn, out,
						   &len, &from, &to);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_true(isc_sockaddr_compare(&from, &client_addr[i],
						 ISC_SOCKADDR_CMPADDR |
							 ISC_SOCKADDR_CMPPORT));
		assert_true(isc_sockaddr_compare(&to, &server_addr,
						 ISC_SOCKADDR_CMPADDR |
							 ISC_SOCKADDR_CMPPORT));

		assert_int_equal(len, 1200);

		conn = NULL;
		result = isc_quic_router_handle_packet(
			server->router, (isc_constregion_t){ len, buf },
			&version, &dcid, &scid, NULL, &conn);
		assert_int_equal(result, ISC_R_NOTFOUND);

		server->state[i].conn = NULL;
		result = isc_quic_conn_server_create(
			isc_g_mctx, server->router, &callbacks, server,
			&server->opts, version, dcid, scid, &to, &from,
			&server->state[i].conn);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_non_null(server->state[i].conn);

		result = isc_quic_conn_push_packet(
			server->state[i].conn, (isc_constregion_t){ len, buf },
			&to, &from);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	rcu_barrier();

	while (server->handshakes != client_len) {
		for (i = 0; i < client_len; i++) {
			len = 0;
			result = isc_quic_conn_pull_packet(
				server->state[i].conn, out, &len, &from, &to);
			switch (result) {
			case ISC_R_UNEXPECTEDEND:
			case ISC_R_IGNORE:
				continue;
			case ISC_R_SUCCESS:
				assert_true(isc_sockaddr_compare(
					&from, &server_addr,
					ISC_SOCKADDR_CMPADDR |
						ISC_SOCKADDR_CMPPORT));
				assert_true(isc_sockaddr_compare(
					&to, &client_addr[i],
					ISC_SOCKADDR_CMPADDR |
						ISC_SOCKADDR_CMPPORT));
				break;
			default:
				UNREACHABLE();
			}

			result = isc_quic_conn_push_packet(
				client->state[i].conn,
				(isc_constregion_t){ len, buf }, &to, &from);
			assert_int_equal(result, ISC_R_SUCCESS);
		}

		for (i = 0; i < client_len; i++) {
			len = 0;
			result = isc_quic_conn_pull_packet(
				client->state[i].conn, out, &len, &from, &to);
			switch (result) {
			case ISC_R_UNEXPECTEDEND:
			case ISC_R_IGNORE:
				continue;
			case ISC_R_SUCCESS:
				break;
			default:
				UNREACHABLE();
			}

			assert_true(isc_sockaddr_compare(
				&from, &client_addr[i],
				ISC_SOCKADDR_CMPADDR | ISC_SOCKADDR_CMPPORT));
			assert_true(isc_sockaddr_compare(
				&to, &server_addr,
				ISC_SOCKADDR_CMPADDR | ISC_SOCKADDR_CMPPORT));

			result = isc_quic_router_handle_packet(
				server->router, (isc_constregion_t){ len, buf },
				NULL, &dcid, &scid, NULL, &conn);
			assert_int_equal(result, ISC_R_SUCCESS);

			result = isc_quic_conn_push_packet(
				conn, (isc_constregion_t){ len, buf }, &to,
				&from);
			assert_int_equal(result, ISC_R_SUCCESS);

			isc_quic_conn_detach(&conn);
		}
	}

	assert_int_equal(client->handshakes, server->handshakes);

	for (i = 0; i < client_len / 2; i++) {
		stream = isc_mem_get(isc_g_mctx, sizeof(*stream));
		*stream = (stream_state_t){ .link = ISC_LINK_INITIALIZER };
		result = isc_quic_conn_open_bidi_stream(
			client->state[i].conn, &stream->id, &client->state[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
		ISC_LIST_APPEND(client->state[i].stream, stream, link);

		result = isc_quic_conn_push_stream_data(
			client->state[i].conn, stream->id,
			messages[stream->cursor], sizeof(messages[0]));
		assert_int_equal(result, ISC_R_SUCCESS);
		stream->cursor = (stream->cursor + 1) % ARRAY_SIZE(messages);

		len = 0;
		result = isc_quic_conn_pull_packet(client->state[i].conn, out,
						   &len, &from, &to);
		assert_int_equal(result, ISC_R_SUCCESS);

		assert_int_not_equal(len, 0);

		result = isc_quic_router_handle_packet(
			server->router, (isc_constregion_t){ len, buf }, NULL,
			&dcid, &scid, NULL, &conn);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = isc_quic_conn_push_packet(
			conn, (isc_constregion_t){ len, buf }, &to, &from);
		assert_int_equal(result, ISC_R_SUCCESS);

		isc_quic_conn_detach(&conn);
	}

	for (i = client_len / 2; i < client_len; i++) {
		stream = isc_mem_get(isc_g_mctx, sizeof(*stream));
		*stream = (stream_state_t){ .link = ISC_LINK_INITIALIZER };
		result = isc_quic_conn_open_bidi_stream(
			server->state[i].conn, &stream->id, &server->state[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
		ISC_LIST_APPEND(client->state[i].stream, stream, link);

		result = isc_quic_conn_push_stream_data(
			server->state[i].conn, stream->id,
			messages[stream->cursor], sizeof(messages[0]));
		assert_int_equal(result, ISC_R_SUCCESS);

		len = 0;
		result = isc_quic_conn_pull_packet(server->state[i].conn, out,
						   &len, &from, &to);
		assert_int_equal(result, ISC_R_SUCCESS);

		assert_int_not_equal(len, 0);

		result = isc_quic_conn_push_packet(
			client->state[i].conn, (isc_constregion_t){ len, buf },
			&to, &from);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	endpoint_destroy(&client);
	endpoint_destroy(&server);

	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(isc_quic_conn_closed_stream_no_write) {
	isc_constregion_t dcid, scid;
	isc_quic_conn_t *conn = NULL;
	isc_sockaddr_t from, to;
	isc_result_t result;
	endpoint_t *client, *server;
	struct stream_state *stream;
	isc_quic_version_t version;
	uint8_t buf[1200];
	size_t len;

	isc_constregion_t packet = { 0, buf };
	isc_region_t out = { sizeof(buf), buf };

	endpoint_create(true, 1, &server);
	endpoint_create(false, 1, &client);

	result = isc_quic_conn_client_create(
		isc_g_mctx, client->router, &callbacks, client, &client->opts,
		ISC_QUIC_VERSION_V1, "bind9.local", &client_addr[0],
		&server_addr, &client->state[0].conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	len = 0;
	result = isc_quic_conn_pull_packet(client->state[0].conn, out, &len,
					   &from, &to);
	assert_int_equal(result, ISC_R_SUCCESS);

	packet.length = len;
	conn = NULL;
	result = isc_quic_router_handle_packet(server->router, packet, &version,
					       &dcid, &scid, NULL, &conn);
	assert_int_equal(result, ISC_R_NOTFOUND);
	server->state[0].conn = NULL;
	result = isc_quic_conn_server_create(
		isc_g_mctx, server->router, &callbacks, server, &server->opts,
		version, dcid, scid, &to, &from, &server->state[0].conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	rcu_barrier();

	while (client->handshakes == 0 && server->handshakes == 0) {
		try_exchange_packets(client->state[0].conn,
				     server->state[0].conn);
	}

	stream = isc_mem_get(isc_g_mctx, sizeof(*stream));
	*stream = (stream_state_t){ .link = ISC_LINK_INITIALIZER };
	result = isc_quic_conn_open_bidi_stream(client->state[0].conn,
						&stream->id, &client->state[0]);
	assert_int_equal(result, ISC_R_SUCCESS);
	ISC_LIST_APPEND(client->state[0].stream, stream, link);
	result = isc_quic_conn_push_stream_data(
		client->state[0].conn, stream->id, messages[stream->cursor],
		sizeof(messages[0]));
	assert_int_equal(result, ISC_R_SUCCESS);

	try_exchange_packets(client->state[0].conn, server->state[0].conn);

	/*
	 * Enqueue data to be written by the server.
	 */
	result = isc_quic_conn_push_stream_data(
		server->state[0].conn, stream->id, messages[stream->cursor],
		sizeof(messages[0]));
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_quic_conn_push_stream_data(
		server->state[0].conn, stream->id, messages[stream->cursor],
		sizeof(messages[0]));
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_quic_conn_push_stream_data(
		server->state[0].conn, stream->id, messages[stream->cursor],
		sizeof(messages[0]));
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Create packet with stream shutdown and push it to the server
	 */
	result = isc_quic_conn_shutdown_stream(client->state[0].conn,
					       stream->id, 123);
	assert_int_equal(result, ISC_R_SUCCESS);
	len = 0;
	result = isc_quic_conn_pull_packet(client->state[0].conn, out, &len,
					   &from, &to);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_not_equal(len, 0);
	packet.length = len;
	result = isc_quic_conn_push_packet(server->state[0].conn, packet, &to,
					   &from);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Because the stream has been closed, the messages will not be used.
	 */
	len = 0;
	result = isc_quic_conn_pull_packet(server->state[0].conn, out, &len,
					   &from, &to);
	assert_int_equal(result, ISC_R_IGNORE);
	assert_int_equal(len, 0);

	endpoint_destroy(&client);
	endpoint_destroy(&server);

	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_quic_router_cid)
ISC_TEST_ENTRY(isc_quic_router_stateless_reset)
ISC_TEST_ENTRY(isc_quic_router_packet)
ISC_TEST_ENTRY_CUSTOM(isc_quic_conn_base, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(isc_quic_conn_closed_stream_no_write, setup_managers,
		      teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(global_setup, global_teardown);
