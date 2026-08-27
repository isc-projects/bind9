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
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/urcu.h>

#include <tests/isc.h>

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

constexpr uint8_t stateless_reset_token[ISC_QUIC_STATELESS_TOKEN_LENGTH] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

constexpr uint8_t stateless_reset_packet[] = {
	0x40, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

/*
 * A 1-RTT packet for the connection identified by client_dcid. Its last 16
 * bytes deliberately differ from stateless_reset_token.
 */
constexpr uint8_t short_header_packet[] = {
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

ISC_RUN_TEST_IMPL(isc_quic_router_cid) {
	isc_quic_router_t *router = NULL;
	isc_quic_conn_t *conn, *found;
	isc_constregion_t cid;
	isc_result_t result;
	isc_tid_t tid = ISC_TID_UNKNOWN;

	isc_quic_conn_options_t opts = {};

	isc_quic_router_create(isc_g_mctx, sizeof(client_dcid), &router);

	conn = NULL;
	result = isc_quic_conn_client_create(isc_g_mctx, router, NULL, NULL,
					     &opts, NULL, NULL, NULL, &conn);
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

	isc_quic_conn_options_t opts = {};

	isc_quic_router_create(isc_g_mctx, sizeof(client_dcid), &router);

	conn = NULL;
	result = isc_quic_conn_client_create(isc_g_mctx, router, NULL, NULL,
					     &opts, NULL, NULL, NULL, &conn);
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

	isc_quic_conn_options_t opts = {};

	isc_quic_router_create(isc_g_mctx, sizeof(client_dcid), &router);

	conn = NULL;
	result = isc_quic_conn_client_create(isc_g_mctx, router, NULL, NULL,
					     &opts, NULL, NULL, NULL, &conn);
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
		(isc_constregion_t){ sizeof(short_header_packet),
				     short_header_packet },
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
		(isc_constregion_t){ sizeof(short_header_packet),
				     short_header_packet },
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
		(isc_constregion_t){ sizeof(short_header_packet),
				     short_header_packet },
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

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_quic_router_cid)
ISC_TEST_ENTRY(isc_quic_router_stateless_reset)
ISC_TEST_ENTRY(isc_quic_router_packet)
ISC_TEST_LIST_END

ISC_TEST_MAIN
