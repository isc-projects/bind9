
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

#pragma once

#include <stdint.h>

#include <ngtcp2/ngtcp2.h>

#include <isc/quic.h>
#include <isc/types.h>

typedef struct isc__quic_stream isc__quic_stream_t;
typedef struct isc__quic_stream_data isc__quic_stream_data_t;

#ifdef HAVE_OPENSSL_3
typedef struct isc__quic_crypto_frame_data isc__quic_crypto_frame_data_t;
#endif /* HAVE_OPENSSL_3 */

typedef enum isc__quic_conn_state {
	QUIC_CONN_STATE_INVALID = 0x00,
	QUIC_CONN_STATE_HANDSHAKE = 0x01,
	QUIC_CONN_STATE_CONNECTED = 0x02,
	QUIC_CONN_STATE_CLOSED = 0x03,
	QUIC_CONN_STATE_TERMINATED = 0x04,
} isc__quic_conn_state_t;

struct isc_quic_conn {
	uint32_t magic;
	isc_refcount_t references;

	isc_quic_router_t *router;

	const isc_quic_conn_callbacks_t *cb;
	void *cbarg;

	ISC_LIST(isc__quic_stream_t) streams;
	ISC_LIST(isc__quic_stream_data_t) outgoing_stream_data;

	/* isc_mem_t resides inside `mem.user_data` */
	ngtcp2_mem mem;

	/*
	 * This fits "\x3doq\x2h3" and fits perfectly with the struct's 8 byte
	 * member alignment.
	 */
	struct {
		uint8_t len;
		uint8_t data[7];
	} alpn;

	isc__quic_conn_state_t state;

/*
 * OpenSSL (not the forks) wants us to keep some information alive and
 * allocated.
 */
#ifdef HAVE_OPENSSL_3
	ngtcp2_encryption_level level;
	uint8_t *local_transport_params;
	ISC_LIST(isc__quic_crypto_frame_data_t) crypto_buffered_frames;
	ISC_LIST(isc__quic_crypto_frame_data_t) crypto_awaiting_frames;
#endif /* HAVE_OPENSSL_3 */

	ngtcp2_conn *inner;
};

#ifdef HAVE_OPENSSL_3
struct isc__quic_crypto_frame_data {
	size_t len;
	ISC_LINK(isc__quic_crypto_frame_data_t) link;
	uint8_t data[] ISC_ATTR_COUNTED_BY(len);
};
#endif /* HAVE_OPENSSL_3 */

isc_result_t
isc__quic_setup_read_key(isc_quic_conn_t *conn, bool is_server,
			 ngtcp2_encryption_level nglevel,
			 isc_constregion_t secret);
/**<
 * \brief
 * Derive and install key for RX operations.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_FAILURE on opaque failure
 */

isc_result_t
isc__quic_setup_write_key(isc_quic_conn_t *conn, bool is_server,
			  ngtcp2_encryption_level nglevel,
			  isc_constregion_t secret);
/**<
 * \brief
 * Derive and install key for TX operations.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_FAILURE on opaque failure
 */

isc_result_t
isc__quic_set_remote_transport_params(isc_quic_conn_t *conn, isc_tls_t *tls);

isc_result_t
isc__quic_set_local_transport_params(isc_quic_conn_t *conn, isc_tls_t *tls);

isc_result_t
isc__quic_setup_tls(isc_tls_t *tls, isc_quic_conn_t *conn);
/**<
 * \brief
 * Setup for the connection.
 *
 * \retval ISC_R_SUCCESS on success.
 */

isc_result_t
isc__quic_do_tls(isc_quic_conn_t *conn, isc_tls_t *tls,
		 ngtcp2_encryption_level nglevel, isc_constregion_t data);
/**<
 * \brief
 * Drive the TLS integration of the connection.
 *
 * \retval ISC_R_SUCCESS on success
 */
