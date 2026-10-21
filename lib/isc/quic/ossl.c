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
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/crypto.h>
#include <isc/ossl_wrap.h>

#include "quic_p.h" /* IWYU pragma: keep */

/**
 * \brief
 * Lookup table for translating a OpenSSL encryption level to its ngtcp2
 * counterpart.
 */
static ngtcp2_encryption_level libssl_to_ngtcp2_level_lut[] = {
	/* clang-format off */
	[OSSL_RECORD_PROTECTION_LEVEL_NONE] = NGTCP2_ENCRYPTION_LEVEL_INITIAL,
	[OSSL_RECORD_PROTECTION_LEVEL_EARLY] = NGTCP2_ENCRYPTION_LEVEL_0RTT,
	[OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE] = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
	[OSSL_RECORD_PROTECTION_LEVEL_APPLICATION] = NGTCP2_ENCRYPTION_LEVEL_1RTT,
	/* clang-format on */
};

/**
 * \brief
 * `SSL` object index to point back to its `isc_quic_conn_t`
 *
 * This is only really used inside the ALPN selection callback since the
 * callback argument is global for all connections created by the same
 * `SSL_CTX`.
 */
static int quic_index = -1;

/*
 * https://docs.openssl.org/master/man3/SSL_set_quic_tls_cbs/
 */

static int
crypto_send_cb(isc_tls_t *tls, const uint8_t *buf, size_t len, size_t *consumed,
	       void *arg);

static int
crypto_recv_rcd_cb(isc_tls_t *tls, const unsigned char **buf, size_t *read,
		   void *arg);

static int
crypto_release_rcd_cb(isc_tls_t *tls, size_t released, void *arg);

static int
yield_secret_cb(isc_tls_t *tls, uint32_t prot_level, int direction,
		const unsigned char *secret, size_t len, void *arg);

static int
got_transport_params_cb(isc_tls_t *tls, const uint8_t *params, size_t len,
			void *arg);

static int
alert_cb(isc_tls_t *tls, uint8_t code, void *arg);

static const OSSL_DISPATCH dispatch[] = {
	{
		.function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
		.function = (OSSL_FUNC)crypto_send_cb,
	},
	{
		.function_id = OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
		.function = (OSSL_FUNC)yield_secret_cb,
	},
	{
		.function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
		.function = (OSSL_FUNC)crypto_recv_rcd_cb,
	},
	{
		.function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
		.function = (OSSL_FUNC)crypto_release_rcd_cb,
	},
	{
		.function_id = OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
		.function = (OSSL_FUNC)got_transport_params_cb,
	},
	{
		.function_id = OSSL_FUNC_SSL_QUIC_TLS_ALERT,
		.function = (OSSL_FUNC)alert_cb,
	},
	{
		.function_id = 0,
		.function = NULL,
	},
};

isc_result_t
isc__quic_setup_tls(isc_tls_t *tls, isc_quic_conn_t *conn) {
	SSL_set_ex_data(tls, quic_index, conn);

	/*
	 * There is no SSL_CTX_set_quic_tls_cbs
	 */
	if (SSL_set_quic_tls_cbs(tls, dispatch, conn) != 1) {
		return ISC_R_TLSERROR;
	}

	return ISC_R_SUCCESS;
}

static int
crypto_send_cb(isc_tls_t *tls ISC_ATTR_UNUSED, const uint8_t *buf, size_t len,
	       size_t *consumed, void *arg) {
	isc_quic_conn_t *conn;
	int r;

	conn = arg;
	r = ngtcp2_conn_submit_crypto_data(conn->inner, conn->level, buf, len);
	if (r != 0) {
		ngtcp2_conn_set_tls_error(conn->inner, r);
		return 0;
	}

	*consumed = len;

	return 1;
}

static int
crypto_recv_rcd_cb(isc_tls_t *tls ISC_ATTR_UNUSED, const unsigned char **bufp,
		   size_t *readp, void *arg) {
	isc__quic_crypto_frame_data_t *frame;
	isc_quic_conn_t *conn;

	conn = arg;
	if (conn == NULL) {
		*bufp = NULL;
		*readp = 0;
		return 1;
	}

	frame = ISC_LIST_HEAD(conn->crypto_buffered_frames);
	if (frame == NULL) {
		*bufp = NULL;
		*readp = 0;
		return 1;
	}
	ISC_LIST_DEQUEUE(conn->crypto_buffered_frames, frame, link);
	ISC_LIST_ENQUEUE(conn->crypto_awaiting_frames, frame, link);

	*bufp = frame->data;
	*readp = frame->len;

	return 1;
}

static int
crypto_release_rcd_cb(isc_tls_t *tls ISC_ATTR_UNUSED, size_t released,
		      void *arg) {
	isc__quic_crypto_frame_data_t *frame;
	isc_quic_conn_t *conn;

	conn = arg;
	INSIST(conn != NULL);

	if (released == 0) {
		return 1;
	}

	frame = ISC_LIST_HEAD(conn->crypto_awaiting_frames);
	INSIST(frame != NULL);
	ISC_LIST_DEQUEUE(conn->crypto_awaiting_frames, frame, link);
	isc_mem_put(conn->mem.user_data, frame,
		    STRUCT_FLEX_SIZE(frame, data, frame->len));

	return 1;
}

static int
yield_secret_cb(isc_tls_t *tls ISC_ATTR_UNUSED, uint32_t level, int direction,
		const unsigned char *secret, size_t len, void *arg) {
	ngtcp2_encryption_level nglevel;
	isc_quic_conn_t *conn;
	isc_result_t result;
	bool is_server;

	nglevel = libssl_to_ngtcp2_level_lut[level];
	conn = arg;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	is_server = ngtcp2_conn_is_server2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	is_server = ngtcp2_conn_is_server(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	switch (direction) {
	case 0:
		result = isc__quic_setup_read_key(
			conn, is_server, nglevel,
			(isc_constregion_t){ len, secret });
		if (result != ISC_R_SUCCESS) {
			return 0;
		}
		break;
	case 1:
		result = isc__quic_setup_write_key(
			conn, is_server, nglevel,
			(isc_constregion_t){ len, secret });
		if (result != ISC_R_SUCCESS) {
			return 0;
		}
		conn->level = nglevel;
		break;
	default:
		UNREACHABLE();
	}

	return 1;
}

static int
got_transport_params_cb(isc_tls_t *tls ISC_ATTR_UNUSED, const uint8_t *params,
			size_t len, void *arg) {
	isc_quic_conn_t *conn;
	int r;

	conn = arg;
	r = ngtcp2_conn_decode_and_set_remote_transport_params(conn->inner,
							       params, len);
	if (r != 0) {
		ngtcp2_conn_set_tls_error(conn->inner, r);
		return 0;
	}

	return 1;
}

static int
alert_cb(isc_tls_t *tls ISC_ATTR_UNUSED, uint8_t code, void *arg) {
	isc_quic_conn_t *conn = arg;
	ngtcp2_conn_set_tls_alert(conn->inner, code);
	return 1;
}

static int
quic_alpn_select(isc_tls_t *tls, const unsigned char **outp,
		 unsigned char *lenp, const unsigned char *in, unsigned int len,
		 void *arg ISC_ATTR_UNUSED) {
	isc_quic_conn_t *conn = SSL_get_ex_data(tls, quic_index);
	INSIST(conn != NULL);

	int r = SSL_select_next_proto(UNCONST(outp), lenp, in, len,
				      conn->alpn.data, conn->alpn.len);
	if (r != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	return SSL_TLSEXT_ERR_OK;
}

/*
 * This is a no-op here because OpenSSL expects the remote transport parameters
 * to be set inside the `got_transport_params_cb`.
 */
isc_result_t
isc__quic_set_remote_transport_params(isc_quic_conn_t *conn ISC_ATTR_UNUSED,
				      isc_tls_t *tls ISC_ATTR_UNUSED) {
	return ISC_R_SUCCESS;
}

isc_result_t
isc__quic_set_local_transport_params(isc_quic_conn_t *conn, isc_tls_t *tls) {
	/*
	 * I don't think there is a well defined limit but I see that 256 bytes
	 * is common in the wild so this should be good enough
	 *
	 * (famous last words)
	 *
	 * - Aydin
	 */
	uint8_t buffer[512];
	ngtcp2_ssize len;
	int r;

	INSIST(conn->local_transport_params == NULL);

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	len = ngtcp2_conn_encode_local_transport_params2(conn->inner, buffer,
							 sizeof(buffer));
#else
	len = ngtcp2_conn_encode_local_transport_params(conn->inner, buffer,
							sizeof(buffer));
#endif
	if (len < 0) {
		return ISC_R_NOSPACE;
	}

	conn->local_transport_params = isc_mem_allocate(conn->mem.user_data,
							len);
	memcpy(conn->local_transport_params, buffer, len);

	r = SSL_set_quic_tls_transport_params(tls, conn->local_transport_params,
					      len);
	if (r != 1) {
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"SSL_set_quic_tls_transport_params", ISC_R_TLSERROR);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc__quic_do_tls(isc_quic_conn_t *conn, isc_tls_t *tls,
		 ngtcp2_encryption_level nglevel ISC_ATTR_UNUSED,
		 isc_constregion_t data) {
	isc__quic_crypto_frame_data_t *frame;
	isc_result_t result;
	bool need_handshake;
	int r;

	ERR_set_mark();

	if (data.length != 0) {
		frame = isc_mem_get(conn->mem.user_data,
				    STRUCT_FLEX_SIZE(frame, data, data.length));
		*frame = (isc__quic_crypto_frame_data_t){
			.len = data.length,
			.link = ISC_LINK_INITIALIZER,
		};
		memcpy(frame->data, data.base, data.length);
		ISC_LIST_ENQUEUE(conn->crypto_buffered_frames, frame, link);
	}

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	need_handshake = ngtcp2_conn_get_handshake_completed2(conn->inner) == 0;
#else
	need_handshake = ngtcp2_conn_get_handshake_completed(conn->inner) == 0;
#endif

	if (need_handshake) {
		r = SSL_do_handshake(tls);
		if (r <= 0) {
			switch (SSL_get_error(tls, r)) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_X509_LOOKUP:
			case SSL_ERROR_WANT_CLIENT_HELLO_CB:
				CLEANUP(ISC_R_SUCCESS);
			default:
				CLEANUP(ISC_R_TLSERROR);
			}
		}

		ngtcp2_conn_tls_handshake_completed(conn->inner);
	}

	r = SSL_read(tls, NULL, 0);
	if (r != 1) {
		switch (SSL_get_error(tls, r)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			CLEANUP(ISC_R_SUCCESS);
		default:
			CLEANUP(ISC_R_TLSERROR);
		}
	}

	result = ISC_R_SUCCESS;

cleanup:
	ERR_pop_to_mark();
	return result;
}

isc_result_t
isc_quic_tlsctx_client_configure(isc_tlsctx_t *tlsctx) {
	REQUIRE(tlsctx != NULL);

	if (SSL_CTX_set_min_proto_version(tlsctx, TLS1_3_VERSION) != 1) {
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"SSL_CTX_set_min_proto_version", ISC_R_TLSERROR);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_tlsctx_server_configure(isc_tlsctx_t *tlsctx) {
	REQUIRE(tlsctx != NULL);

	SSL_CTX_set_alpn_select_cb(tlsctx, quic_alpn_select, NULL);

	if (SSL_CTX_set_min_proto_version(tlsctx, TLS1_3_VERSION) != 1) {
		return isc_ossl_wrap_logged_toresult(
			ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO,
			"SSL_CTX_set_min_proto_version", ISC_R_TLSERROR);
	}

	return ISC_R_SUCCESS;
}

void
isc__quic_initialize(void) {
	quic_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	INSIST(quic_index != -1);
}

void
isc__quic_shutdown(void) {
	/* noop */
}
