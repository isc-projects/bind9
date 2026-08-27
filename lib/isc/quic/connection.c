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
#include <stdint.h>

#include <ngtcp2/ngtcp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/attributes.h>
#include <isc/crypto.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/safe.h>
#include <isc/sockaddr.h>
#include <isc/util.h>

#include "quic_p.h" /* IWYU pragma: keep */

/**
 * \brief
 * Specified in RFC9001, Section 5.2.
 */
#define QUIC_INITIAL_SECRET_LENGTH 32

#define QUIC_AES128_KEY_LENGTH 16

#define VALID_CONNECTION(c) ISC_MAGIC_VALID(c, conn_magic)

#ifdef ISC_QUIC_STATE_CHECK
#define CHECK_STATE(conn, ...)                                         \
	({                                                             \
		__label__ out;                                         \
		isc__quic_conn_state_t _allowed[] = { __VA_ARGS__ };   \
		for (size_t _i = 0; _i < ARRAY_SIZE(_allowed); _i++) { \
			if ((conn)->state == _allowed[_i]) {           \
				goto out;                              \
			}                                              \
		}                                                      \
		UNREACHABLE();                                         \
	out:;                                                          \
	})
#else /* ISC_QUIC_STATE_CHECK */
#define CHECK_STATE(conn, ...)
#endif /* ISC_QUIC_STATE_CHECK */

typedef isc_result_t (*pull_packet_fn)(isc_quic_conn_t *conn, isc_region_t out,
				       size_t *written, isc_sockaddr_t *from,
				       isc_sockaddr_t *to);

typedef struct quic_conn_state_node {
	pull_packet_fn pull_packet;
} quic_conn_state_node_t;

struct isc__quic_stream {
	int64_t id;
	void *data;
	size_t last_acked_offset;
	ISC_LIST(isc__quic_stream_data_t) ack_data;
	ISC_LINK(isc__quic_stream_t) link;
};

struct isc__quic_stream_data {
	bool finish;
	bool zerortt;
	int64_t stream_id;
	size_t length;
	ISC_LINK(isc__quic_stream_data_t) link;
	uint8_t bytes[] ISC_ATTR_COUNTED_BY(length);
};

constexpr uint32_t conn_magic = ISC_MAGIC('Q', 'U', 'I', 'c');

/**
 * \brief
 * Initial maximum stream data of 128 KiB.
 */
constexpr uint64_t initial_max_stream_data = 131072;

/**
 * \brief
 * Initial maximum data of 512 KiB.
 */
constexpr uint64_t initial_max_data = 524288;

/**
 * \brief
 * Initial number of allowed bidirectional streams.
 */
constexpr uint64_t initial_max_streams_bidi = 16;

/**
 * \brief
 * Initial number of allowed unidirectional streams.
 */
constexpr uint64_t initial_max_streams_uni = 0;

/**
 * \brief
 * The confidentiality limit for AES-128-GCM and AES-256-GCM as used in TLS.
 *
 * The value is specified in RFC9001, Section 6.6.
 */
constexpr uint64_t aes_gcm_max_encryption = 8388608;

/**
 * \brief
 * The integrity limit for AES-128-GCM and AES-256-GCM as used in TLS.
 *
 * The value is specified in RFC9001, Section 6.6.
 */
constexpr uint64_t aes_gcm_max_decryption_failure = 4503599627370496;

/**
 * \brief
 * The confidentiality limit for ChaCha20-Poly1305 as used in TLS.
 *
 * The value is specified in RFC9001, Section 6.6.
 */
constexpr uint64_t chacha20poly1305_max_encryption = 4611686018427387904;

/**
 * \brief
 * The integrity limit for ChaCha20-Poly1305 as used in TLS.
 *
 * The value is specified in RFC9001, Section 6.6.
 */
constexpr uint64_t chacha20poly1305_max_decryption_failure = 68719476736;

static const uint32_t preferred_versions[] = {
	NGTCP2_PROTO_VER_V2,
	NGTCP2_PROTO_VER_V1,
};

static isc_result_t
pull_packet_invalid(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		    isc_sockaddr_t *from, isc_sockaddr_t *to);

static isc_result_t
pull_packet_nodata(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		   isc_sockaddr_t *from, isc_sockaddr_t *to);

static isc_result_t
pull_packet_connected(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		      isc_sockaddr_t *from, isc_sockaddr_t *to);

static isc_result_t
pull_packet_closed(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		   isc_sockaddr_t *from, isc_sockaddr_t *to);

static isc_result_t
pull_packet_terminated(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		       isc_sockaddr_t *from, isc_sockaddr_t *to);

static int
client_initial_cb(ngtcp2_conn *ngconn, void *user_data);

static int
recv_client_initial_cb(ngtcp2_conn *ngconn, const ngtcp2_cid *dcid,
		       void *user_data);

static int
recv_crypto_data_cb(ngtcp2_conn *ngconn, ngtcp2_encryption_level nglevel,
		    uint64_t offset, const uint8_t *data, size_t len,
		    void *user_data);

static int
handshake_completed_cb(ngtcp2_conn *ngconn, void *user_data);

static int
encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *ngaead,
	   const ngtcp2_crypto_aead_ctx *ngctx, const uint8_t *plaintext,
	   size_t plaintextlen, const uint8_t *nonce, size_t noncelen,
	   const uint8_t *aad, size_t aadlen);

static int
decrypt_cb(uint8_t *out_ptr, const ngtcp2_crypto_aead *ngaead,
	   const ngtcp2_crypto_aead_ctx *ngctx, const uint8_t *ciphertext_ptr,
	   size_t ciphertext_len, const uint8_t *nonce_ptr, size_t nonce_len,
	   const uint8_t *aad_ptr, size_t aad_len);

static int
hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *nghp,
	   const ngtcp2_crypto_cipher_ctx *ngctx, const uint8_t *sample);

static int
recv_stream_data_cb(ngtcp2_conn *ngconn, uint32_t flags, int64_t stream_id,
		    uint64_t offset, const uint8_t *data, size_t datalen,
		    void *user_data, void *stream_user_data);

static int
acked_stream_data_offset_cb(ngtcp2_conn *ngconn, int64_t stream_id,
			    uint64_t offset, uint64_t datalen, void *user_data,
			    void *stream_user_data);

static int
stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data);

#ifndef NGTCP2_CALLBACKS_V5
static int
stream_close_cb(ngtcp2_conn *ngconn, uint32_t flags, int64_t stream_id,
		uint64_t app_error_code, void *user_data,
		void *stream_user_data);
#endif /* !NGTCP2_CALLBACKS_V5 */

static int
recv_retry_cb(ngtcp2_conn *ngconn, const ngtcp2_pkt_hd *header,
	      void *user_data);

static void
rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx);

#ifndef NGTCP2_CALLBACKS_V3
static int
get_new_connection_id_cb(ngtcp2_conn *ngconn, ngtcp2_cid *cid, uint8_t *token,
			 size_t cidlen, void *user_data);
#endif /* !NGTCP2_CALLBACKS_V3 */

static int
remove_connection_id_cb(ngtcp2_conn *ngconn, const ngtcp2_cid *ngcid,
			void *user_data);

static int
update_key_cb(ngtcp2_conn *ngconn, uint8_t *rx_secret, uint8_t *tx_secret,
	      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
	      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
	      const uint8_t *current_rx_secret,
	      const uint8_t *current_tx_secret, size_t secretlen,
	      void *user_data);

static void
delete_crypto_aead_ctx_cb(ngtcp2_conn *ngconn, ngtcp2_crypto_aead_ctx *ngctx,
			  void *user_data);

static void
delete_crypto_cipher_ctx_cb(ngtcp2_conn *ngconn,
			    ngtcp2_crypto_cipher_ctx *ngctx, void *user_data);

#ifndef NGTCP2_CALLBACKS_V3
static int
get_path_challenge_data_cb(ngtcp2_conn *ngconn, uint8_t *data, void *user_data);
#endif /* NGTCP2_CALLBACKS_V3 */

static int
version_negotiation_cb(ngtcp2_conn *ngconn, uint32_t ngversion,
		       const ngtcp2_cid *client_dcid, void *user_data);

#ifdef NGTCP2_CALLBACKS_V3
static int
get_new_connection_id2_cb(ngtcp2_conn *ngconn, ngtcp2_cid *ngcid,
			  ngtcp2_stateless_reset_token *token, size_t cidlen,
			  void *user_data);

static int
dcid_status2_cb(ngtcp2_conn *ngconn, ngtcp2_connection_id_status_type type,
		uint64_t seq, const ngtcp2_cid *ngcid,
		const ngtcp2_stateless_reset_token *ngtoken, void *user_data);

static int
get_path_challenge_data2_cb(ngtcp2_conn *ngconn,
			    ngtcp2_path_challenge_data *data, void *user_data);
#endif /* NGTCP2_CALLBACKS_V3 */

#ifdef NGTCP2_CALLBACKS_V4
static int
recv_stop_sending_cb(ngtcp2_conn *ngconn, int64_t stream_id,
		     uint64_t app_error_code, void *user_data,
		     void *stream_user_data);
#endif /* NGTCP2_CALLBACKS_V4 */

#ifdef NGTCP2_CALLBACKS_V5
static int
stream_close2_cb(ngtcp2_conn *ngconn, uint32_t flags, int64_t stream_id,
		 uint64_t rx_app_error_code, uint64_t tx_app_error_code,
		 void *user_data, void *stream_user_data);
#endif /* NGTCP2_CALLBACKS_V5 */

static const ngtcp2_callbacks client_cb = {
	.client_initial = client_initial_cb,
	.recv_crypto_data = recv_crypto_data_cb,
	.handshake_completed = handshake_completed_cb,
	.encrypt = encrypt_cb,
	.decrypt = decrypt_cb,
	.hp_mask = hp_mask_cb,
	.recv_stream_data = recv_stream_data_cb,
	.acked_stream_data_offset = acked_stream_data_offset_cb,
	.stream_open = stream_open_cb,
#ifndef NGTCP2_CALLBACKS_V5
	.stream_close = stream_close_cb,
#endif /* NGTCP2_CALLBACKS_V5 */
	.recv_retry = recv_retry_cb,
	.rand = rand_cb,
#ifndef NGTCP2_CALLBACKS_V3
	.get_new_connection_id = get_new_connection_id_cb,
#endif /* NGTCP2_CALLBACKS_V3 */
	.remove_connection_id = remove_connection_id_cb,
	.update_key = update_key_cb,
	.delete_crypto_aead_ctx = delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = delete_crypto_cipher_ctx_cb,
#ifndef NGTCP2_CALLBACKS_V3
	.get_path_challenge_data = get_path_challenge_data_cb,
#endif /* NGTCP2_CALLBACKS_V3 */
	.version_negotiation = version_negotiation_cb,
#ifdef NGTCP2_CALLBACKS_V3
	.get_new_connection_id2 = get_new_connection_id2_cb,
	.get_path_challenge_data2 = get_path_challenge_data2_cb,
#endif /* NGTCP2_CALLBACKS_V3 */
#ifdef NGTCP2_CALLBACKS_V4
	.recv_stop_sending = recv_stop_sending_cb,
#endif /* NGTCP2_CALLBACKS_V4 */
#ifdef NGTCP2_CALLBACKS_V5
	.stream_close2 = stream_close2_cb,
#endif /* NGTCP2_CALLBACKS_V5 */
};

static const ngtcp2_callbacks server_cb = {
	.recv_client_initial = recv_client_initial_cb,
	.recv_crypto_data = recv_crypto_data_cb,
	.handshake_completed = handshake_completed_cb,
	.encrypt = encrypt_cb,
	.decrypt = decrypt_cb,
	.hp_mask = hp_mask_cb,
	.recv_stream_data = recv_stream_data_cb,
	.acked_stream_data_offset = acked_stream_data_offset_cb,
	.stream_open = stream_open_cb,
#ifndef NGTCP2_CALLBACKS_V5
	.stream_close = stream_close_cb,
#endif /* !NGTCP2_CALLBACKS_V5 */
	.rand = rand_cb,
#ifndef NGTCP2_CALLBACKS_V3
	.get_new_connection_id = get_new_connection_id_cb,
#endif /* !NGTCP2_CALLBACKS_V3 */
	.remove_connection_id = remove_connection_id_cb,
	.update_key = update_key_cb,
	.delete_crypto_aead_ctx = delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = delete_crypto_cipher_ctx_cb,
#ifndef NGTCP2_CALLBACKS_V3
	.get_path_challenge_data = get_path_challenge_data_cb,
#endif /* !NGTCP2_CALLBACKS_V3 */
	.version_negotiation = version_negotiation_cb,
#ifdef NGTCP2_CALLBACKS_V3
	.get_new_connection_id2 = get_new_connection_id2_cb,
	.dcid_status2 = dcid_status2_cb,
	.get_path_challenge_data2 = get_path_challenge_data2_cb,
#endif /* NGTCP2_CALLBACKS_V3 */
#ifdef NGTCP2_CALLBACKS_V4
	.recv_stop_sending = recv_stop_sending_cb,
#endif /* NGTCP2_CALLBACKS_V4 */
#ifdef NGTCP2_CALLBACKS_V5
	.stream_close2 = stream_close2_cb,
#endif /* NGTCP2_CALLBACKS_V5 */
};

static quic_conn_state_node_t state_table[] = {
	[QUIC_CONN_STATE_INVALID] = { pull_packet_invalid },
	[QUIC_CONN_STATE_HANDSHAKE] = { pull_packet_nodata },
	[QUIC_CONN_STATE_CONNECTED] = { pull_packet_connected },
	[QUIC_CONN_STATE_CLOSED] = { pull_packet_closed },
	[QUIC_CONN_STATE_TERMINATED] = { pull_packet_terminated },
};

static const ngtcp2_crypto_ctx initial_aes128gcm_sha256_ctx = {
	.aead = { .native_handle = (void *)(uintptr_t)
			  ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM,
		  .max_overhead = isc_crypto_aes128gcm_tag_length },
	.md = { .native_handle = (void *)(uintptr_t)ISC_MD_SHA256 },
	.hp = { .native_handle = (void *)(uintptr_t)
			ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128 },
	.max_encryption = aes_gcm_max_encryption,
	.max_decryption_failure = aes_gcm_max_decryption_failure,
};

static const ngtcp2_crypto_ctx initial_aes256_sha384_ctx = {
	.aead = { .native_handle = (void *)(uintptr_t)
			  ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM,
		  .max_overhead = isc_crypto_aes256gcm_tag_length, },
	.md = { .native_handle = (void *)(uintptr_t)ISC_MD_SHA384 },
	.hp = { .native_handle = (void *)(uintptr_t)
			ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES256 },
	.max_encryption = aes_gcm_max_encryption,
	.max_decryption_failure = aes_gcm_max_decryption_failure,
};

static const ngtcp2_crypto_ctx initial_chacha20poly1305_sha256_ctx = {
	.aead = { .native_handle = (void *)(uintptr_t)
			  ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305,
		  .max_overhead = isc_crypto_chacha20poly1305_tag_length },
	.md = { .native_handle = (void *)(uintptr_t)ISC_MD_SHA256 },
	.hp = { .native_handle = (void *)(uintptr_t)
			ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_CHACHA20 },
	.max_encryption = chacha20poly1305_max_encryption,
	.max_decryption_failure = chacha20poly1305_max_decryption_failure,
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC client-side initial packet secret.
 *
 * The value is specified in RFC9001, Section 5.2.
 */
static const uint8_t client_label[] = {
	'c', 'l', 'i', 'e', 'n', 't', ' ', 'i', 'n',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC server-side initial packet secret.
 *
 * The value is specified in RFC9001, Section 5.2.
 */
static const uint8_t server_label[] = {
	's', 'e', 'r', 'v', 'e', 'r', ' ', 'i', 'n',
};

/**
 * \brief
 * The HKDF label used when deriving QUIC v1 packet protection AEAD keys.
 *
 * The value is specified in RFC9001, Section 5.1.
 */
static const uint8_t key_label_v1[] = {
	'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v1 new write secret in a key
 * update.
 *
 * The value is specified in RFC9001, Section 6.1.
 */
static const uint8_t key_update_label_v1[] = {
	'q', 'u', 'i', 'c', ' ', 'k', 'u',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v1 packet protection AEAD nonce.
 *
 * The value is specified in RFC9001, Section 5.1.
 */
static const uint8_t iv_label_v1[] = {
	'q', 'u', 'i', 'c', ' ', 'i', 'v',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v1 header protection key.
 *
 * The value is specified in RFC9001, Section 5.4.
 */
static const uint8_t hp_label_v1[] = {
	'q', 'u', 'i', 'c', ' ', 'h', 'p',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v2 packet protection keys.
 *
 * The value is specified in RFC9369, Section 3.3.2.
 */
static const uint8_t key_label_v2[] = {
	'q', 'u', 'i', 'c', 'v', '2', ' ', 'k', 'e', 'y',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v2 new write secret in a key
 * update.
 *
 * The value is specified in RFC9369, Section 3.3.2.
 */
static const uint8_t key_update_label_v2[] = {
	'q', 'u', 'i', 'c', 'v', '2', ' ', 'k', 'u',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v2 packet protection AEAD nonce.
 *
 * The value is specified in RFC9369, Section 3.3.2.
 */
static const uint8_t iv_label_v2[] = {
	'q', 'u', 'i', 'c', 'v', '2', ' ', 'i', 'v',
};

/**
 * \brief
 * The HKDF label used when deriving the QUIC v1 header protection key.
 *
 * The value is specified in RFC9369, Section 3.3.2.
 */
static const uint8_t hp_label_v2[] = {
	'q', 'u', 'i', 'c', 'v', '2', ' ', 'h', 'p',
};

/**
 * \brief
 * Salt value of the HKDF-Extract when the deriving QUIC v1 initial secrets.
 *
 * The value is specified in RFC9001 Section 5.2.
 */
static const uint8_t salt_v1[] = {
	0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17,
	0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A,
};

/**
 * \brief
 * Salt value of the HKDF-Extract when deriving the QUIC v2 initial secrets.
 *
 * The value is specified in RFC9369 Section 3.3.1.
 */
static const uint8_t salt_v2[] = {
	0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB, 0x81, 0x93,
	0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB, 0xF9, 0xBD, 0x2E, 0xD9,
};

static void
destroy(isc_quic_conn_t *conn) {
	isc_mem_t *mctx;
	isc_tls_t *tls;

	conn->magic = 0x00;
	mctx = conn->mem.user_data;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	tls = ngtcp2_conn_get_tls_native_handle2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	tls = ngtcp2_conn_get_tls_native_handle(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	ISC_LIST_FOREACH(conn->streams, stream, link) {
		ISC_LIST_FOREACH(stream->ack_data, data, link) {
			isc_mem_put(
				mctx, data,
				STRUCT_FLEX_SIZE(data, bytes, data->length));
		}

		isc_mem_put(mctx, stream, sizeof(*stream));
	}

	ISC_LIST_FOREACH(conn->outgoing_stream_data, data, link) {
		isc_mem_put(mctx, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

#ifdef HAVE_OPENSSL_3
	if (conn->local_transport_params != NULL) {
		isc_mem_free(mctx, conn->local_transport_params);
	}

	ISC_LIST_FOREACH(conn->crypto_buffered_frames, frame, link) {
		isc_mem_put(mctx, frame,
			    STRUCT_FLEX_SIZE(frame, data, frame->len));
	}

	ISC_LIST_FOREACH(conn->crypto_awaiting_frames, frame, link) {
		isc_mem_put(mctx, frame,
			    STRUCT_FLEX_SIZE(frame, data, frame->len));
	}
#endif /* HAVE_OPENSSL_3 */

	isc_tls_free(&tls);

	ngtcp2_conn_del(conn->inner);

	isc_quic_router_unref(conn->router);

	isc_mem_put(mctx, conn, sizeof(*conn));
	isc_mem_unref(mctx);
}

static isc_result_t
derive_initial_secret(isc_region_t secret, isc_region_t self_secret,
		      isc_region_t peer_secret, uint32_t version,
		      bool is_server, const ngtcp2_cid *cid) {
	isc_region_t client_secret, server_secret;
	isc_constregion_t salt;
	isc_constregion_t initial_secret = {
		.base = secret.base,
		.length = secret.length,
	};

	switch (version) {
	case NGTCP2_PROTO_VER_V1:
		salt = (isc_constregion_t){
			.base = salt_v1,
			.length = sizeof(salt_v1),
		};
		break;
	case NGTCP2_PROTO_VER_V2:
		salt = (isc_constregion_t){
			.base = salt_v2,
			.length = sizeof(salt_v2),
		};
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	if (is_server) {
		client_secret = peer_secret;
		server_secret = self_secret;
	} else {
		client_secret = self_secret;
		server_secret = peer_secret;
	}

	RETERR(isc_crypto_hkdf_extract(
		secret, ISC_MD_SHA256,
		(isc_constregion_t){ cid->datalen, cid->data }, salt));

	RETERR(isc_crypto_hkdf_expand_label(
		client_secret, ISC_MD_SHA256, initial_secret,
		(isc_constregion_t){ sizeof(client_label), client_label }));

	RETERR(isc_crypto_hkdf_expand_label(
		server_secret, ISC_MD_SHA256, initial_secret,
		(isc_constregion_t){ sizeof(server_label), server_label }));

	return ISC_R_SUCCESS;
}

static isc_result_t
derive_packet_keys(const uint32_t version, isc_md_type_t md,
		   isc_constregion_t secret, isc_region_t key, isc_region_t iv,
		   isc_region_t hp) {
	isc_constregion_t key_label, iv_label, hp_label;
	isc_result_t result;

	switch (version) {
	case NGTCP2_PROTO_VER_V1:
		key_label = (isc_constregion_t){
			.base = key_label_v1,
			.length = sizeof(key_label_v1),
		};
		iv_label = (isc_constregion_t){
			.base = iv_label_v1,
			.length = sizeof(iv_label_v1),
		};
		hp_label = (isc_constregion_t){
			.base = hp_label_v1,
			.length = sizeof(hp_label_v1),
		};
		break;
	case NGTCP2_PROTO_VER_V2:
		key_label = (isc_constregion_t){
			.base = key_label_v2,
			.length = sizeof(key_label_v2),
		};
		iv_label = (isc_constregion_t){
			.base = iv_label_v2,
			.length = sizeof(iv_label_v2),
		};
		hp_label = (isc_constregion_t){
			.base = hp_label_v2,
			.length = sizeof(hp_label_v2),
		};
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	CHECK(isc_crypto_hkdf_expand_label(key, md, secret, key_label));
	CHECK(isc_crypto_hkdf_expand_label(iv, md, secret, iv_label));
	if (hp.base != NULL) {
		CHECK(isc_crypto_hkdf_expand_label(hp, md, secret, hp_label));
	}

	return ISC_R_SUCCESS;

cleanup:
	isc_safe_memwipe(key.base, key.length);
	isc_safe_memwipe(iv.base, iv.length);
	if (hp.base != NULL) {
		isc_safe_memwipe(hp.base, hp.length);
	}
	return result;
}

static isc_result_t
derive_traffic_update(isc_region_t next_secret, uint32_t version,
		      isc_md_type_t md, isc_constregion_t secret) {
	isc_constregion_t label;

	switch (version) {
	case NGTCP2_PROTO_VER_V1:
		label = (isc_constregion_t){
			.base = key_update_label_v1,
			.length = sizeof(key_update_label_v1),
		};
		break;
	case NGTCP2_PROTO_VER_V2:
		label = (isc_constregion_t){
			.base = key_update_label_v2,
			.length = sizeof(key_update_label_v2),
		};
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	return isc_crypto_hkdf_expand_label(next_secret, md, secret, label);
}

/**
 * Initial setup uses:
 * \li AES-128 for the header protection
 * \li AES-128-GCM for AEAD
 */
static isc_result_t
setup_initial_key(ngtcp2_conn *ngconn, const ngtcp2_cid *dcid) {
	uint8_t self_secret[QUIC_INITIAL_SECRET_LENGTH],
		self_key[QUIC_AES128_KEY_LENGTH],
		self_iv[ISC_CRYPTO_AEAD_MAX_NONCE_LENGTH],
		self_hp[QUIC_AES128_KEY_LENGTH];
	uint8_t peer_secret[QUIC_INITIAL_SECRET_LENGTH],
		peer_key[QUIC_AES128_KEY_LENGTH],
		peer_iv[ISC_CRYPTO_AEAD_MAX_NONCE_LENGTH],
		peer_hp[QUIC_AES128_KEY_LENGTH];
	ngtcp2_crypto_aead_ctx self_aead_ctx = { 0 }, peer_aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx self_hp_ctx = { 0 }, peer_hp_ctx = { 0 };
	isc_crypto_quic_hp_protect_t *hp = NULL;
	isc_crypto_aead_t *aead = NULL;
	isc_result_t result;
	uint32_t version;
	bool is_server;

	uint8_t initial_secret[QUIC_INITIAL_SECRET_LENGTH];

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	version = ngtcp2_conn_get_client_chosen_version2(ngconn);
	is_server = ngtcp2_conn_is_server2(ngconn);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	version = ngtcp2_conn_get_client_chosen_version(ngconn);
	is_server = ngtcp2_conn_is_server(ngconn);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	ngtcp2_conn_set_initial_crypto_ctx(ngconn,
					   &initial_aes128gcm_sha256_ctx);

	CHECK(derive_initial_secret(
		(isc_region_t){ sizeof(initial_secret), initial_secret },
		(isc_region_t){ sizeof(self_secret), self_secret },
		(isc_region_t){ sizeof(peer_secret), peer_secret }, version,
		is_server, dcid));

	CHECK(derive_packet_keys(
		version, ISC_MD_SHA256,
		(isc_constregion_t){ sizeof(self_secret), self_secret },
		(isc_region_t){ sizeof(self_key), self_key },
		(isc_region_t){ sizeof(self_iv), self_iv },
		(isc_region_t){ sizeof(self_hp), self_hp }));

	CHECK(derive_packet_keys(
		version, ISC_MD_SHA256,
		(isc_constregion_t){ sizeof(peer_secret), peer_secret },
		(isc_region_t){ sizeof(peer_key), peer_key },
		(isc_region_t){ sizeof(peer_iv), peer_iv },
		(isc_region_t){ sizeof(peer_hp), peer_hp }));

	CHECK(isc_crypto_aead_create(
		ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM,
		(isc_constregion_t){ sizeof(self_key), self_key },
		ISC_CRYPTO_AEAD_DIRECTION_SEAL, &aead));
	self_aead_ctx.native_handle = MOVE_OWNERSHIP(aead);

	CHECK(isc_crypto_aead_create(
		ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM,
		(isc_constregion_t){ sizeof(peer_key), peer_key },
		ISC_CRYPTO_AEAD_DIRECTION_OPEN, &aead));
	peer_aead_ctx.native_handle = MOVE_OWNERSHIP(aead);

	CHECK(isc_crypto_quic_hp_protect_create(
		isc_g_mctx,
		(isc_constregion_t){ isc_crypto_aes128gcm_key_length, self_hp },
		ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128, &hp));
	self_hp_ctx.native_handle = MOVE_OWNERSHIP(hp);

	CHECK(isc_crypto_quic_hp_protect_create(
		isc_g_mctx,
		(isc_constregion_t){ isc_crypto_aes128gcm_key_length, peer_hp },
		ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128, &hp));
	peer_hp_ctx.native_handle = MOVE_OWNERSHIP(hp);

	INSIST(ngtcp2_conn_install_initial_key(
		       ngconn, &peer_aead_ctx, peer_iv, &peer_hp_ctx,
		       &self_aead_ctx, self_iv, &self_hp_ctx,
		       isc_crypto_aes128gcm_nonce_length) == 0);

	return ISC_R_SUCCESS;

cleanup:
	if (hp != NULL) {
		isc_crypto_quic_hp_protect_destroy(&hp);
	}
	if (self_hp_ctx.native_handle != NULL) {
		hp = self_hp_ctx.native_handle;
		isc_crypto_quic_hp_protect_destroy(&hp);
	}
	if (peer_hp_ctx.native_handle != NULL) {
		hp = peer_hp_ctx.native_handle;
		isc_crypto_quic_hp_protect_destroy(&hp);
	}
	if (aead != NULL) {
		isc_crypto_aead_destroy(&aead);
	}
	if (self_aead_ctx.native_handle != NULL) {
		aead = self_aead_ctx.native_handle;
		isc_crypto_aead_destroy(&aead);
	}
	if (peer_aead_ctx.native_handle != NULL) {
		aead = peer_aead_ctx.native_handle;
		isc_crypto_aead_destroy(&aead);
	}
	return result;
}

static isc_result_t
pull_packet_invalid(isc_quic_conn_t *conn ISC_ATTR_UNUSED,
		    isc_region_t out ISC_ATTR_UNUSED,
		    size_t *written ISC_ATTR_UNUSED,
		    isc_sockaddr_t *from ISC_ATTR_UNUSED,
		    isc_sockaddr_t *to ISC_ATTR_UNUSED) {
	UNREACHABLE();
}

static isc_result_t
pull_packet_nodata(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		   isc_sockaddr_t *from, isc_sockaddr_t *to) {
	ngtcp2_path_storage ps;
	isc_result_t result;
	ngtcp2_ssize r;

	CHECK_STATE(conn, QUIC_CONN_STATE_HANDSHAKE, QUIC_CONN_STATE_CONNECTED);

	ngtcp2_path_storage_zero(&ps);

	r = ngtcp2_conn_writev_stream(conn->inner, &ps.path, NULL, out.base,
				      out.length, NULL,
				      NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL,
				      0, isc_time_monotonic());

	ngtcp2_conn_update_pkt_tx_time(conn->inner, isc_time_monotonic());

	if (r <= 0) {
		*written = 0;
		switch (r) {
		case 0:
			return ISC_R_UNEXPECTEDEND;
		case NGTCP2_ERR_NOMEM:
			return ISC_R_NOMEMORY;
		case NGTCP2_ERR_STREAM_NOT_FOUND:
			return ISC_R_NOTFOUND;
		case NGTCP2_ERR_STREAM_SHUT_WR:
			return ISC_R_SHUTTINGDOWN;
		case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
			return ISC_R_NOMORE;
		case NGTCP2_ERR_CALLBACK_FAILURE:
			return ISC_R_FAILURE;
		case NGTCP2_ERR_INVALID_ARGUMENT:
			return ISC_R_NOSPACE;
		case NGTCP2_ERR_STREAM_DATA_BLOCKED:
			return ISC_R_IOERROR;
		case NGTCP2_ERR_WRITE_MORE:
			UNREACHABLE();
		default:
			return ISC_R_FAILURE;
		}
	}

	if (from != NULL) {
		result = isc_sockaddr_fromsockaddr(
			from, (const struct sockaddr *)&ps.local_addrbuf);
		INSIST(result == ISC_R_SUCCESS);
	}

	if (to != NULL) {
		result = isc_sockaddr_fromsockaddr(
			to, (const struct sockaddr *)&ps.remote_addrbuf);
		INSIST(result == ISC_R_SUCCESS);
	}

	*written = r;

	return ISC_R_SUCCESS;
}

static isc_result_t
pull_packet_connected(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		      isc_sockaddr_t *from, isc_sockaddr_t *to) {
	isc__quic_stream_data_t *data;
	isc_nanosecs_t timestamp;
	ngtcp2_path_storage ps;
	isc__quic_stream_t *stream;
	isc_result_t result;
	ngtcp2_ssize r;
	int64_t stream_id;
	size_t total;
	ssize_t single;
	uint32_t flags;

	CHECK_STATE(conn, QUIC_CONN_STATE_CONNECTED);

	if (ISC_LIST_EMPTY(conn->outgoing_stream_data)) {
		return pull_packet_nodata(conn, out, written, from, to);
	}

	ngtcp2_path_storage_zero(&ps);

	timestamp = isc_time_monotonic();
	total = 0;
	flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	while (flags != NGTCP2_WRITE_STREAM_FLAG_NONE) {
		data = ISC_LIST_HEAD(conn->outgoing_stream_data);

		if (ISC_LIST_NEXT(data, link) == NULL) {
			flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
		}

		stream_id = data->stream_id;
		r = ngtcp2_conn_write_stream(conn->inner, &ps.path, NULL,
					     out.base, out.length, &single,
					     flags, stream_id, data->bytes,
					     data->length, timestamp);
		if (r < 0 && r != NGTCP2_ERR_WRITE_MORE) {
			ngtcp2_conn_update_pkt_tx_time(conn->inner,
						       isc_time_monotonic());

			switch (r) {
			case NGTCP2_ERR_NOMEM:
				return ISC_R_NOMEMORY;
			case NGTCP2_ERR_STREAM_SHUT_WR:
			case NGTCP2_ERR_STREAM_NOT_FOUND:
				ISC_LIST_UNLINK(conn->outgoing_stream_data,
						data, link);
				isc_mem_put(conn->mem.user_data, data,
					    STRUCT_FLEX_SIZE(data, bytes,
							     data->length));
				continue;
			case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
				return ISC_R_NOMORE;
			case NGTCP2_ERR_CALLBACK_FAILURE:
				return ISC_R_FAILURE;
			case NGTCP2_ERR_INVALID_ARGUMENT:
				return ISC_R_NOSPACE;
			case NGTCP2_ERR_STREAM_DATA_BLOCKED:
				return ISC_R_IOERROR;
			case NGTCP2_ERR_WRITE_MORE:
				UNREACHABLE();
			default:
				return ISC_R_FAILURE;
			}
		}

		ISC_LIST_UNLINK(conn->outgoing_stream_data, data, link);
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		stream = ngtcp2_conn_get_stream_user_data2(conn->inner,
							   stream_id);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		stream = ngtcp2_conn_get_stream_user_data(conn->inner,
							  stream_id);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		INSIST(stream != NULL);
		ISC_LIST_APPEND(stream->ack_data, data, link);

		if (r > 0) {
			total += r;
		}

		if (r == 0) {
			break;
		}
	}

	ngtcp2_conn_update_pkt_tx_time(conn->inner, isc_time_monotonic());

	if (total == 0) {
		*written = 0;
		return ISC_R_IGNORE;
	}

	if (from != NULL) {
		result = isc_sockaddr_fromsockaddr(
			from, (const struct sockaddr *)&ps.local_addrbuf);
		INSIST(result == ISC_R_SUCCESS);
	}

	if (to != NULL) {
		result = isc_sockaddr_fromsockaddr(
			to, (const struct sockaddr *)&ps.remote_addrbuf);
		INSIST(result == ISC_R_SUCCESS);
	}

	*written = total;

	return ISC_R_SUCCESS;
}

static isc_result_t
pull_packet_closed(isc_quic_conn_t *conn, isc_region_t out, size_t *written,
		   isc_sockaddr_t *from, isc_sockaddr_t *to) {
	ngtcp2_path_storage ps;
	isc_result_t result;
	ngtcp2_ccerr ccerr = { 0 };
	ngtcp2_ssize r;

	CHECK_STATE(conn, QUIC_CONN_STATE_CLOSED);

	ngtcp2_path_storage_zero(&ps);

	r = ngtcp2_conn_write_connection_close(conn->inner, &ps.path, NULL,
					       out.base, out.length, &ccerr,
					       isc_time_monotonic());
	if (r <= 0) {
		*written = 0;
		switch (r) {
		case 0:
			return ISC_R_UNEXPECTEDEND;
		case NGTCP2_ERR_NOMEM:
			return ISC_R_NOMEMORY;
		case NGTCP2_ERR_NOBUF:
			return ISC_R_NOSPACE;
		case NGTCP2_ERR_INVALID_STATE:
			return ISC_R_UNEXPECTED;
		case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
			return ISC_R_NOMORE;
		case NGTCP2_ERR_CALLBACK_FAILURE:
			return ISC_R_FAILURE;
		default:
			UNREACHABLE();
		}
	}

	if (from != NULL) {
		result = isc_sockaddr_fromsockaddr(
			from, (const struct sockaddr *)&ps.local_addrbuf);
		INSIST(result == ISC_R_SUCCESS);
	}

	if (to != NULL) {
		result = isc_sockaddr_fromsockaddr(
			to, (const struct sockaddr *)&ps.remote_addrbuf);
		INSIST(result == ISC_R_SUCCESS);
	}

	*written = r;

	return ISC_R_SUCCESS;
}

static isc_result_t
pull_packet_terminated(isc_quic_conn_t *conn ISC_ATTR_UNUSED,
		       isc_region_t out ISC_ATTR_UNUSED, size_t *written,
		       isc_sockaddr_t *from ISC_ATTR_UNUSED,
		       isc_sockaddr_t *to ISC_ATTR_UNUSED) {
	*written = 0;
	return ISC_R_COMPLETE;
}

static void
log_printf(void *user_data ISC_ATTR_UNUSED, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	isc_log_vwrite(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER,
		       ISC_LOG_DEBUG(99), fmt, ap);
	va_end(ap);
}

static int
client_initial_cb(ngtcp2_conn *ngconn, void *user_data) {
	const ngtcp2_cid *dcid;
	isc_quic_conn_t *conn;
	isc_result_t result;
	isc_tls_t *tls;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	tls = ngtcp2_conn_get_tls_native_handle2(ngconn);
	dcid = ngtcp2_conn_get_dcid2(ngconn);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	tls = ngtcp2_conn_get_tls_native_handle(ngconn);
	dcid = ngtcp2_conn_get_dcid(ngconn);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	conn = user_data;

	result = setup_initial_key(ngconn, dcid);
	if (result != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (isc__quic_set_local_transport_params(conn, tls) != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	result = isc__quic_do_tls(conn, tls, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
				  (isc_constregion_t){ 0, NULL });
	if (result != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int
recv_client_initial_cb(ngtcp2_conn *ngconn, const ngtcp2_cid *dcid,
		       void *user_data ISC_ATTR_UNUSED) {
	if (setup_initial_key(ngconn, dcid) != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int
recv_crypto_data_cb(ngtcp2_conn *ngconn, ngtcp2_encryption_level nglevel,
		    uint64_t offset ISC_ATTR_UNUSED, const uint8_t *data,
		    size_t len, void *user_data) {
	isc_quic_conn_t *conn = user_data;
	isc_tls_t *tls;
	int r;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	tls = ngtcp2_conn_get_tls_native_handle2(ngconn);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	tls = ngtcp2_conn_get_tls_native_handle(ngconn);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	if (isc__quic_do_tls(conn, tls, nglevel,
			     (isc_constregion_t){ len, data }) != ISC_R_SUCCESS)
	{
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		r = ngtcp2_conn_get_tls_error2(ngconn);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		r = ngtcp2_conn_get_tls_error(ngconn);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		if (r == 0) {
			return NGTCP2_ERR_CRYPTO;
		}
		return r;
	}

	return 0;
}

static int
handshake_completed_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, void *user_data) {
	isc_quic_conn_t *conn = user_data;

	CHECK_STATE(conn, QUIC_CONN_STATE_HANDSHAKE);
	conn->state = QUIC_CONN_STATE_CONNECTED;

	if (conn->cb != NULL && conn->cb->handshake_completed != NULL) {
		conn->cb->handshake_completed(conn->cbarg);
	}

	return 0;
}

static int
encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *ngaead,
	   const ngtcp2_crypto_aead_ctx *ngctx, const uint8_t *plaintext,
	   size_t plaintextlen, const uint8_t *nonceptr, size_t noncelen,
	   const uint8_t *aad, size_t aadlen) {
	size_t out_sealed_len;

	if (isc_crypto_aead_seal(
		    ngctx->native_handle,
		    (isc_constregion_t){ noncelen, nonceptr },
		    (isc_constregion_t){ plaintextlen, plaintext },
		    (isc_region_t){ plaintextlen + ngaead->max_overhead, dest },
		    &out_sealed_len,
		    (isc_constregion_t){ aadlen, aad }) != ISC_R_SUCCESS)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int
decrypt_cb(uint8_t *out_ptr, const ngtcp2_crypto_aead *ngaead,
	   const ngtcp2_crypto_aead_ctx *ngctx, const uint8_t *ciphertext_ptr,
	   size_t ciphertext_len, const uint8_t *nonce_ptr, size_t nonce_len,
	   const uint8_t *aad_ptr, size_t aad_len) {
	size_t out_opened_len;

	if (isc_crypto_aead_open(
		    ngctx->native_handle,
		    (isc_constregion_t){ nonce_len, nonce_ptr },
		    (isc_constregion_t){ ciphertext_len, ciphertext_ptr },
		    (isc_region_t){ ciphertext_len - ngaead->max_overhead,
				    out_ptr },
		    &out_opened_len,
		    (isc_constregion_t){ aad_len, aad_ptr }) != ISC_R_SUCCESS)
	{
		return NGTCP2_ERR_DECRYPT;
	}

	return 0;
}

static int
hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *nghp ISC_ATTR_UNUSED,
	   const ngtcp2_crypto_cipher_ctx *ngctx, const uint8_t *sample) {
	isc_crypto_quic_hp_protect_t *hp = ngctx->native_handle;

	if (isc_crypto_quic_hp_protect_mask(hp, dest, sample) != ISC_R_SUCCESS)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int
recv_stream_data_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint32_t flags,
		    int64_t stream_id, uint64_t offset ISC_ATTR_UNUSED,
		    const uint8_t *data, size_t datalen, void *user_data,
		    void *stream_user_data) {
	isc_quic_conn_t *conn = user_data;
	isc__quic_stream_t *stream = stream_user_data;
	const isc_quic_stream_data_info_t info = {
		.final = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0x00,
		.zerortt = (flags & NGTCP2_STREAM_DATA_FLAG_0RTT) != 0x00,
		.stream_id = stream_id,
		.stream_data = stream->data,
	};

	if (conn->cb != NULL && conn->cb->data_read != NULL) {
		if (conn->cb->data_read(conn, conn->cbarg, info,
					(isc_constregion_t){ datalen, data }) !=
		    ISC_R_SUCCESS)
		{
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int
acked_stream_data_offset_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			    int64_t stream_id, uint64_t offset,
			    uint64_t datalen, void *user_data,
			    void *stream_user_data) {
	isc__quic_stream_t *stream = stream_user_data;
	isc_quic_conn_t *conn = user_data;
	uint64_t last_acked_offset = stream->last_acked_offset;

	INSIST(stream->id == stream_id);

	ISC_LIST_FOREACH(stream->ack_data, data, link) {
		if (last_acked_offset + data->length > offset + datalen) {
			break;
		}
		last_acked_offset += data->length;
		ISC_LIST_UNLINK(stream->ack_data, data, link);
		isc_mem_put(conn->mem.user_data, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	stream->last_acked_offset = offset;

	return 0;
}

static int
stream_open_cb(ngtcp2_conn *ngconn, int64_t stream_id, void *user_data) {
	isc_quic_conn_t *conn = user_data;
	isc__quic_stream_t *stream;
	isc_result_t result;

	stream = isc_mem_get(conn->mem.user_data, sizeof(*stream));
	*stream = (isc__quic_stream_t){
		.id = stream_id,
		.ack_data = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
	};

	if (conn->cb != NULL && conn->cb->stream_opened != NULL) {
		result = conn->cb->stream_opened(conn, conn->cbarg,
						 &stream->data, stream_id);
		if (result != ISC_R_SUCCESS) {
			isc_mem_put(conn->mem.user_data, stream,
				    sizeof(*stream));
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	if (ngtcp2_conn_set_stream_user_data(ngconn, stream_id, stream) != 0) {
		isc_mem_put(conn->mem.user_data, stream, sizeof(*stream));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	ISC_LIST_APPEND(conn->streams, stream, link);

	return 0;
}

#ifndef NGTCP2_CALLBACKS_V5
static int
stream_close_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint32_t flags,
		int64_t stream_id, uint64_t app_error_code, void *user_data,
		void *stream_user_data) {
	isc_quic_application_error_kind_t kind;
	isc__quic_stream_t *stream = stream_user_data;
	isc_quic_conn_t *conn = user_data;
	isc_result_t result;

	ISC_LIST_FOREACH(stream->ack_data, data, link) {
		ISC_LIST_DEQUEUE(stream->ack_data, data, link);
		isc_mem_put(conn->mem.user_data, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	if (conn->cb != NULL && conn->cb->stream_closed != NULL) {
		if (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) {
			kind = ISC_QUIC_APPLICATION_ERROR_UNKNOWN;
		} else {
			kind = ISC_QUIC_APPLICATION_ERROR_NONE;
		}

		result = conn->cb->stream_closed(
			conn, conn->cbarg, stream_id, stream->data, kind,
			app_error_code, app_error_code);
		if (result != ISC_R_SUCCESS) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}
#endif /* !NGTCP2_CALLBACKS_V5 */

static int
recv_retry_cb(ngtcp2_conn *ngconn, const ngtcp2_pkt_hd *header,
	      void *user_data ISC_ATTR_UNUSED) {
	if (setup_initial_key(ngconn, &header->dcid) != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static void
rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx ISC_ATTR_UNUSED) {
	isc_random_buf(dest, destlen);
}

#ifndef NGTCP2_CALLBACKS_V3
static int
get_new_connection_id_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, ngtcp2_cid *ngcid,
			 uint8_t *token, size_t cidlen, void *user_data) {
	isc_quic_conn_t *conn = user_data;
	uint8_t buffer[ISC_QUIC_CID_MAX_LENGTH];
	isc_constregion_t cid = { cidlen, buffer };
	isc_result_t result;

	for (;;) {
		isc_random_buf(buffer, sizeof(buffer));
		result = isc_quic_router_add_cid(conn->router, cid, isc_tid(),
						 conn);
		if (result == ISC_R_SUCCESS) {
			isc_quic_router_stateless_reset_from_cid(conn->router,
								 cid, token);
			result = isc_quic_router_add_stateless_reset(
				conn->router, token, isc_tid(), conn);
			/*
			 * Failure probability is $2^{-128}$
			 */
			INSIST(result == ISC_R_SUCCESS);
			ngcid->datalen = cidlen;
			memmove(ngcid->data, buffer, cidlen);
			return 0;
		}
	}

	UNREACHABLE();
}
#endif /* NGTCP2_CALLBACKS_V3 */

static int
remove_connection_id_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			const ngtcp2_cid *ngcid, void *user_data) {
	isc_constregion_t cid = { ngcid->datalen, ngcid->data };
	isc_quic_conn_t *conn = user_data;

	if (isc_quic_router_del_cid(conn->router, cid) != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int
update_key_cb(ngtcp2_conn *ngconn, uint8_t *rx_secret, uint8_t *tx_secret,
	      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
	      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
	      const uint8_t *current_rx_secret,
	      const uint8_t *current_tx_secret, size_t len,
	      void *user_data ISC_ATTR_UNUSED) {
	uint8_t rx_key[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH],
		tx_key[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH];
	const ngtcp2_crypto_ctx *ctx;
	isc_crypto_aead_algorithm_t aead_algorithm;
	isc_crypto_aead_t *aead = NULL;
	isc_result_t result;
	isc_md_type_t md;
	uint32_t version;
	size_t nonce_len, key_len;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	ctx = ngtcp2_conn_get_crypto_ctx2(ngconn);
	version = ngtcp2_conn_get_client_chosen_version2(ngconn);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	ctx = ngtcp2_conn_get_crypto_ctx(ngconn);
	version = ngtcp2_conn_get_client_chosen_version(ngconn);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	md = (uintptr_t)(void *)ctx->md.native_handle;
	INSIST(md < ISC_MD_MAX);

	aead_algorithm = (uintptr_t)(void *)ctx->aead.native_handle;
	switch (aead_algorithm) {
	case ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM:
		nonce_len = isc_crypto_aes128gcm_nonce_length;
		key_len = isc_crypto_aes128gcm_key_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM:
		nonce_len = isc_crypto_aes256gcm_nonce_length;
		key_len = isc_crypto_aes256gcm_key_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305:
		nonce_len = isc_crypto_chacha20poly1305_nonce_length;
		key_len = isc_crypto_chacha20poly1305_key_length;
		break;
	default:
		UNREACHABLE();
	}

	CHECK(derive_traffic_update(
		(isc_region_t){ len, rx_secret }, version, md,
		(isc_constregion_t){ len, current_rx_secret }));

	CHECK(derive_packet_keys(
		version, md, (isc_constregion_t){ len, rx_secret },
		(isc_region_t){ key_len, rx_key },
		(isc_region_t){ nonce_len, rx_iv }, (isc_region_t){ 0, NULL }));

	CHECK(isc_crypto_aead_create(aead_algorithm,
				     (isc_constregion_t){ key_len, rx_key },
				     ISC_CRYPTO_AEAD_DIRECTION_OPEN, &aead));
	rx_aead_ctx->native_handle = MOVE_OWNERSHIP(aead);

	CHECK(derive_traffic_update(
		(isc_region_t){ len, tx_secret }, version, md,
		(isc_constregion_t){ len, current_tx_secret }));

	CHECK(derive_packet_keys(
		version, md, (isc_constregion_t){ len, tx_secret },
		(isc_region_t){ key_len, tx_key },
		(isc_region_t){ nonce_len, tx_iv }, (isc_region_t){ 0, NULL }));

	CHECK(isc_crypto_aead_create(aead_algorithm,
				     (isc_constregion_t){ key_len, tx_key },
				     ISC_CRYPTO_AEAD_DIRECTION_SEAL, &aead));
	tx_aead_ctx->native_handle = MOVE_OWNERSHIP(aead);

	return 0;

cleanup:
	if (aead != NULL) {
		isc_crypto_aead_destroy(&aead);
	}

	if (rx_aead_ctx->native_handle != NULL) {
		aead = MOVE_OWNERSHIP(rx_aead_ctx->native_handle);
		isc_crypto_aead_destroy(&aead);
	}

	return NGTCP2_ERR_CALLBACK_FAILURE;
}

static void
delete_crypto_aead_ctx_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			  ngtcp2_crypto_aead_ctx *ngctx,
			  void *user_data ISC_ATTR_UNUSED) {
	isc_crypto_aead_t *aead = MOVE_OWNERSHIP(ngctx->native_handle);
	isc_crypto_aead_destroy(&aead);
}

static void
delete_crypto_cipher_ctx_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			    ngtcp2_crypto_cipher_ctx *ngctx,
			    void *user_data ISC_ATTR_UNUSED) {
	isc_crypto_quic_hp_protect_t *hp = MOVE_OWNERSHIP(ngctx->native_handle);
	isc_crypto_quic_hp_protect_destroy(&hp);
}

#ifndef NGTCP2_CALLBACKS_V3
static int
get_path_challenge_data_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint8_t *data,
			   void *user_data ISC_ATTR_UNUSED) {
	isc_random_buf(data, NGTCP2_PATH_CHALLENGE_DATALEN);
	return 0;
}
#endif /* NGTCP2_CALLBACKS_V3 */

static int
version_negotiation_cb(ngtcp2_conn *ngconn, uint32_t ngversion,
		       const ngtcp2_cid *client_dcid,
		       void *user_data ISC_ATTR_UNUSED) {
	uint8_t self_secret[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH],
		self_key[QUIC_AES128_KEY_LENGTH],
		self_iv[ISC_CRYPTO_AEAD_MAX_NONCE_LENGTH],
		self_hp[QUIC_AES128_KEY_LENGTH];
	uint8_t peer_secret[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH],
		peer_key[QUIC_AES128_KEY_LENGTH],
		peer_iv[ISC_CRYPTO_AEAD_MAX_NONCE_LENGTH],
		peer_hp[QUIC_AES128_KEY_LENGTH];
	uint8_t initial_secret[QUIC_INITIAL_SECRET_LENGTH];

	ngtcp2_crypto_aead_ctx self_aead_ctx = { 0 }, peer_aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx self_hp_ctx = { 0 }, peer_hp_ctx = { 0 };
	isc_crypto_quic_hp_protect_t *hp = NULL;
	isc_crypto_aead_t *aead = NULL;
	isc_result_t result;
	bool is_server;
	int r;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	is_server = ngtcp2_conn_is_server2(ngconn);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	is_server = ngtcp2_conn_is_server(ngconn);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	CHECK(derive_initial_secret(
		(isc_region_t){ sizeof(initial_secret), initial_secret },
		(isc_region_t){ sizeof(self_secret), self_secret },
		(isc_region_t){ sizeof(peer_secret), peer_secret }, ngversion,
		is_server, client_dcid));

	CHECK(derive_packet_keys(
		ngversion, ISC_MD_SHA256,
		(isc_constregion_t){ sizeof(self_secret), self_secret },
		(isc_region_t){ sizeof(self_key), self_key },
		(isc_region_t){ sizeof(self_iv), self_iv },
		(isc_region_t){ sizeof(self_hp), self_hp }));

	CHECK(isc_crypto_aead_create(
		ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM,
		(isc_constregion_t){ sizeof(self_key), self_key },
		ISC_CRYPTO_AEAD_DIRECTION_SEAL, &aead));
	self_aead_ctx.native_handle = MOVE_OWNERSHIP(aead);

	CHECK(isc_crypto_quic_hp_protect_create(
		isc_g_mctx, (isc_constregion_t){ sizeof(self_hp), self_hp },
		ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128, &hp));
	self_hp_ctx.native_handle = MOVE_OWNERSHIP(hp);

	CHECK(derive_packet_keys(
		ngversion, ISC_MD_SHA256,
		(isc_constregion_t){ sizeof(peer_secret), peer_secret },
		(isc_region_t){ sizeof(peer_key), peer_key },
		(isc_region_t){ sizeof(peer_iv), peer_iv },
		(isc_region_t){ sizeof(peer_hp), peer_hp }));

	CHECK(isc_crypto_aead_create(
		ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM,
		(isc_constregion_t){ sizeof(peer_key), peer_key },
		ISC_CRYPTO_AEAD_DIRECTION_SEAL, &aead));
	peer_aead_ctx.native_handle = MOVE_OWNERSHIP(aead);

	CHECK(isc_crypto_quic_hp_protect_create(
		isc_g_mctx, (isc_constregion_t){ sizeof(peer_hp), peer_hp },
		ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128, &hp));
	peer_hp_ctx.native_handle = MOVE_OWNERSHIP(hp);

	r = ngtcp2_conn_install_vneg_initial_key(
		ngconn, ngversion, &peer_aead_ctx, peer_iv, &peer_hp_ctx,
		&self_aead_ctx, self_iv, &self_hp_ctx,
		isc_crypto_aes128gcm_nonce_length);
	if (r != 0) {
		goto cleanup;
	}

	return 0;

cleanup:
	if (hp != NULL) {
		isc_crypto_quic_hp_protect_destroy(&hp);
	}
	if (self_hp_ctx.native_handle != NULL) {
		hp = self_hp_ctx.native_handle;
		isc_crypto_quic_hp_protect_destroy(&hp);
	}
	if (peer_hp_ctx.native_handle != NULL) {
		hp = peer_hp_ctx.native_handle;
		isc_crypto_quic_hp_protect_destroy(&hp);
	}
	if (aead != NULL) {
		isc_crypto_aead_destroy(&aead);
	}
	if (self_aead_ctx.native_handle != NULL) {
		aead = self_aead_ctx.native_handle;
		isc_crypto_aead_destroy(&aead);
	}
	if (peer_aead_ctx.native_handle != NULL) {
		aead = peer_aead_ctx.native_handle;
		isc_crypto_aead_destroy(&aead);
	}

	return NGTCP2_ERR_CALLBACK_FAILURE;
}

#ifdef NGTCP2_CALLBACKS_V3
static int
get_new_connection_id2_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			  ngtcp2_cid *ngcid,
			  ngtcp2_stateless_reset_token *token, size_t cidlen,
			  void *user_data) {
	isc_quic_conn_t *conn = user_data;
	uint8_t buffer[ISC_QUIC_CID_MAX_LENGTH];
	isc_constregion_t cid = { cidlen, buffer };
	isc_result_t result;

	for (;;) {
		isc_random_buf(buffer, sizeof(buffer));
		result = isc_quic_router_add_cid(conn->router, cid, isc_tid(),
						 conn);
		if (result == ISC_R_SUCCESS) {
			isc_quic_router_stateless_reset_from_cid(
				conn->router, cid, token->data);
			result = isc_quic_router_add_stateless_reset(
				conn->router, token->data, isc_tid(), conn);
			/*
			 * Failure probability is $2^{-128}$
			 */
			INSIST(result == ISC_R_SUCCESS);
			ngcid->datalen = cidlen;
			memmove(ngcid->data, buffer, cidlen);
			return 0;
		}
	}

	UNREACHABLE();
}

static int
dcid_status2_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
		ngtcp2_connection_id_status_type type,
		uint64_t seq ISC_ATTR_UNUSED, const ngtcp2_cid *ngcid,
		const ngtcp2_stateless_reset_token *ngtoken, void *user_data) {
	isc_constregion_t cid = { ngcid->datalen, ngcid->data };
	isc_quic_conn_t *conn = user_data;
	isc_result_t result;
	isc_tid_t tid = isc_tid();

	switch (type) {
	case NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE:
		result = isc_quic_router_add_cid(conn->router, cid, tid, conn);
		if (result == ISC_R_SUCCESS && ngtoken != NULL) {
			result = isc_quic_router_add_stateless_reset(
				conn->router, ngtoken->data, tid, conn);
			if (result != ISC_R_SUCCESS) {
				(void)isc_quic_router_del_cid(conn->router,
							      cid);
			}
		}
		break;
	case NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE:
		result = isc_quic_router_del_cid(conn->router, cid);
		if (result == ISC_R_SUCCESS && ngtoken != NULL) {
			result = isc_quic_router_del_stateless_reset(
				conn->router, ngtoken->data);
			/* TODO(aydin) do we need to re-add the CID? */
		}
		break;
	default:
		/*
		 * Other values might be added in the future so it is best to
		 * not crash.
		 *
		 * https://nghttp2.org/ngtcp2/types.html#c.ngtcp2_connection_id_status2
		 */
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (result != ISC_R_SUCCESS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int
get_path_challenge_data2_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			    ngtcp2_path_challenge_data *data,
			    void *user_data ISC_ATTR_UNUSED) {
	isc_random_buf(data->data, NGTCP2_PATH_CHALLENGE_DATALEN);
	return 0;
}

#endif /* NGTCP2_CALLBACKS_V3 */

#ifdef NGTCP2_CALLBACKS_V4
static int
recv_stop_sending_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
		     int64_t stream_id ISC_ATTR_UNUSED,
		     uint64_t app_error_code ISC_ATTR_UNUSED, void *user_data,
		     void *stream_user_data) {
	isc__quic_stream_t *stream = stream_user_data;
	isc_quic_conn_t *conn = user_data;
	isc_mem_t *mctx = conn->mem.user_data;

	ISC_LIST_UNLINK(conn->streams, stream, link);
	ISC_LIST_FOREACH(stream->ack_data, data, link) {
		ISC_LIST_DEQUEUE(stream->ack_data, data, link);
		isc_mem_put(mctx, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	isc_mem_put(mctx, stream, sizeof(*stream));

	return 0;
}
#endif /* NGTCP2_CALLBACKS_V4 */

#ifdef NGTCP2_CALLBACKS_V5
static int
stream_close2_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint32_t flags,
		 int64_t stream_id, uint64_t rx_app_error_code,
		 uint64_t tx_app_error_code, void *user_data,
		 void *stream_user_data) {
	isc_quic_application_error_kind_t kind;
	isc__quic_stream_t *stream = stream_user_data;
	isc_quic_conn_t *conn = user_data;
	isc_result_t result;
	bool rx, tx;

	ISC_LIST_FOREACH(stream->ack_data, data, link) {
		ISC_LIST_DEQUEUE(stream->ack_data, data, link);
		isc_mem_put(conn->mem.user_data, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	if (conn->cb != NULL && conn->cb->stream_closed != NULL) {
		rx = flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET;
		tx = flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET;

		if (rx && tx) {
			kind = ISC_QUIC_APPLICATION_ERROR_RX_AND_TX;
		} else if (rx) {
			kind = ISC_QUIC_APPLICATION_ERROR_RX_ONLY;
		} else if (tx) {
			kind = ISC_QUIC_APPLICATION_ERROR_TX_ONLY;
		} else {
			kind = ISC_QUIC_APPLICATION_ERROR_NONE;
		}

		result = conn->cb->stream_closed(
			conn, conn->cbarg, stream_id, stream->data, kind,
			rx_app_error_code, tx_app_error_code);
		if (result != ISC_R_SUCCESS) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}
#endif /* NGTCP2_CALLBACKS_V5 */

static void *
quic_malloc(size_t size, void *user_data) {
	return isc_mem_allocate(user_data, size);
}

static void
quic_free(void *ptr, void *user_data) {
	if (ptr != NULL) {
		isc_mem_free(user_data, ptr);
	}
}

static void *
quic_calloc(size_t nmemb, size_t size, void *user_data) {
	return isc_mem_callocate(user_data, nmemb, size);
}

static void *
quic_realloc(void *ptr, size_t size, void *user_data) {
	return isc_mem_reallocate(user_data, ptr, size);
}

static void
common_transport_params(ngtcp2_transport_params *params) {
	ngtcp2_transport_params_default(params);
	params->initial_max_stream_data_bidi_local = initial_max_stream_data;
	params->initial_max_stream_data_bidi_remote = initial_max_stream_data;
	params->initial_max_streams_bidi = initial_max_streams_bidi;
	params->initial_max_streams_uni = initial_max_streams_uni;
	params->initial_max_data = initial_max_data;
	params->disable_active_migration = 1;
	params->grease_quic_bit = 1;
}

static void
common_settings(ngtcp2_settings *settings) {
	ngtcp2_settings_default(settings);

	settings->cc_algo = NGTCP2_CC_ALGO_BBR;
	settings->max_tx_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
	settings->preferred_versions = preferred_versions;
	settings->preferred_versionslen = ARRAY_SIZE(preferred_versions);
	/*
	 * libuv needs to expose relevant socket options for pmtud to
	 * work correctly [1].
	 * https://github.com/nodejs/node/blob/e6ef4774c202245e8daaa3cc48a44f3f38b99429/src/quic/session.cc#L348-L351
	 */
	settings->no_pmtud = 1;

	if (isc_log_wouldlog(ISC_LOG_DEBUG(99))) {
		settings->log_printf = log_printf;
	}
}

isc_result_t
isc__quic_setup_read_key(isc_quic_conn_t *conn, bool is_server,
			 ngtcp2_encryption_level nglevel,
			 isc_constregion_t secret) {
	isc_crypto_quic_hp_protect_algorithm_t hp_algorithm;
	isc_crypto_quic_hp_protect_t *hp = NULL;
	isc_crypto_aead_algorithm_t aead_algorithm;
	ngtcp2_crypto_cipher_ctx ng_hp_ctx = { 0 };
	const ngtcp2_crypto_ctx *ngctx = NULL;
	ngtcp2_crypto_aead_ctx ng_aead_ctx = { 0 };
	isc_crypto_aead_t *aead = NULL;
	const SSL_CIPHER *cipher;
	isc_md_type_t md;
	isc_result_t result;
	isc_tls_t *tls;
	uint32_t version;
	size_t key_len, nonce_len;
	uint8_t key_buffer[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH],
		nonce_buffer[ISC_CRYPTO_AEAD_MAX_NONCE_LENGTH],
		hp_buffer[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH];

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	tls = ngtcp2_conn_get_tls_native_handle2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	tls = ngtcp2_conn_get_tls_native_handle(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	switch (nglevel) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		if (!is_server) {
			return ISC_R_SUCCESS;
		}

		cipher = SSL_get_current_cipher(tls);
		if (cipher == NULL) {
			return ISC_R_FAILURE;
		}

		switch (SSL_CIPHER_get_id(cipher)) {
		case TLS1_3_CK_AES_128_GCM_SHA256:
			ngctx = &initial_aes128gcm_sha256_ctx;
			break;
		case TLS1_3_CK_AES_256_GCM_SHA384:
			ngctx = &initial_aes256_sha384_ctx;
			break;
		case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
			ngctx = &initial_chacha20poly1305_sha256_ctx;
			break;
		default:
			UNREACHABLE();
		}

		ngtcp2_conn_set_0rtt_crypto_ctx(conn->inner, ngctx);
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		ngctx = ngtcp2_conn_get_0rtt_crypto_ctx2(conn->inner);
		version = ngtcp2_conn_get_client_chosen_version2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		ngctx = ngtcp2_conn_get_0rtt_crypto_ctx(conn->inner);
		version = ngtcp2_conn_get_client_chosen_version(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		version = ngtcp2_conn_get_negotiated_version2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		version = ngtcp2_conn_get_negotiated_version(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		if (is_server && (version == 0)) {
			RETERR(isc__quic_set_remote_transport_params(conn,
								     tls));
		}
		FALLTHROUGH;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		version = ngtcp2_conn_get_negotiated_version2(conn->inner);
		ngctx = ngtcp2_conn_get_crypto_ctx2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		version = ngtcp2_conn_get_negotiated_version(conn->inner);
		ngctx = ngtcp2_conn_get_crypto_ctx(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		if (ngctx->aead.native_handle == NULL) {
			cipher = SSL_get_current_cipher(tls);
			if (cipher == NULL) {
				CLEANUP(ISC_R_FAILURE);
			}

			switch (SSL_CIPHER_get_id(cipher)) {
			case TLS1_3_CK_AES_128_GCM_SHA256:
				ngctx = &initial_aes128gcm_sha256_ctx;
				break;
			case TLS1_3_CK_AES_256_GCM_SHA384:
				ngctx = &initial_aes256_sha384_ctx;
				break;
			case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
				ngctx = &initial_chacha20poly1305_sha256_ctx;
				break;
			default:
				UNREACHABLE();
			}

			ngtcp2_conn_set_crypto_ctx(conn->inner, ngctx);
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
			ngctx = ngtcp2_conn_get_crypto_ctx2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
			ngctx = ngtcp2_conn_get_crypto_ctx(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		}
		break;
	default:
		UNREACHABLE();
	}

	aead_algorithm = (uintptr_t)(void *)ngctx->aead.native_handle;
	switch (aead_algorithm) {
	case ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM:
		hp_algorithm = ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128;
		key_len = isc_crypto_aes128gcm_key_length;
		nonce_len = isc_crypto_aes128gcm_nonce_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM:
		hp_algorithm = ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES256;
		key_len = isc_crypto_aes256gcm_key_length;
		nonce_len = isc_crypto_aes256gcm_nonce_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305:
		hp_algorithm = ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_CHACHA20;
		key_len = isc_crypto_chacha20poly1305_key_length;
		nonce_len = isc_crypto_chacha20poly1305_nonce_length;
		break;
	default:
		UNREACHABLE();
	}

	md = (uintptr_t)(void *)ngctx->md.native_handle;
	hp_algorithm = (uintptr_t)(void *)ngctx->hp.native_handle;

	CHECK(derive_packet_keys(version, md, secret,
				 (isc_region_t){ key_len, key_buffer },
				 (isc_region_t){ nonce_len, nonce_buffer },
				 (isc_region_t){ key_len, hp_buffer }));

	CHECK(isc_crypto_aead_create(aead_algorithm,
				     (isc_constregion_t){ key_len, key_buffer },
				     ISC_CRYPTO_AEAD_DIRECTION_OPEN, &aead));
	ng_aead_ctx = (ngtcp2_crypto_aead_ctx){
		.native_handle = MOVE_OWNERSHIP(aead),
	};

	CHECK(isc_crypto_quic_hp_protect_create(
		isc_g_mctx, (isc_constregion_t){ key_len, hp_buffer },
		hp_algorithm, &hp));
	ng_hp_ctx = (ngtcp2_crypto_cipher_ctx){
		.native_handle = MOVE_OWNERSHIP(hp),
	};

	switch (nglevel) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		if (ngtcp2_conn_install_0rtt_key(conn->inner, &ng_aead_ctx,
						 nonce_buffer, nonce_len,
						 &ng_hp_ctx) != 0)
		{
			CLEANUP(ISC_R_FAILURE);
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		if (ngtcp2_conn_install_rx_handshake_key(
			    conn->inner, &ng_aead_ctx, nonce_buffer, nonce_len,
			    &ng_hp_ctx) != 0)
		{
			CLEANUP(ISC_R_FAILURE);
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		if (!is_server) {
			CHECK(isc__quic_set_remote_transport_params(conn, tls));
		}

		if (ngtcp2_conn_install_rx_key(conn->inner, secret.base,
					       secret.length, &ng_aead_ctx,
					       nonce_buffer, nonce_len,
					       &ng_hp_ctx) != 0)
		{
			CLEANUP(ISC_R_FAILURE);
		}
		break;
	default:
		UNREACHABLE();
	}

	isc_safe_memwipe(key_buffer, sizeof(key_buffer));
	isc_safe_memwipe(nonce_buffer, sizeof(nonce_buffer));
	isc_safe_memwipe(hp_buffer, sizeof(hp_buffer));
	return ISC_R_SUCCESS;

cleanup:
	if (aead != NULL) {
		isc_crypto_aead_destroy(&aead);
	}

	if (ng_aead_ctx.native_handle != NULL) {
		aead = ng_aead_ctx.native_handle;
		isc_crypto_aead_destroy(&aead);
	}

	if (hp != NULL) {
		isc_crypto_quic_hp_protect_destroy(&hp);
	}

	if (ng_hp_ctx.native_handle != NULL) {
		hp = ng_hp_ctx.native_handle;
		isc_crypto_quic_hp_protect_destroy(&hp);
	}

	isc_safe_memwipe(key_buffer, sizeof(key_buffer));
	isc_safe_memwipe(nonce_buffer, sizeof(nonce_buffer));
	isc_safe_memwipe(hp_buffer, sizeof(hp_buffer));

	return result;
}

isc_result_t
isc__quic_setup_write_key(isc_quic_conn_t *conn, bool is_server,
			  ngtcp2_encryption_level nglevel,
			  isc_constregion_t secret) {
	isc_crypto_quic_hp_protect_algorithm_t hp_algorithm;
	isc_crypto_aead_algorithm_t aead_algorithm;
	isc_crypto_quic_hp_protect_t *hp = NULL;
	ngtcp2_crypto_cipher_ctx ng_hp_ctx = { 0 };
	const ngtcp2_crypto_ctx *ngctx;
	ngtcp2_crypto_aead_ctx ng_aead_ctx = { 0 };
	isc_crypto_aead_t *aead = NULL;
	const SSL_CIPHER *cipher;
	isc_md_type_t md;
	isc_result_t result;
	isc_tls_t *tls;
	uint32_t version;
	size_t key_len, nonce_len;
	uint8_t key_buffer[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH],
		nonce_buffer[ISC_CRYPTO_AEAD_MAX_NONCE_LENGTH],
		hp_buffer[ISC_CRYPTO_AEAD_MAX_KEY_LENGTH];

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	tls = ngtcp2_conn_get_tls_native_handle2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	tls = ngtcp2_conn_get_tls_native_handle(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	switch (nglevel) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		if (!is_server) {
			return ISC_R_SUCCESS;
		}

		cipher = SSL_get_current_cipher(tls);
		if (cipher == NULL) {
			return ISC_R_FAILURE;
		}

		switch (SSL_CIPHER_get_id(cipher)) {
		case TLS1_3_CK_AES_128_GCM_SHA256:
			ngctx = &initial_aes128gcm_sha256_ctx;
			break;
		case TLS1_3_CK_AES_256_GCM_SHA384:
			ngctx = &initial_aes256_sha384_ctx;
			break;
		case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
			ngctx = &initial_chacha20poly1305_sha256_ctx;
			break;
		default:
			UNREACHABLE();
		}

		ngtcp2_conn_set_0rtt_crypto_ctx(conn->inner, ngctx);
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		ngctx = ngtcp2_conn_get_0rtt_crypto_ctx2(conn->inner);
		version = ngtcp2_conn_get_client_chosen_version2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		ngctx = ngtcp2_conn_get_0rtt_crypto_ctx(conn->inner);
		version = ngtcp2_conn_get_client_chosen_version(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		version = ngtcp2_conn_get_negotiated_version2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		version = ngtcp2_conn_get_negotiated_version(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

		if (is_server && (version == 0)) {
			RETERR(isc__quic_set_remote_transport_params(conn,
								     tls));
		}
		FALLTHROUGH;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
		version = ngtcp2_conn_get_negotiated_version2(conn->inner);
		ngctx = ngtcp2_conn_get_crypto_ctx2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
		version = ngtcp2_conn_get_negotiated_version(conn->inner);
		ngctx = ngtcp2_conn_get_crypto_ctx(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		if (ngctx->aead.native_handle == NULL) {
			cipher = SSL_get_current_cipher(tls);
			if (cipher == NULL) {
				CLEANUP(ISC_R_FAILURE);
			}

			switch (SSL_CIPHER_get_id(cipher)) {
			case TLS1_3_CK_AES_128_GCM_SHA256:
				ngctx = &initial_aes128gcm_sha256_ctx;
				break;
			case TLS1_3_CK_AES_256_GCM_SHA384:
				ngctx = &initial_aes256_sha384_ctx;
				break;
			case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
				ngctx = &initial_chacha20poly1305_sha256_ctx;
				break;
			default:
				UNREACHABLE();
			}

			ngtcp2_conn_set_crypto_ctx(conn->inner, ngctx);
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
			ngctx = ngtcp2_conn_get_crypto_ctx2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
			ngctx = ngtcp2_conn_get_crypto_ctx(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
		}
		break;
	default:
		UNREACHABLE();
	}

	aead_algorithm = (uintptr_t)(void *)ngctx->aead.native_handle;
	switch (aead_algorithm) {
	case ISC_CRYPTO_AEAD_ALGORITHM_AES128GCM:
		hp_algorithm = ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES128;
		key_len = isc_crypto_aes128gcm_key_length;
		nonce_len = isc_crypto_aes128gcm_nonce_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_AES256GCM:
		hp_algorithm = ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_AES256;
		key_len = isc_crypto_aes256gcm_key_length;
		nonce_len = isc_crypto_aes256gcm_nonce_length;
		break;
	case ISC_CRYPTO_AEAD_ALGORITHM_CHACHA20POLY1305:
		hp_algorithm = ISC_CRYPTO_QUIC_HP_PROTECT_ALGORITHM_CHACHA20;
		key_len = isc_crypto_chacha20poly1305_key_length;
		nonce_len = isc_crypto_chacha20poly1305_nonce_length;
		break;
	default:
		UNREACHABLE();
	}

	md = (uintptr_t)(void *)ngctx->md.native_handle;
	hp_algorithm = (uintptr_t)(void *)ngctx->hp.native_handle;

	CHECK(derive_packet_keys(version, md, secret,
				 (isc_region_t){ key_len, key_buffer },
				 (isc_region_t){ nonce_len, nonce_buffer },
				 (isc_region_t){ key_len, hp_buffer }));

	CHECK(isc_crypto_aead_create(aead_algorithm,
				     (isc_constregion_t){ key_len, key_buffer },
				     ISC_CRYPTO_AEAD_DIRECTION_SEAL, &aead));
	ng_aead_ctx = (ngtcp2_crypto_aead_ctx){
		.native_handle = MOVE_OWNERSHIP(aead),
	};

	CHECK(isc_crypto_quic_hp_protect_create(
		isc_g_mctx, (isc_constregion_t){ key_len, hp_buffer },
		hp_algorithm, &hp));
	ng_hp_ctx = (ngtcp2_crypto_cipher_ctx){
		.native_handle = MOVE_OWNERSHIP(hp),
	};

	switch (nglevel) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		if (ngtcp2_conn_install_0rtt_key(conn->inner, &ng_aead_ctx,
						 nonce_buffer, nonce_len,
						 &ng_hp_ctx) != 0)
		{
			CLEANUP(ISC_R_FAILURE);
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		if (ngtcp2_conn_install_tx_handshake_key(
			    conn->inner, &ng_aead_ctx, nonce_buffer, nonce_len,
			    &ng_hp_ctx) != 0)
		{
			CLEANUP(ISC_R_FAILURE);
		}

		if (is_server) {
			CHECK(isc__quic_set_local_transport_params(conn, tls));
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		if (ngtcp2_conn_install_tx_key(conn->inner, secret.base,
					       secret.length, &ng_aead_ctx,
					       nonce_buffer, nonce_len,
					       &ng_hp_ctx) != 0)
		{
			CLEANUP(ISC_R_FAILURE);
		}
		break;
	default:
		UNREACHABLE();
	}

	isc_safe_memwipe(key_buffer, sizeof(key_buffer));
	isc_safe_memwipe(nonce_buffer, sizeof(nonce_buffer));
	isc_safe_memwipe(hp_buffer, sizeof(hp_buffer));
	return ISC_R_SUCCESS;

cleanup:
	if (aead != NULL) {
		isc_crypto_aead_destroy(&aead);
	}

	if (ng_aead_ctx.native_handle != NULL) {
		aead = ng_aead_ctx.native_handle;
		isc_crypto_aead_destroy(&aead);
	}

	if (hp != NULL) {
		isc_crypto_quic_hp_protect_destroy(&hp);
	}

	if (ng_hp_ctx.native_handle != NULL) {
		hp = ng_hp_ctx.native_handle;
		isc_crypto_quic_hp_protect_destroy(&hp);
	}

	isc_safe_memwipe(key_buffer, sizeof(key_buffer));
	isc_safe_memwipe(nonce_buffer, sizeof(nonce_buffer));
	isc_safe_memwipe(hp_buffer, sizeof(hp_buffer));

	return result;
}

ISC_REFCOUNT_IMPL(isc_quic_conn, destroy);

isc_result_t
isc_quic_conn_client_create(isc_mem_t *mctx, isc_quic_router_t *router,
			    const isc_quic_conn_callbacks_t *callbacks,
			    void *callback_arg,
			    const isc_quic_conn_options_t *options,
			    isc_quic_version_t version, const char *sni,
			    const isc_sockaddr_t *local,
			    const isc_sockaddr_t *peer,
			    isc_quic_conn_t **connp) {
	ngtcp2_transport_params transport_params;
	isc_quic_conn_t *conn = NULL;
	ngtcp2_settings settings;
	isc_result_t result;
	ngtcp2_path path;
	ngtcp2_cid dcid, scid;
	isc_tls_t *tls = NULL;
	uint32_t ngversion;
	int r;

	REQUIRE(connp != NULL && *connp == NULL);
	REQUIRE(options != NULL &&
		options->handshake_timeout != isc_quic_timestamp_invalid &&
		options->idle_timeout != isc_quic_timestamp_invalid &&
		options->alpn.length <= sizeof(conn->alpn.data));
	REQUIRE(version != ISC_QUIC_VERSION_INVALID &&
		version != ISC_QUIC_VERSION_UNKNOWN &&
		version < ISC_QUIC_VERSION__MAX);

	switch (version) {
	case ISC_QUIC_VERSION_V1:
		ngversion = NGTCP2_PROTO_VER_V1;
		break;
	case ISC_QUIC_VERSION_V2:
		ngversion = NGTCP2_PROTO_VER_V2;
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	ERR_set_mark();

	path = (ngtcp2_path){
		.local = { (ngtcp2_sockaddr *)&local->type.sa, local->length },
		.remote = { (ngtcp2_sockaddr *)&peer->type.sa, peer->length },
	};

	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	isc_random_buf(dcid.data, NGTCP2_MIN_INITIAL_DCIDLEN);
	scid.datalen = ISC_QUIC_CID_MAX_LENGTH;
	isc_random_buf(scid.data, ISC_QUIC_CID_MAX_LENGTH);

	common_settings(&settings);
	settings.initial_ts = isc_time_monotonic();
	settings.handshake_timeout = options->handshake_timeout != 0
					     ? options->handshake_timeout
					     : UINT64_MAX;

	common_transport_params(&transport_params);
	transport_params.max_idle_timeout = options->idle_timeout;

	tls = isc_tls_create(options->tlsctx);
	if (tls == NULL) {
		CLEANUP(ISC_R_TLSERROR);
	}

	conn = isc_mem_get(mctx, sizeof(*conn));
	*conn = (isc_quic_conn_t){
		.magic = conn_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.state = QUIC_CONN_STATE_HANDSHAKE,
		.router = isc_quic_router_ref(router),
		.alpn = { .len = options->alpn.length },
		.streams = ISC_LIST_INITIALIZER,
		.outgoing_stream_data = ISC_LIST_INITIALIZER,
		.cb = callbacks,
		.cbarg = callback_arg,
#ifdef HAVE_OPENSSL_3
		.level = NGTCP2_ENCRYPTION_LEVEL_INITIAL,
		.crypto_awaiting_frames = ISC_LIST_INITIALIZER,
		.crypto_buffered_frames = ISC_LIST_INITIALIZER,
#endif /* HAVE_OPENSSL_3 */
		.mem = { .user_data = isc_mem_ref(mctx),
			 .malloc = quic_malloc,
			 .free = quic_free,
			 .calloc = quic_calloc,
			 .realloc = quic_realloc },
	};

	memmove(conn->alpn.data, options->alpn.base, conn->alpn.len);

	r = ngtcp2_conn_client_new(&conn->inner, &dcid, &scid, &path, ngversion,
				   &client_cb, &settings, &transport_params,
				   &conn->mem, conn);
	switch (r) {
	case 0:
		break;
	case NGTCP2_ERR_NOMEM:
		CLEANUP(ISC_R_NOMEMORY);
	default:
		CLEANUP(ISC_R_FAILURE);
	}

	SSL_set_connect_state(tls);
	SSL_set_tlsext_host_name(tls, sni);
	if (SSL_set_alpn_protos(tls, conn->alpn.data, conn->alpn.len) != 0) {
		CLEANUP(ISC_R_TLSERROR);
	}
	CHECK(isc__quic_setup_tls(tls, conn));
	ngtcp2_conn_set_tls_native_handle(conn->inner, tls);
	tls = NULL;

	*connp = MOVE_OWNERSHIP(conn);

	result = ISC_R_SUCCESS;

cleanup:
	if (tls != NULL) {
		isc_tls_free(&tls);
	}

	if (conn != NULL) {
		isc_quic_router_unref(router);
		isc_mem_put(mctx, conn, sizeof(*conn));
		isc_mem_unref(mctx);
	}

	ERR_pop_to_mark();
	return result;
}

/*
 * original scid: SCID of the client
 *
 * initial dcid : DCID of the initial server
 *
 * scid : Generated SCID of the _server_
 *
 * dcid : The destination CID from the _server's_ perspective which is the
 * initial_scid.
 */
isc_result_t
isc_quic_conn_server_create(
	isc_mem_t *mctx, isc_quic_router_t *router,
	const isc_quic_conn_callbacks_t *callbacks, void *callback_arg,
	const isc_quic_conn_options_t *options,
	isc_quic_version_t initial_version, isc_constregion_t initial_dcid,
	isc_constregion_t initial_scid, const isc_sockaddr_t *local,
	const isc_sockaddr_t *peer, isc_quic_conn_t **connp) {
	ngtcp2_transport_params transport_params;
	isc_quic_conn_t *conn = NULL;
	ngtcp2_settings settings;
	isc_result_t result;
	ngtcp2_path path;
	ngtcp2_cid dcid, scid;
	isc_tls_t *tls = NULL;
	uint32_t version;
	int r;

	REQUIRE(connp != NULL && *connp == NULL);
	REQUIRE(options != NULL &&
		options->handshake_timeout != isc_quic_timestamp_invalid &&
		options->idle_timeout != isc_quic_timestamp_invalid &&
		options->alpn.base != NULL &&
		options->alpn.length <= sizeof(conn->alpn.data));
	REQUIRE(initial_version == ISC_QUIC_VERSION_V1 ||
		initial_version == ISC_QUIC_VERSION_V2);

	ERR_set_mark();

	path = (ngtcp2_path){
		.local = { (ngtcp2_sockaddr *)&local->type.sa, local->length },
		.remote = { (ngtcp2_sockaddr *)&peer->type.sa, peer->length },
	};

	/*
	 * When confused, remember that from a connection side, itself is always
	 * the SCID and the peer is always using the DCID.
	 *
	 * So, a clients SCID is the server's DCID and vice versa.
	 */

	/*
	 * Generate a new source CID from **our** perspective.
	 */
	scid.datalen = ISC_QUIC_CID_MAX_LENGTH;
	isc_random_buf(scid.data, scid.datalen);

	/*
	 * Destination CID to be used for now is the source CID of the
	 * **client** in the initial packet.
	 */
	ngtcp2_cid_init(&dcid, initial_scid.base, initial_scid.length);

	common_transport_params(&transport_params);

	/*
	 * original_dcid is what the client used as the destination CID from its
	 * own perspective.
	 */
	ngtcp2_cid_init(&transport_params.original_dcid, initial_dcid.base,
			initial_dcid.length);
	transport_params.max_idle_timeout = options->idle_timeout;
	transport_params.original_dcid_present = 1;

	common_settings(&settings);
	settings.initial_ts = isc_time_monotonic();
	settings.handshake_timeout = options->handshake_timeout != 0
					     ? options->handshake_timeout
					     : UINT64_MAX;

	tls = isc_tls_create(options->tlsctx);
	if (tls == NULL) {
		CLEANUP(ISC_R_TLSERROR);
	}

	conn = isc_mem_get(mctx, sizeof(*conn));
	*conn = (isc_quic_conn_t){
		.magic = conn_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.state = QUIC_CONN_STATE_HANDSHAKE,
		.router = isc_quic_router_ref(router),
		.alpn = { .len = options->alpn.length },
		.streams = ISC_LIST_INITIALIZER,
		.outgoing_stream_data = ISC_LIST_INITIALIZER,
		.cb = callbacks,
		.cbarg = callback_arg,
#ifdef HAVE_OPENSSL_3
		.level = NGTCP2_ENCRYPTION_LEVEL_INITIAL,
		.crypto_awaiting_frames = ISC_LIST_INITIALIZER,
		.crypto_buffered_frames = ISC_LIST_INITIALIZER,
#endif /* HAVE_OPENSSL_3 */
		.mem = { .user_data = isc_mem_ref(mctx),
			 .malloc = quic_malloc,
			 .free = quic_free,
			 .calloc = quic_calloc,
			 .realloc = quic_realloc },
	};

	memmove(conn->alpn.data, options->alpn.base, conn->alpn.len);

	switch (initial_version) {
	case ISC_QUIC_VERSION_V1:
		version = NGTCP2_PROTO_VER_V1;
		break;
	case ISC_QUIC_VERSION_V2:
		version = NGTCP2_PROTO_VER_V2;
		break;
	default:
		UNREACHABLE();
	}

	r = ngtcp2_conn_server_new(&conn->inner, &dcid, &scid, &path, version,
				   &server_cb, &settings, &transport_params,
				   &conn->mem, conn);
	switch (r) {
	case 0:
		break;
	case NGTCP2_ERR_NOMEM:
		CLEANUP(ISC_R_NOMEMORY);
	default:
		CLEANUP(ISC_R_FAILURE);
	}

	SSL_set_accept_state(tls);
	CHECK(isc__quic_setup_tls(tls, conn));
	ngtcp2_conn_set_tls_native_handle(conn->inner, tls);
	tls = NULL;

	/*
	 * Probability is 2^{-160}, even these checks are actually not worth it
	 * the slightest.
	 */
	result = isc_quic_router_add_cid(router, initial_dcid, isc_tid(), conn);
	INSIST(result == ISC_R_SUCCESS);

	result = isc_quic_router_add_cid(
		router, (isc_constregion_t){ scid.datalen, scid.data },
		isc_tid(), conn);
	INSIST(result == ISC_R_SUCCESS);

	*connp = MOVE_OWNERSHIP(conn);

cleanup:
	if (tls != NULL) {
		isc_tls_free(&tls);
	}

	if (conn != NULL) {
		isc_quic_router_unref(router);
		isc_mem_put(mctx, conn, sizeof(*conn));
		isc_mem_unref(mctx);
	}

	ERR_pop_to_mark();
	return result;
}

void *
isc_quic_conn_get_callback_arg(const isc_quic_conn_t *conn) {
	REQUIRE(VALID_CONNECTION(conn));

	return conn->cbarg;
}

isc_result_t
isc_quic_conn_shutdown(isc_quic_conn_t *conn) {
#if NGTCP2_VERSION_NUM >= 0x011600 /* 1.22.0 */
	ngtcp2_cid_token2 *token;
#else
	ngtcp2_cid_token *token;
#endif
	isc_constregion_t cid;
	isc_result_t result;
	ngtcp2_cid *ngcid;
	isc_mem_t *mctx;
	uint8_t reset[ISC_QUIC_STATELESS_TOKEN_LENGTH];
	size_t i, len;

	REQUIRE(VALID_CONNECTION(conn));

	if (conn->state == QUIC_CONN_STATE_CLOSED ||
	    conn->state == QUIC_CONN_STATE_TERMINATED)
	{
		return ISC_R_SHUTTINGDOWN;
	}

	conn->state = QUIC_CONN_STATE_CLOSED;

	mctx = conn->mem.user_data;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	len = ngtcp2_conn_get_scid2(conn->inner, NULL);
	ngcid = isc_mem_cget(mctx, len, sizeof(*ngcid));
	ngtcp2_conn_get_scid2(conn->inner, ngcid);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	len = ngtcp2_conn_get_scid(conn->inner, NULL);
	ngcid = isc_mem_cget(mctx, len, sizeof(*ngcid));
	ngtcp2_conn_get_scid(conn->inner, ngcid);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
	for (i = 0; i < len; i++) {
		cid = (isc_constregion_t){ ngcid[i].datalen, ngcid[i].data };
		result = isc_quic_router_del_cid(conn->router, cid);
		if (result == ISC_R_SUCCESS) {
			(void)isc_quic_router_stateless_reset_from_cid(
				conn->router, cid, reset);
			(void)isc_quic_router_del_stateless_reset(conn->router,
								  reset);
		}
	}
	isc_mem_cput(mctx, ngcid, len, sizeof(*ngcid));

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	len = ngtcp2_conn_get_active_dcid3(conn->inner, NULL);
	token = isc_mem_cget(mctx, len, sizeof(*token));
	ngtcp2_conn_get_active_dcid3(conn->inner, token);
#elif NGTCP2_VERSION_NUM >= 0x011600 /* 1.22.0 */
	len = ngtcp2_conn_get_active_dcid2(conn->inner, NULL);
	token = isc_mem_cget(mctx, len, sizeof(*token));
	ngtcp2_conn_get_active_dcid2(conn->inner, token);
#else
	len = ngtcp2_conn_get_active_dcid(conn->inner, NULL);
	token = isc_mem_cget(mctx, len, sizeof(*token));
	ngtcp2_conn_get_active_dcid(conn->inner, token);
#endif
	for (i = 0; i < len; i++) {
		if (token[i].token_present != 0) {
#if NGTCP2_VERSION_NUM >= 0x011600 /* 1.22.0 */
			(void)isc_quic_router_del_stateless_reset(
				conn->router, token[i].token.data);
#else  /* NGTCP2_VERSION_NUM >= 0x011600 */
			(void)isc_quic_router_del_stateless_reset(
				conn->router, token[i].token);
#endif /* NGTCP2_VERSION_NUM >= 0x011600 */
		}
	}
	isc_mem_cput(mctx, token, len, sizeof(*token));

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	ngcid = UNCONST(ngtcp2_conn_get_dcid2(conn->inner));
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	ngcid = UNCONST(ngtcp2_conn_get_dcid(conn->inner));
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
	if (ngcid->datalen != 0) {
		cid = (isc_constregion_t){ ngcid->datalen, ngcid->data };
		(void)isc_quic_router_del_cid(conn->router, cid);
	}

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	ngcid = UNCONST(ngtcp2_conn_get_client_initial_dcid2(conn->inner));
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	ngcid = UNCONST(ngtcp2_conn_get_client_initial_dcid(conn->inner));
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */
	if (ngcid->datalen != 0) {
		cid = (isc_constregion_t){ ngcid->datalen, ngcid->data };
		(void)isc_quic_router_del_cid(conn->router, cid);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_conn_handle_expiry(isc_quic_conn_t *conn) {
	int r;

	REQUIRE(VALID_CONNECTION(conn));

	r = ngtcp2_conn_handle_expiry(conn->inner, isc_time_monotonic());
	if (r >= 0) {
		return ISC_R_SUCCESS;
	} else if (r == NGTCP2_ERR_IDLE_CLOSE) {
		conn->state = QUIC_CONN_STATE_TERMINATED;
		return ISC_R_TIMEDOUT;
	}

	isc_quic_conn_shutdown(conn);

	return ISC_R_CANCELED;
}

isc_result_t
isc_quic_conn_pull_packet(isc_quic_conn_t *conn, isc_region_t out,
			  size_t *written, isc_sockaddr_t *from,
			  isc_sockaddr_t *to) {
	REQUIRE(VALID_CONNECTION(conn));
	REQUIRE(out.base != NULL && out.length > 0 && written != NULL);

	REQUIRE(conn->state < ARRAY_SIZE(state_table));

	return state_table[conn->state].pull_packet(conn, out, written, from,
						    to);
}

isc_result_t
isc_quic_conn_push_packet(isc_quic_conn_t *conn, isc_constregion_t packet,
			  isc_sockaddr_t *local, isc_sockaddr_t *peer) {
	ngtcp2_path path;

	REQUIRE(VALID_CONNECTION(conn));
	REQUIRE(packet.base != NULL);

	path = (ngtcp2_path){
		.local = { (ngtcp2_sockaddr *)&local->type.sa, local->length },
		.remote = { (ngtcp2_sockaddr *)&peer->type.sa, peer->length },
	};

	switch (ngtcp2_conn_read_pkt(conn->inner, &path, NULL, packet.base,
				     packet.length, isc_time_monotonic()))
	{
	case 0:
		return ISC_R_SUCCESS;
	case NGTCP2_ERR_DROP_CONN:
		return ISC_R_NOMORE;
	case NGTCP2_ERR_DRAINING:
		return ISC_R_CANCELED;
	case NGTCP2_ERR_CLOSING:
		return ISC_R_CANCELED;
	case NGTCP2_ERR_CRYPTO:
		return ISC_R_CRYPTOFAILURE;
	case NGTCP2_ERR_RETRY:
		/* TODO(aydin) address validation */
		FALLTHROUGH;
	default:
		return ISC_R_FAILURE;
	}
}

isc_result_t
isc_quic_conn_shutdown_stream(isc_quic_conn_t *conn, int64_t stream_id,
			      uint64_t application_code) {
	REQUIRE(VALID_CONNECTION(conn));
	REQUIRE(stream_id >= 0);

	switch (ngtcp2_conn_shutdown_stream(conn->inner, 0x00, stream_id,
					    application_code))
	{
	case 0:
		return ISC_R_SUCCESS;
	case NGTCP2_ERR_NOMEM:
		return ISC_R_NOMEMORY;
	default:
		return ISC_R_FAILURE;
	}
}

isc_nanosecs_t
isc_quic_conn_next_expiry_time(isc_quic_conn_t *conn) {
	REQUIRE(VALID_CONNECTION(conn));

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	return ngtcp2_conn_get_expiry2(conn->inner);
#else
	return ngtcp2_conn_get_expiry(conn->inner);
#endif
}

isc_result_t
isc_quic_conn_open_bidi_stream(isc_quic_conn_t *conn, int64_t *stream_idp,
			       void *user_data) {
	isc__quic_stream_t *stream;
	int r;

	REQUIRE(VALID_CONNECTION(conn));
	REQUIRE(stream_idp != NULL && user_data != NULL);

	CHECK_STATE(conn, QUIC_CONN_STATE_CONNECTED);

	stream = isc_mem_get(conn->mem.user_data, sizeof(*stream));

	/*
	 * To get the stream ID for `isc__quic_stream_t`, we need to pass the
	 * `isc__quic_stream_t` pointer to `ngtcp2_conn_open_bidi_stream`.
	 *
	 * Thus, we initialize the values of `stream` after this call.
	 */
	r = ngtcp2_conn_open_bidi_stream(conn->inner, stream_idp, stream);
	if (r != 0) {
		isc_mem_put(conn->mem.user_data, stream, sizeof(*stream));
		switch (r) {
		case NGTCP2_ERR_NOMEM:
			return ISC_R_NOMEMORY;
		case NGTCP2_ERR_STREAM_ID_BLOCKED:
			return ISC_R_IOERROR;
		default:
			UNREACHABLE();
		}
	}

	*stream = (isc__quic_stream_t){
		.id = *stream_idp,
		.data = user_data,
		.ack_data = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
	};

	ISC_LIST_APPEND(conn->streams, stream, link);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_conn_push_stream_data(isc_quic_conn_t *conn, int64_t stream_id,
			       const uint8_t *data, size_t len) {
	isc__quic_stream_data_t *outgoing;

	REQUIRE(VALID_CONNECTION(conn));
	REQUIRE(data != NULL && len != 0);

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	if (ngtcp2_conn_get_stream_user_data2(conn->inner, stream_id) == NULL) {
		return ISC_R_NOTFOUND;
	}
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	if (ngtcp2_conn_get_stream_user_data(conn->inner, stream_id) == NULL) {
		return ISC_R_NOTFOUND;
	}
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	outgoing = isc_mem_get(conn->mem.user_data,
			       STRUCT_FLEX_SIZE(outgoing, bytes, len));
	*outgoing = (isc__quic_stream_data_t){
		.stream_id = stream_id,
		.length = len,
		.link = ISC_LINK_INITIALIZER,
	};
	memmove(outgoing->bytes, data, len);

	ISC_LIST_APPEND(conn->outgoing_stream_data, outgoing, link);

	return ISC_R_SUCCESS;
}
