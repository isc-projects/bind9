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

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <nghttp2/nghttp2.h>
#include <signal.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/base64.h>
#include <isc/netmgr.h>
#include <isc/print.h>
#include <isc/tls.h>
#include <isc/url.h>

#include "netmgr-int.h"

#define AUTHEXTRA 7

#define MAX_DNS_MESSAGE_SIZE (UINT16_MAX)

#define HEADER_MATCH(header, name, namelen)   \
	(((namelen) == sizeof(header) - 1) && \
	 (strncasecmp((header), (const char *)(name), (namelen)) == 0))

typedef struct isc_nm_http2_response_status {
	size_t code;
	size_t content_length;
	bool content_type_valid;
} isc_nm_http2_response_status_t;

typedef struct http2_client_stream {
	isc_nm_recv_cb_t read_cb;
	void *read_cbarg;

	isc_nm_cb_t connect_cb;
	void *connect_cbarg;

	char *uri;
	isc_url_parser_t up;

	char *authority;
	size_t authoritylen;
	char *path;

	uint8_t rbuf[MAX_DNS_MESSAGE_SIZE];
	size_t rbufsize;

	size_t pathlen;
	int32_t stream_id;

	bool post; /* POST or GET */
	isc_region_t postdata;
	size_t postdata_pos;
	char *GET_path;
	size_t GET_path_len;

	isc_nm_http2_response_status_t response_status;

	LINK(struct http2_client_stream) link;
} http2_client_stream_t;

#define HTTP2_SESSION_MAGIC    ISC_MAGIC('H', '2', 'S', 'S')
#define VALID_HTTP2_SESSION(t) ISC_MAGIC_VALID(t, HTTP2_SESSION_MAGIC)

struct isc_nm_http2_session {
	unsigned int magic;
	isc_mem_t *mctx;
	bool sending;
	bool closed;
	bool reading;

	nghttp2_session *ngsession;
	bool client;

	ISC_LIST(http2_client_stream_t) cstreams;
	ISC_LIST(isc_nmsocket_h2_t) sstreams;
#ifdef NETMGR_TRACE
	size_t sstreams_count;
#endif /* NETMGR_TRACE */

	isc_nmhandle_t *handle;
	isc_nmsocket_t *serversocket;

	isc_region_t r;
	uint8_t buf[MAX_DNS_MESSAGE_SIZE];
	size_t bufsize;

	bool ssl_ctx_created;
	SSL_CTX *ssl_ctx;
};

typedef enum isc_http2_error_responses {
	ISC_HTTP_ERROR_SUCCESS,		       /* 200 */
	ISC_HTTP_ERROR_NOT_FOUND,	       /* 404 */
	ISC_HTTP_ERROR_PAYLOAD_TOO_LARGE,      /* 413 */
	ISC_HTTP_ERROR_URI_TOO_LONG,	       /* 414 */
	ISC_HTTP_ERROR_UNSUPPORTED_MEDIA_TYPE, /* 415 */
	ISC_HTTP_ERROR_BAD_REQUEST,	       /* 400 */
	ISC_HTTP_ERROR_NOT_IMPLEMENTED,	       /* 501 */
	ISC_HTTP_ERROR_GENERIC,		       /* 500 Internal Server Error */
	ISC_HTTP_ERROR_MAX
} isc_http2_error_responses_t;

static void
http2_do_bio(isc_nm_http2_session_t *session);

static void
failed_httpstream_read_cb(isc_nmsocket_t *sock, isc_result_t result,
			  isc_nm_http2_session_t *session);

static void
failed_read_cb(isc_result_t result, isc_nm_http2_session_t *session);

static int
server_send_error_response(const isc_http2_error_responses_t error,
			   nghttp2_session *ngsession, isc_nmsocket_t *socket);

static bool
inactive(isc_nmsocket_t *sock) {
	return (!isc__nmsocket_active(sock) || atomic_load(&sock->closing) ||
		atomic_load(&sock->mgr->closing) ||
		(sock->server != NULL && !isc__nmsocket_active(sock->server)));
}

static http2_client_stream_t *
find_http2_client_stream(int32_t stream_id, isc_nm_http2_session_t *session) {
	http2_client_stream_t *cstream = NULL;
	REQUIRE(VALID_HTTP2_SESSION(session));

	for (cstream = ISC_LIST_HEAD(session->cstreams); cstream != NULL;
	     cstream = ISC_LIST_NEXT(cstream, link))
	{
		if (cstream->stream_id == stream_id) {
			break;
		}
	}

	return (cstream);
}

static isc_result_t
get_http2_client_stream(isc_mem_t *mctx, http2_client_stream_t **streamp,
			const char *uri) {
	http2_client_stream_t *stream = NULL;
	isc_result_t result;

	REQUIRE(streamp != NULL && *streamp == NULL);
	REQUIRE(uri != NULL);

	stream = isc_mem_get(mctx, sizeof(http2_client_stream_t));
	*stream = (http2_client_stream_t){ .stream_id = -1, .rbufsize = 0 };

	stream->uri = isc_mem_strdup(mctx, uri);

	result = isc_url_parse(stream->uri, strlen(stream->uri), 0,
			       &stream->up);
	if (result != ISC_R_SUCCESS) {
		isc_mem_free(mctx, stream->uri);
		isc_mem_put(mctx, stream, sizeof(http2_client_stream_t));
		return (result);
	}

	stream->authoritylen = stream->up.field_data[ISC_UF_HOST].len;
	stream->authority = isc_mem_get(mctx, stream->authoritylen + AUTHEXTRA);
	memmove(stream->authority, &uri[stream->up.field_data[ISC_UF_HOST].off],
		stream->up.field_data[ISC_UF_HOST].len);

	if (stream->up.field_set & (1 << ISC_UF_PORT)) {
		stream->authoritylen += (size_t)snprintf(
			stream->authority +
				stream->up.field_data[ISC_UF_HOST].len,
			AUTHEXTRA, ":%u", stream->up.port);
	}

	/* If we don't have path in URI, we use "/" as path. */
	stream->pathlen = 1;
	if (stream->up.field_set & (1 << ISC_UF_PATH)) {
		stream->pathlen = stream->up.field_data[ISC_UF_PATH].len;
	}
	if (stream->up.field_set & (1 << ISC_UF_QUERY)) {
		/* +1 for '?' character */
		stream->pathlen +=
			(size_t)(stream->up.field_data[ISC_UF_QUERY].len + 1);
	}

	stream->path = isc_mem_get(mctx, stream->pathlen);
	if (stream->up.field_set & (1 << ISC_UF_PATH)) {
		memmove(stream->path,
			&uri[stream->up.field_data[ISC_UF_PATH].off],
			stream->up.field_data[ISC_UF_PATH].len);
	} else {
		stream->path[0] = '/';
	}

	if (stream->up.field_set & (1 << ISC_UF_QUERY)) {
		stream->path[stream->pathlen -
			     stream->up.field_data[ISC_UF_QUERY].len - 1] = '?';
		memmove(stream->path + stream->pathlen -
				stream->up.field_data[ISC_UF_QUERY].len,
			&uri[stream->up.field_data[ISC_UF_QUERY].off],
			stream->up.field_data[ISC_UF_QUERY].len);
	}

	stream->GET_path = NULL;
	stream->GET_path_len = 0;
	stream->postdata = (isc_region_t){ .base = NULL, .length = 0 };
	memset(&stream->response_status, 0, sizeof(stream->response_status));

	*streamp = stream;

	return (ISC_R_SUCCESS);
}

static void
put_http2_client_stream(isc_mem_t *mctx, http2_client_stream_t *stream) {
	isc_mem_put(mctx, stream->path, stream->pathlen);
	isc_mem_put(mctx, stream->authority,
		    stream->up.field_data[ISC_UF_HOST].len + AUTHEXTRA);
	isc_mem_free(mctx, stream->uri);
	if (stream->GET_path != NULL) {
		isc_mem_free(mctx, stream->GET_path);
		stream->GET_path = NULL;
		stream->GET_path_len = 0;
	}
	if (stream->postdata.base != NULL) {
		isc_mem_put(mctx, stream->postdata.base,
			    stream->postdata.length);
	}
	isc_mem_put(mctx, stream, sizeof(http2_client_stream_t));
}

static void
delete_http2_session(isc_nm_http2_session_t *session) {
	REQUIRE(ISC_LIST_EMPTY(session->sstreams));
	REQUIRE(ISC_LIST_EMPTY(session->cstreams));

	session->magic = 0;
	if (session->ssl_ctx_created) {
		SSL_CTX_free(session->ssl_ctx);
	}
	isc_mem_putanddetach(&session->mctx, session,
			     sizeof(isc_nm_http2_session_t));
}

static void
finish_http2_session(isc_nm_http2_session_t *session) {
	if (session->handle != NULL) {
		isc_nm_pauseread(session->handle);
		isc_nmhandle_detach(&session->handle);
	}
	if (session->ngsession != NULL) {
		nghttp2_session_del(session->ngsession);
		session->ngsession = NULL;
	}
	if (!ISC_LIST_EMPTY(session->cstreams)) {
		http2_client_stream_t *cstream =
			ISC_LIST_HEAD(session->cstreams);
		while (cstream != NULL) {
			http2_client_stream_t *next = ISC_LIST_NEXT(cstream,
								    link);
			ISC_LIST_DEQUEUE(session->cstreams, cstream, link);
			put_http2_client_stream(session->mctx, cstream);

			cstream = next;
		}
	}
	INSIST(ISC_LIST_EMPTY(session->cstreams));

	/* detach from server socket */
	if (session->serversocket != NULL) {
		isc__nmsocket_detach(&session->serversocket);
	}

	/*
	 * There might be leftover callbacks waiting to be received
	 */
	if (session->sending) {
		session->closed = true;
	}
}

static int
on_data_chunk_recv_callback(nghttp2_session *ngsession, uint8_t flags,
			    int32_t stream_id, const uint8_t *data, size_t len,
			    void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;

	UNUSED(ngsession);
	UNUSED(flags);

	if (session->client) {
		http2_client_stream_t *cstream =
			find_http2_client_stream(stream_id, session);
		if (cstream) {
			size_t new_rbufsize = cstream->rbufsize + len;
			if (new_rbufsize <= MAX_DNS_MESSAGE_SIZE &&
			    new_rbufsize <=
				    cstream->response_status.content_length)
			{
				memmove(cstream->rbuf + cstream->rbufsize, data,
					len);
				cstream->rbufsize = new_rbufsize;
			} else {
				return (NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE);
			}
		} else {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
	} else {
		isc_nmsocket_h2_t *sock_h2 = ISC_LIST_HEAD(session->sstreams);
		while (sock_h2 != NULL) {
			if (stream_id == sock_h2->stream_id) {
				size_t new_bufsize = sock_h2->bufsize + len;
				if (new_bufsize <= MAX_DNS_MESSAGE_SIZE &&
				    new_bufsize <= sock_h2->content_length)
				{
					memmove(sock_h2->buf + sock_h2->bufsize,
						data, len);
					sock_h2->bufsize = new_bufsize;
				} else {
					return (NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE);
				}
				break;
			}
			sock_h2 = ISC_LIST_NEXT(sock_h2, link);
		}
		if (sock_h2 == NULL) {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
	}

	return (0);
}

static int
on_stream_close_callback(nghttp2_session *ngsession, int32_t stream_id,
			 uint32_t error_code, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;
	int rv = 0;

	REQUIRE(VALID_HTTP2_SESSION(session));

	UNUSED(error_code);

	/* NOTE: calling isc_nm_cancelread() or
	 * isc__nmsocket_prep_destroy() on a socket will lead to an
	 * indirect call to the delete_http2_session() which will, in
	 * turn, perform required stream session cleanup.*/
	if (session->client) {
		http2_client_stream_t *cstream =
			find_http2_client_stream(stream_id, session);
		if (cstream) {
			isc_result_t result =
				cstream->response_status.code >= 200 &&
						cstream->response_status.code <
							300
					? ISC_R_SUCCESS
					: ISC_R_FAILURE;
			cstream->read_cb(session->handle, result,
					 &(isc_region_t){ cstream->rbuf,
							  cstream->rbufsize },
					 cstream->read_cbarg);
			ISC_LIST_UNLINK(session->cstreams, cstream, link);
			put_http2_client_stream(session->mctx, cstream);
			if (ISC_LIST_EMPTY(session->cstreams)) {
				rv = nghttp2_session_terminate_session(
					ngsession, NGHTTP2_NO_ERROR);
				if (rv != 0) {
					return (NGHTTP2_ERR_CALLBACK_FAILURE);
				}
				if (session->handle->sock->h2.session->reading)
				{
					isc_nm_cancelread(
						session->handle->sock->h2
							.session->handle);
				}
			}
		} else {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
	} else {
		isc_nmsocket_t *sock = nghttp2_session_get_stream_user_data(
			ngsession, stream_id);
		if (ISC_LIST_EMPTY(session->sstreams)) {
			rv = nghttp2_session_terminate_session(
				ngsession, NGHTTP2_NO_ERROR);
		}
		isc__nmsocket_prep_destroy(sock);
		if (rv != 0) {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
	}

	return (0);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * NPN TLS extension client callback. We check that server advertised
 * the HTTP/2 protocol the nghttp2 library supports.
 */
static int
select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
		     const unsigned char *in, unsigned int inlen, void *arg) {
	UNUSED(ssl);
	UNUSED(arg);

	if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
		return (SSL_TLSEXT_ERR_NOACK);
	}
	return (SSL_TLSEXT_ERR_OK);
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

/* Create SSL_CTX. */
static SSL_CTX *
create_client_ssl_ctx(void) {
	SSL_CTX *ssl_ctx = NULL;

	RUNTIME_CHECK(isc_tlsctx_createclient(&ssl_ctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(ssl_ctx != NULL);

#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_protos(ssl_ctx,
				(const unsigned char *)NGHTTP2_PROTO_ALPN,
				NGHTTP2_PROTO_ALPN_LEN);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

	ENSURE(ssl_ctx != NULL);
	return (ssl_ctx);
}

static void
client_handle_status_header(http2_client_stream_t *cstream,
			    const uint8_t *value, const size_t valuelen) {
	char tmp[32] = { 0 };
	const size_t tmplen = sizeof(tmp) - 1;

	strncpy(tmp, (const char *)value,
		valuelen > tmplen ? tmplen : valuelen);
	cstream->response_status.code = strtoul(tmp, NULL, 10);
}

static void
client_handle_content_length_header(http2_client_stream_t *cstream,
				    const uint8_t *value,
				    const size_t valuelen) {
	char tmp[32] = { 0 };
	const size_t tmplen = sizeof(tmp) - 1;

	strncpy(tmp, (const char *)value,
		valuelen > tmplen ? tmplen : valuelen);
	cstream->response_status.content_length = strtoul(tmp, NULL, 10);
}

static void
client_handle_content_type_header(http2_client_stream_t *cstream,
				  const uint8_t *value, const size_t valuelen) {
	const char type_dns_message[] = "application/dns-message";

	UNUSED(valuelen);

	if (strncasecmp((const char *)value, type_dns_message,
			sizeof(type_dns_message) - 1) == 0)
	{
		cstream->response_status.content_type_valid = true;
	}
}

static int
client_on_header_callback(nghttp2_session *ngsession,
			  const nghttp2_frame *frame, const uint8_t *name,
			  size_t namelen, const uint8_t *value, size_t valuelen,
			  uint8_t flags, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;
	const char status[] = ":status";
	const char content_length[] = "Content-Length";
	const char content_type[] = "Content-Type";

	REQUIRE(VALID_HTTP2_SESSION(session));
	REQUIRE(session->client);
	REQUIRE(!ISC_LIST_EMPTY(session->cstreams));

	UNUSED(flags);
	UNUSED(ngsession);

	http2_client_stream_t *cstream =
		find_http2_client_stream(frame->hd.stream_id, session);

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
			break;
		}

		if (HEADER_MATCH(status, name, namelen)) {
			client_handle_status_header(cstream, value, valuelen);
		} else if (HEADER_MATCH(content_length, name, namelen)) {
			client_handle_content_length_header(cstream, value,
							    valuelen);
		} else if (HEADER_MATCH(content_type, name, namelen)) {
			client_handle_content_type_header(cstream, value,
							  valuelen);
		}
		break;
	}

	return (0);
}

static void
initialize_nghttp2_client_session(isc_nm_http2_session_t *session) {
	nghttp2_session_callbacks *callbacks = NULL;

	RUNTIME_CHECK(nghttp2_session_callbacks_new(&callbacks) == 0);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, on_stream_close_callback);

	nghttp2_session_callbacks_set_on_header_callback(
		callbacks, client_on_header_callback);

	nghttp2_session_client_new(&session->ngsession, callbacks, session);

	nghttp2_session_callbacks_del(callbacks);
}

static bool
send_client_connection_header(isc_nm_http2_session_t *session) {
	nghttp2_settings_entry iv[] = { { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 } };
	int rv;

	rv = nghttp2_submit_settings(session->ngsession, NGHTTP2_FLAG_NONE, iv,
				     sizeof(iv) / sizeof(iv[0]));
	if (rv != 0) {
		return (false);
	}

	return (true);
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                       \
	{                                                                    \
		(uint8_t *)(uintptr_t)(NAME), (uint8_t *)(uintptr_t)(VALUE), \
			sizeof(NAME) - 1, VALUELEN, NGHTTP2_NV_FLAG_NONE     \
	}

#define MAKE_NV2(NAME, VALUE)                                                \
	{                                                                    \
		(uint8_t *)(uintptr_t)(NAME), (uint8_t *)(uintptr_t)(VALUE), \
			sizeof(NAME) - 1, sizeof(VALUE) - 1,                 \
			NGHTTP2_NV_FLAG_NONE                                 \
	}

static ssize_t
client_read_callback(nghttp2_session *ngsession, int32_t stream_id,
		     uint8_t *buf, size_t length, uint32_t *data_flags,
		     nghttp2_data_source *source, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;
	http2_client_stream_t *cstream;

	REQUIRE(session->client);
	REQUIRE(!ISC_LIST_EMPTY(session->cstreams));

	UNUSED(ngsession);
	UNUSED(source);

	cstream = find_http2_client_stream(stream_id, session);
	if (!cstream || cstream->stream_id != stream_id) {
		/* We haven't found the stream, so we are not reading anything
		 */
		return (NGHTTP2_ERR_CALLBACK_FAILURE);
	}

	if (cstream->post) {
		size_t len = cstream->postdata.length - cstream->postdata_pos;

		if (len > length) {
			len = length;
		}

		memmove(buf, cstream->postdata.base + cstream->postdata_pos,
			len);
		cstream->postdata_pos += len;

		if (cstream->postdata_pos == cstream->postdata.length) {
			*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		}

		return (len);
	} else {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		return (0);
	}

	return (0);
}

/* Send HTTP request to the remote peer */
static isc_result_t
client_submit_request(isc_nm_http2_session_t *session,
		      http2_client_stream_t *stream) {
	int32_t stream_id;
	char *uri = stream->uri;
	isc_url_parser_t *up = &stream->up;
	nghttp2_data_provider dp;

	if (stream->post) {
		char p[64];
		snprintf(p, sizeof(p), "%u", stream->postdata.length);
		nghttp2_nv hdrs[] = {
			MAKE_NV2(":method", "POST"),
			MAKE_NV(":scheme",
				&uri[up->field_data[ISC_UF_SCHEMA].off],
				up->field_data[ISC_UF_SCHEMA].len),
			MAKE_NV(":authority", stream->authority,
				stream->authoritylen),
			MAKE_NV(":path", stream->path, stream->pathlen),
			MAKE_NV2("content-type", "application/dns-message"),
			MAKE_NV2("accept", "application/dns-message"),
			MAKE_NV("content-length", p, strlen(p)),
		};

		dp = (nghttp2_data_provider){ .read_callback =
						      client_read_callback };
		stream_id = nghttp2_submit_request(
			session->ngsession, NULL, hdrs,
			sizeof(hdrs) / sizeof(hdrs[0]), &dp, stream);
	} else {
		INSIST(stream->GET_path != NULL);
		INSIST(stream->GET_path_len != 0);
		nghttp2_nv hdrs[] = {
			MAKE_NV2(":method", "GET"),
			MAKE_NV(":scheme",
				&uri[up->field_data[ISC_UF_SCHEMA].off],
				up->field_data[ISC_UF_SCHEMA].len),
			MAKE_NV(":authority", stream->authority,
				stream->authoritylen),
			MAKE_NV(":path", stream->GET_path,
				stream->GET_path_len),
			MAKE_NV2("accept", "application/dns-message")
		};

		dp = (nghttp2_data_provider){ .read_callback =
						      client_read_callback };
		stream_id = nghttp2_submit_request(
			session->ngsession, NULL, hdrs,
			sizeof(hdrs) / sizeof(hdrs[0]), &dp, stream);
	}
	if (stream_id < 0) {
		return (ISC_R_FAILURE);
	}

	stream->stream_id = stream_id;
	http2_do_bio(session);

	return (ISC_R_SUCCESS);
}

/*
 * Read callback from TLS socket.
 */
static void
https_readcb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
	     void *data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)data;
	ssize_t readlen;

	REQUIRE(VALID_HTTP2_SESSION(session));

	UNUSED(handle);

	if (result != ISC_R_SUCCESS) {
		session->reading = false;
		failed_read_cb(result, session);
		return;
	}

	readlen = nghttp2_session_mem_recv(session->ngsession, region->base,
					   region->length);
	if (readlen < 0) {
		failed_read_cb(ISC_R_CANCELED, session);
		return;
	}

	if (readlen < region->length) {
		INSIST(session->bufsize == 0);
		INSIST(region->length - readlen < MAX_DNS_MESSAGE_SIZE);
		memmove(session->buf, region->base, region->length - readlen);
		session->bufsize = region->length - readlen;
		isc_nm_pauseread(session->handle);
	}

	/* We might have something to receive or send, do IO */
	http2_do_bio(session);
}

static void
https_writecb(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)arg;

	REQUIRE(VALID_HTTP2_SESSION(session));

	UNUSED(handle);

	session->sending = false;
	isc_mem_put(session->mctx, session->r.base, session->r.length);
	session->r.base = NULL;
	if (result == ISC_R_SUCCESS) {
		http2_do_bio(session);
	}
}

static void
http2_do_bio(isc_nm_http2_session_t *session) {
	REQUIRE(VALID_HTTP2_SESSION(session));

	if (session->closed ||
	    (nghttp2_session_want_read(session->ngsession) == 0 &&
	     nghttp2_session_want_write(session->ngsession) == 0))
	{
		finish_http2_session(session);
		return;
	}

	if (nghttp2_session_want_read(session->ngsession) != 0) {
		if (!session->reading) {
			/* We have not yet started reading from this handle */
			isc_nm_read(session->handle, https_readcb, session);
			session->reading = true;
		} else if (session->bufsize > 0) {
			/* Leftover data in the buffer, use it */
			size_t readlen = nghttp2_session_mem_recv(
				session->ngsession, session->buf,
				session->bufsize);

			if (readlen == session->bufsize) {
				session->bufsize = 0;
			} else {
				memmove(session->buf, session->buf + readlen,
					session->bufsize - readlen);
				session->bufsize -= readlen;
			}

			http2_do_bio(session);
			return;
		} else {
			/* Resume reading, it's idempotent, wait for more */
			isc_nm_resumeread(session->handle);
		}
	} else {
		/* We don't want more data, stop reading for now */
		isc_nm_pauseread(session->handle);
	}

	if (!session->sending &&
	    nghttp2_session_want_write(session->ngsession) != 0) {
		const uint8_t *data = NULL;
		size_t sz;

		/*
		 * XXXWPK TODO
		 * This function may produce a very small byte string.  If
		 * that is the case, and application disables Nagle
		 * algorithm (``TCP_NODELAY``), then writing this small
		 * chunk leads to a very small packet, and it is very
		 * inefficient.  An application should be responsible to
		 * buffer up small chunks of data as necessary to avoid
		 * this situation.
		 */
		sz = nghttp2_session_mem_send(session->ngsession, &data);
		if (sz == 0) {
			/* No data returned */
			return;
		}
		INSIST(session->r.base == NULL);
		session->r.base = isc_mem_get(session->mctx, sz);
		session->r.length = sz;
		memmove(session->r.base, data, sz);
		session->sending = true;
		isc_nm_send(session->handle, &session->r, https_writecb,
			    session);
		return;
	}

	return;
}

typedef struct http_connect_data {
	char *uri;
	isc_nm_cb_t connect_cb;
	void *connect_cbarg;
	bool post;
	bool ssl_ctx_created;
	SSL_CTX *ssl_ctx;
} http_connect_data_t;

static void
transport_connect_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	char *uri = NULL;
	http_connect_data_t *pconn_data = (http_connect_data_t *)cbarg;
	http_connect_data_t conn_data;
	isc_nm_http2_session_t *session = NULL;
	isc_mem_t *mctx;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(cbarg != NULL);

	handle->sock->h2.session = NULL;
	mctx = handle->sock->mgr->mctx;

	conn_data = *pconn_data;
	uri = conn_data.uri;
	isc_mem_put(mctx, pconn_data, sizeof(*pconn_data));

	INSIST(conn_data.connect_cb != NULL);
	INSIST(conn_data.uri != NULL);

	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	session = isc_mem_get(mctx, sizeof(isc_nm_http2_session_t));
	*session = (isc_nm_http2_session_t){ .magic = HTTP2_SESSION_MAGIC,
#ifdef NETMGR_TRACE
					     .sstreams_count = 0,
#endif /* NETMGR_TRACE */
					     .ssl_ctx_created =
						     conn_data.ssl_ctx_created,
					     .ssl_ctx = conn_data.ssl_ctx,
					     .handle = NULL,
					     .client = true };
	isc_mem_attach(mctx, &session->mctx);

	handle->sock->h2.connect.uri = uri;
	handle->sock->h2.connect.post = conn_data.post;

	session->ssl_ctx = conn_data.ssl_ctx;
	conn_data.ssl_ctx = NULL;
	session->ssl_ctx_created = conn_data.ssl_ctx_created;
	conn_data.ssl_ctx_created = false;

	if (session->ssl_ctx != NULL) {
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
		SSL *ssl = NULL;

		REQUIRE(VALID_NMHANDLE(handle));
		REQUIRE(VALID_NMSOCK(handle->sock));
		REQUIRE(handle->sock->type == isc_nm_tlssocket);

		ssl = handle->sock->tlsstream.ssl;
		INSIST(ssl != NULL);
#ifndef OPENSSL_NO_NEXTPROTONEG
		SSL_get0_next_proto_negotiated(handle->sock->tlsstream.ssl,
					       &alpn, &alpnlen);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (alpn == NULL) {
			SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
		}
#endif

		if (alpn == NULL || alpnlen != 2 ||
		    memcmp(NGHTTP2_PROTO_VERSION_ID, alpn,
			   NGHTTP2_PROTO_VERSION_ID_LEN) != 0)
		{
			result = ISC_R_CANCELED;
			goto error;
		}
	}

	isc_nmhandle_attach(handle, &session->handle);
	handle->sock->h2.session = session;

	initialize_nghttp2_client_session(session);
	if (!send_client_connection_header(session)) {
		handle->sock->h2.session = NULL;
		goto error;
	}
	conn_data.connect_cb(handle, ISC_R_SUCCESS, conn_data.connect_cbarg);
	if (ISC_LIST_EMPTY(session->cstreams)) {
		delete_http2_session(session);
		isc__nmsocket_prep_destroy(handle->sock);
	} else {
		http2_do_bio(session);
	}

	return;
error:
	conn_data.connect_cb(handle, result, conn_data.connect_cbarg);
	if (conn_data.ssl_ctx_created && conn_data.ssl_ctx) {
		SSL_CTX_free(conn_data.ssl_ctx);
	}

	if (session != NULL) {
		delete_http2_session(session);
	}

	if (uri != NULL) {
		isc_mem_free(mctx, uri);
	}
}

isc_result_t
isc_nm_httpconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		   const char *uri, bool post, isc_nm_cb_t cb, void *cbarg,
		   SSL_CTX *ctx, unsigned int timeout, size_t extrahandlesize) {
	isc_nmiface_t resolved_peer, resolved_local;
	http_connect_data_t *pconn_data;
	isc_result_t result;
	uint16_t port = 80;
	isc_url_parser_t url_parser;
	bool create_ssl_ctx;
	const char http[] = "http";
	const char http_secured[] = "https";
	size_t schema_len;
	const char *schema;

	REQUIRE(VALID_NM(mgr));
	REQUIRE(cb != NULL);
	REQUIRE(uri != NULL);
	REQUIRE(*uri != '\0');

	result = isc_url_parse(uri, strlen(uri), 0, &url_parser);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	schema_len = url_parser.field_data[ISC_UF_SCHEMA].len;
	INSIST(schema_len > 0);
	schema = &uri[url_parser.field_data[ISC_UF_SCHEMA].off];

	if (schema_len == sizeof(http_secured) - 1 &&
	    strncasecmp(http_secured, schema, sizeof(http_secured) - 1) == 0)
	{
		create_ssl_ctx = true;
	} else if (schema_len == sizeof(http) - 1 &&
		   strncasecmp(http, schema, sizeof(http) - 1) == 0)
	{
		create_ssl_ctx = false;
	} else {
		INSIST(0);
		ISC_UNREACHABLE();
	}

	if (ctx == NULL && create_ssl_ctx) {
		port = 443;
		ctx = create_client_ssl_ctx();
	}

	if (peer == NULL || local == NULL) {
		size_t hostlen = 0;
		char *host = NULL;
		struct addrinfo hints;
		struct addrinfo *res = NULL;

#ifndef WIN32 /* FIXME */
		/* extract host name */
		hostlen = url_parser.field_data[ISC_UF_HOST].len + 1;
		host = isc_mem_get(mgr->mctx, hostlen);
		memmove(host, &uri[url_parser.field_data[ISC_UF_HOST].off],
			hostlen - 1);
		host[hostlen - 1] = '\0';

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_CANONNAME;

		result = getaddrinfo(host, NULL, &hints, &res);
		isc_mem_put(mgr->mctx, host, hostlen);
		if (result != 0) {
			return (ISC_R_FAILURE);
		}
#endif /* WIN32 */

		if ((url_parser.field_set & (1 << ISC_UF_PORT)) != 0) {
			port = url_parser.port;
		}

		if (peer == NULL) {
			(void)isc_sockaddr_fromsockaddr(&resolved_peer.addr,
							res->ai_addr);
			isc_sockaddr_setport(&resolved_peer.addr, port);
			peer = &resolved_peer;
		}
		if (local == NULL) {
			isc_sockaddr_anyofpf(&resolved_local.addr,
					     res->ai_family);
			local = &resolved_local;
		}

		freeaddrinfo(res);
	}

	pconn_data = isc_mem_get(mgr->mctx, sizeof(*pconn_data));
	*pconn_data =
		(http_connect_data_t){ .uri = isc_mem_strdup(mgr->mctx, uri),
				       .post = post,
				       .connect_cb = cb,
				       .connect_cbarg = cbarg,
				       .ssl_ctx_created = create_ssl_ctx,
				       .ssl_ctx = ctx };

	if (ctx != NULL) {
		result = isc_nm_tlsconnect(mgr, local, peer,
					   transport_connect_cb, pconn_data,
					   ctx, timeout, extrahandlesize);
	} else {
		result = isc_nm_tcpconnect(mgr, local, peer,
					   transport_connect_cb, pconn_data,
					   timeout, extrahandlesize);
	}

	return (result);
}

isc_result_t
isc_nm_httprequest(isc_nmhandle_t *handle, isc_region_t *region,
		   isc_nm_recv_cb_t reply_cb, void *cbarg) {
	http2_client_stream_t *cstream = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	isc_nm_http2_session_t *session = NULL;
	isc_mem_t *mctx;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->tid == isc_nm_tid());
	REQUIRE(VALID_HTTP2_SESSION(handle->sock->h2.session));
	REQUIRE(region != NULL);
	REQUIRE(region->base != NULL);
	REQUIRE(region->length != 0);
	REQUIRE(region->length <= MAX_DNS_MESSAGE_SIZE);
	REQUIRE(reply_cb != NULL);

	session = handle->sock->h2.session;
	mctx = handle->sock->mgr->mctx;

	result = get_http2_client_stream(mctx, &cstream,
					 handle->sock->h2.connect.uri);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	cstream->read_cb = reply_cb;
	cstream->read_cbarg = cbarg;
	cstream->post = handle->sock->h2.connect.post;

	if (cstream->post) { /* POST */
		cstream->postdata = (isc_region_t){
			.base = isc_mem_get(mctx, region->length),
			.length = region->length
		};
		memmove(cstream->postdata.base, region->base, region->length);
		cstream->postdata_pos = 0;
	} else { /* GET */
		size_t path_size = 0;
		char *base64url_data = NULL;
		size_t base64url_data_len = 0;
		isc_buffer_t *buf = NULL;
		isc_region_t data = *region;
		isc_region_t base64_region;
		size_t base64_len = ((4 * data.length / 3) + 3) & ~3;

		isc_buffer_allocate(mctx, &buf, base64_len);

		if ((result = isc_base64_totext(&data, -1, "", buf)) !=
		    ISC_R_SUCCESS) {
			isc_buffer_free(&buf);
			goto error;
		}

		isc__buffer_usedregion(buf, &base64_region);
		INSIST(base64_region.length == base64_len);

		base64url_data = isc__nm_base64_to_base64url(
			mctx, (const char *)base64_region.base,
			base64_region.length, &base64url_data_len);
		isc_buffer_free(&buf);
		if (base64url_data == NULL) {
			goto error;
		}

		/* len("?dns=") + len(path) + len(base64url) + len("\0") */
		path_size = cstream->pathlen + base64url_data_len + 5 + 1;
		cstream->GET_path = isc_mem_allocate(mctx, path_size);
		cstream->GET_path_len = (size_t)snprintf(
			cstream->GET_path, path_size, "%.*s?dns=%s",
			(int)cstream->pathlen, cstream->path, base64url_data);

		INSIST(cstream->GET_path_len == (path_size - 1));
		isc_mem_free(mctx, base64url_data);
	}

	ISC_LINK_INIT(cstream, link);
	ISC_LIST_APPEND(session->cstreams, cstream, link);

	INSIST(cstream != NULL);

	result = client_submit_request(session, cstream);
	if (result != ISC_R_SUCCESS) {
		ISC_LIST_UNLINK(session->cstreams, cstream, link);
		goto error;
	}
	http2_do_bio(session);

	return (ISC_R_SUCCESS);
error:
	reply_cb(handle, result, NULL, cbarg);
	if (cstream) {
		put_http2_client_stream(mctx, cstream);
	}
	return (result);
}

typedef struct isc_nm_connect_send_data {
	isc_nm_recv_cb_t reply_cb;
	void *cb_arg;
	isc_region_t region;
} isc_nm_connect_send_data_t;

static void
https_connect_send_cb(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	isc_nm_connect_send_data_t data;

	REQUIRE(VALID_NMHANDLE(handle));

	memmove(&data, arg, sizeof(data));
	isc_mem_put(handle->sock->mgr->mctx, arg, sizeof(data));
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	result = isc_nm_httprequest(handle, &data.region, data.reply_cb,
				    data.cb_arg);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	isc_mem_put(handle->sock->mgr->mctx, data.region.base,
		    data.region.length);
	return;
error:
	data.reply_cb(handle, result, NULL, data.cb_arg);
	isc_mem_put(handle->sock->mgr->mctx, data.region.base,
		    data.region.length);
}

isc_result_t
isc_nm_http_connect_send_request(isc_nm_t *mgr, const char *uri, bool post,
				 isc_region_t *region, isc_nm_recv_cb_t cb,
				 void *cbarg, SSL_CTX *ctx,
				 unsigned int timeout) {
	isc_region_t copy;
	isc_result_t result;
	isc_nm_connect_send_data_t *data;

	REQUIRE(VALID_NM(mgr));
	REQUIRE(uri != NULL);
	REQUIRE(*uri != '\0');
	REQUIRE(region != NULL);
	REQUIRE(region->base != NULL);
	REQUIRE(region->length != 0);
	REQUIRE(region->length <= MAX_DNS_MESSAGE_SIZE);
	REQUIRE(cb != NULL);

	copy = (isc_region_t){ .base = isc_mem_get(mgr->mctx, region->length),
			       .length = region->length };
	memmove(copy.base, region->base, region->length);
	data = isc_mem_get(mgr->mctx, sizeof(*data));
	*data = (isc_nm_connect_send_data_t){ .reply_cb = cb,
					      .cb_arg = cbarg,
					      .region = copy };
	result = isc_nm_httpconnect(mgr, NULL, NULL, uri, post,
				    https_connect_send_cb, data, ctx, timeout,
				    0);

	return (result);
}

static int
server_on_begin_headers_callback(nghttp2_session *ngsession,
				 const nghttp2_frame *frame, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;
	isc_nmsocket_t *socket = NULL;
	isc_sockaddr_t iface;

	if (frame->hd.type != NGHTTP2_HEADERS ||
	    frame->headers.cat != NGHTTP2_HCAT_REQUEST)
	{
		return (0);
	}

	socket = isc_mem_get(session->mctx, sizeof(isc_nmsocket_t));
	iface = isc_nmhandle_localaddr(session->handle);
	isc__nmsocket_init(socket, session->serversocket->mgr,
			   isc_nm_httpstream, (isc_nmiface_t *)&iface);
	socket->h2 = (isc_nmsocket_h2_t){
		.bufpos = 0,
		.bufsize = 0,
		.buf = isc_mem_allocate(session->mctx, MAX_DNS_MESSAGE_SIZE),
		.psock = socket,
		.handler = NULL,
		.request_path = NULL,
		.query_data = NULL,
		.stream_id = frame->hd.stream_id,
		.session = session
	};
	socket->tid = session->handle->sock->tid;
	ISC_LINK_INIT(&socket->h2, link);
	ISC_LIST_APPEND(session->sstreams, &socket->h2, link);

#ifdef NETMGR_TRACE
	session->sstreams_count++;
	if (session->sstreams_count > 1) {
		fprintf(stderr, "HTTP/2 session %p (active streams: %lu)\n",
			session, session->sstreams_count);
	}
#endif /* NETMGR_TRACE */

	nghttp2_session_set_stream_user_data(ngsession, frame->hd.stream_id,
					     socket);
	return (0);
}

static isc_nm_http2_server_handler_t *
find_server_request_handler(const char *request_path,
			    isc_nmsocket_t *serversocket) {
	isc_nm_http2_server_handler_t *handler = NULL;

	REQUIRE(VALID_NMSOCK(serversocket));

	if (request_path == NULL || *request_path == '\0') {
		return (NULL);
	}

	RWLOCK(&serversocket->h2.handlers_lock, isc_rwlocktype_read);
	if (atomic_load(&serversocket->listening)) {
		for (handler = ISC_LIST_HEAD(serversocket->h2.handlers);
		     handler != NULL; handler = ISC_LIST_NEXT(handler, link))
		{
			if (!strcmp(request_path, handler->path)) {
				break;
			}
		}
	}
	RWUNLOCK(&serversocket->h2.handlers_lock, isc_rwlocktype_read);

	return (handler);
}

static isc_http2_error_responses_t
server_handle_path_header(isc_nmsocket_t *socket, const uint8_t *value,
			  const size_t valuelen) {
	isc_nm_http2_server_handler_t *handler = NULL;
	const uint8_t *qstr = NULL;
	size_t vlen = valuelen;

	qstr = memchr(value, '?', valuelen);
	if (qstr != NULL) {
		vlen = qstr - value;
	}

	if (socket->h2.request_path != NULL) {
		isc_mem_free(socket->mgr->mctx, socket->h2.request_path);
	}
	socket->h2.request_path = isc_mem_strndup(
		socket->mgr->mctx, (const char *)value, vlen + 1);
	handler = find_server_request_handler(socket->h2.request_path,
					      socket->h2.session->serversocket);
	if (handler != NULL) {
		socket->h2.handler_cb = handler->cb;
		socket->h2.handler_cbarg = handler->cbarg;
		socket->extrahandlesize = handler->extrahandlesize;
	} else {
		isc_mem_free(socket->mgr->mctx, socket->h2.request_path);
		socket->h2.request_path = NULL;
		return (ISC_HTTP_ERROR_NOT_FOUND);
	}
	if (qstr != NULL) {
		const char *dns_value = NULL;
		size_t dns_value_len = 0;

		if (socket->h2.request_type != ISC_HTTP_REQ_GET) {
			return (ISC_HTTP_ERROR_BAD_REQUEST);
		}

		if (isc__nm_parse_doh_query_string((const char *)qstr,
						   &dns_value, &dns_value_len))
		{
			const size_t decoded_size = dns_value_len / 4 * 3;
			if (decoded_size <= MAX_DNS_MESSAGE_SIZE) {
				if (socket->h2.query_data != NULL) {
					isc_mem_free(socket->mgr->mctx,
						     socket->h2.query_data);
				}
				socket->h2.query_data =
					isc__nm_base64url_to_base64(
						socket->mgr->mctx, dns_value,
						dns_value_len,
						&socket->h2.query_data_len);
			} else {
				socket->h2.query_too_large = true;
				return (ISC_HTTP_ERROR_PAYLOAD_TOO_LARGE);
			}
		} else {
			return (ISC_HTTP_ERROR_BAD_REQUEST);
		}
	}
	return (ISC_HTTP_ERROR_SUCCESS);
}

static isc_http2_error_responses_t
server_handle_method_header(isc_nmsocket_t *socket, const uint8_t *value,
			    const size_t valuelen) {
	const char get[] = "GET";
	const char post[] = "POST";

	if (HEADER_MATCH(get, value, valuelen)) {
		socket->h2.request_type = ISC_HTTP_REQ_GET;
	} else if (HEADER_MATCH(post, value, valuelen)) {
		socket->h2.request_type = ISC_HTTP_REQ_POST;
	} else {
		return (ISC_HTTP_ERROR_NOT_IMPLEMENTED);
	}
	return (ISC_HTTP_ERROR_SUCCESS);
}

static isc_http2_error_responses_t
server_handle_scheme_header(isc_nmsocket_t *socket, const uint8_t *value,
			    const size_t valuelen) {
	const char http[] = "http";
	const char http_secure[] = "https";

	if (HEADER_MATCH(http_secure, value, valuelen)) {
		socket->h2.request_scheme = ISC_HTTP_SCHEME_HTTP_SECURE;
	} else if (HEADER_MATCH(http, value, valuelen)) {
		socket->h2.request_scheme = ISC_HTTP_SCHEME_HTTP;
	} else {
		return (ISC_HTTP_ERROR_BAD_REQUEST);
	}
	return (ISC_HTTP_ERROR_SUCCESS);
}

static isc_http2_error_responses_t
server_handle_content_length_header(isc_nmsocket_t *socket,
				    const uint8_t *value,
				    const size_t valuelen) {
	char tmp[32] = { 0 };
	const size_t tmplen = sizeof(tmp) - 1;

	if (socket->h2.request_type != ISC_HTTP_REQ_POST) {
		return (ISC_HTTP_ERROR_BAD_REQUEST);
	}
	strncpy(tmp, (const char *)value,
		valuelen > tmplen ? tmplen : valuelen);
	socket->h2.content_length = strtoul(tmp, NULL, 10);
	if (socket->h2.content_length > MAX_DNS_MESSAGE_SIZE) {
		return (ISC_HTTP_ERROR_PAYLOAD_TOO_LARGE);
	}
	return (ISC_HTTP_ERROR_SUCCESS);
}

static isc_http2_error_responses_t
server_handle_content_type_header(isc_nmsocket_t *socket, const uint8_t *value,
				  const size_t valuelen) {
	const char type_dns_message[] = "application/dns-message";

	if (HEADER_MATCH(type_dns_message, value, valuelen)) {
		socket->h2.content_type_verified = true;
	} else {
		return (ISC_HTTP_ERROR_UNSUPPORTED_MEDIA_TYPE);
	}
	return (ISC_HTTP_ERROR_SUCCESS);
}

static isc_http2_error_responses_t
server_handle_accept_header(isc_nmsocket_t *socket, const uint8_t *value,
			    const size_t valuelen) {
	const char type_accept_all[] = "*/*";
	const char type_dns_message[] = "application/dns-message";

	if (HEADER_MATCH(type_dns_message, value, valuelen) ||
	    HEADER_MATCH(type_accept_all, value, valuelen))
	{
		socket->h2.accept_type_verified = true;
	} else {
		return (ISC_HTTP_ERROR_UNSUPPORTED_MEDIA_TYPE);
	}
	return (ISC_HTTP_ERROR_SUCCESS);
}

static int
server_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
			  const uint8_t *name, size_t namelen,
			  const uint8_t *value, size_t valuelen, uint8_t flags,
			  void *user_data) {
	isc_nmsocket_t *socket = NULL;
	isc_http2_error_responses_t code = ISC_HTTP_ERROR_SUCCESS;
	const char path[] = ":path";
	const char method[] = ":method";
	const char scheme[] = ":scheme";
	const char accept[] = "accept";
	const char content_length[] = "Content-Length";
	const char content_type[] = "Content-Type";

	UNUSED(flags);
	UNUSED(user_data);

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
			break;
		}

		socket = nghttp2_session_get_stream_user_data(
			session, frame->hd.stream_id);
		if (socket == NULL) {
			break;
		}

		if (HEADER_MATCH(path, name, namelen)) {
			code = server_handle_path_header(socket, value,
							 valuelen);
		} else if (HEADER_MATCH(method, name, namelen)) {
			code = server_handle_method_header(socket, value,
							   valuelen);
		} else if (HEADER_MATCH(scheme, name, namelen)) {
			code = server_handle_scheme_header(socket, value,
							   valuelen);
		} else if (HEADER_MATCH(content_length, name, namelen)) {
			code = server_handle_content_length_header(
				socket, value, valuelen);
		} else if (HEADER_MATCH(content_type, name, namelen)) {
			code = server_handle_content_type_header(socket, value,
								 valuelen);
		} else if (HEADER_MATCH(accept, (const char *)name, namelen)) {
			code = server_handle_accept_header(socket, value,
							   valuelen);
		}
		break;
	}

	if (code == ISC_HTTP_ERROR_SUCCESS) {
		return (0);
	}

	INSIST(socket != NULL);
	if (server_send_error_response(code, session, socket) != 0) {
		return (NGHTTP2_ERR_CALLBACK_FAILURE);
	};
	failed_httpstream_read_cb(socket, ISC_R_CANCELED, socket->h2.session);
	return (0);
}

static ssize_t
server_read_callback(nghttp2_session *ngsession, int32_t stream_id,
		     uint8_t *buf, size_t length, uint32_t *data_flags,
		     nghttp2_data_source *source, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;
	isc_nmsocket_t *socket = (isc_nmsocket_t *)source->ptr;
	size_t buflen;

	REQUIRE(socket->h2.stream_id == stream_id);

	UNUSED(ngsession);
	UNUSED(session);

	buflen = socket->h2.bufsize - socket->h2.bufpos;
	if (buflen > length) {
		buflen = length;
	}

	memmove(buf, socket->h2.buf + socket->h2.bufpos, buflen);
	socket->h2.bufpos += buflen;
	if (socket->h2.bufpos == socket->h2.bufsize) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	}

	return (buflen);
}

static int
server_send_response(nghttp2_session *ngsession, int32_t stream_id,
		     const nghttp2_nv *nva, size_t nvlen,
		     isc_nmsocket_t *socket) {
	nghttp2_data_provider data_prd;
	int rv;

	data_prd.source.ptr = socket;
	data_prd.read_callback = server_read_callback;

	rv = nghttp2_submit_response(ngsession, stream_id, nva, nvlen,
				     &data_prd);
	if (rv != 0) {
		return (-1);
	}
	return (0);
}

#define MAKE_ERROR_REPLY(tag, code)             \
	{                                       \
		tag, MAKE_NV2(":status", #code) \
	}

static struct http2_error_responses {
	const isc_http2_error_responses_t type;
	const nghttp2_nv header;
} error_responses[] = {
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_SUCCESS, 200),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_NOT_FOUND, 404),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_PAYLOAD_TOO_LARGE, 413),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_URI_TOO_LONG, 414),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_UNSUPPORTED_MEDIA_TYPE, 415),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_BAD_REQUEST, 400),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_NOT_IMPLEMENTED, 501),
	MAKE_ERROR_REPLY(ISC_HTTP_ERROR_GENERIC, 500),
};

static int
server_send_error_response(const isc_http2_error_responses_t error,
			   nghttp2_session *ngsession, isc_nmsocket_t *socket) {
	int rv;

	socket->h2.bufsize = 0;
	socket->h2.bufpos = 0;

	for (size_t i = 0;
	     i < sizeof(error_responses) / sizeof(error_responses[0]); i++)
	{
		if (error_responses[i].type == error) {
			rv = server_send_response(
				ngsession, socket->h2.stream_id,
				&error_responses[i].header,
				sizeof(error_responses[i].header), socket);
			return (rv);
		}
	}

	rv = server_send_error_response(ISC_HTTP_ERROR_GENERIC, ngsession,
					socket);
	return (rv);
}

static int
server_on_request_recv(nghttp2_session *ngsession,
		       isc_nm_http2_session_t *session,
		       isc_nmsocket_t *socket) {
	isc_nmhandle_t *handle = NULL;
	isc_sockaddr_t addr;
	isc_http2_error_responses_t code = ISC_HTTP_ERROR_SUCCESS;
	isc_region_t data;

	/*
	 * Sanity checks. Here we use the same error codes that
	 * Unbound uses.
	 * (https://blog.nlnetlabs.nl/dns-over-https-in-unbound/)
	 */
	if (!socket->h2.request_path || !socket->h2.handler_cb) {
		code = ISC_HTTP_ERROR_NOT_FOUND;
	} else if ((socket->h2.request_type == ISC_HTTP_REQ_POST &&
		    !socket->h2.content_type_verified) ||
		   !socket->h2.accept_type_verified)
	{
		code = ISC_HTTP_ERROR_UNSUPPORTED_MEDIA_TYPE;
	} else if (socket->h2.request_type == ISC_HTTP_REQ_UNSUPPORTED) {
		code = ISC_HTTP_ERROR_NOT_IMPLEMENTED;
	} else if (socket->h2.request_scheme == ISC_HTTP_SCHEME_UNSUPPORTED) {
		/*
		 * TODO: additional checks if we have enabled encryption
		 * on the socket or not
		 */
		code = ISC_HTTP_ERROR_BAD_REQUEST;
	} else if (socket->h2.content_length > MAX_DNS_MESSAGE_SIZE ||
		   socket->h2.query_too_large)
	{
		code = ISC_HTTP_ERROR_PAYLOAD_TOO_LARGE;
	} else if (socket->h2.request_type == ISC_HTTP_REQ_GET &&
		   (socket->h2.content_length > 0 ||
		    socket->h2.query_data_len == 0))
	{
		code = ISC_HTTP_ERROR_BAD_REQUEST;
	} else if (socket->h2.request_type == ISC_HTTP_REQ_POST &&
		   socket->h2.content_length == 0)
	{
		code = ISC_HTTP_ERROR_BAD_REQUEST;
	} else if (socket->h2.request_type == ISC_HTTP_REQ_POST &&
		   socket->h2.bufsize > socket->h2.content_length)
	{
		code = ISC_HTTP_ERROR_PAYLOAD_TOO_LARGE;
	} else if (socket->h2.request_type == ISC_HTTP_REQ_POST &&
		   socket->h2.bufsize != socket->h2.content_length)
	{
		code = ISC_HTTP_ERROR_BAD_REQUEST;
	}

	if (code != ISC_HTTP_ERROR_SUCCESS) {
		goto error;
	}

	if (socket->h2.request_type == ISC_HTTP_REQ_GET) {
		isc_buffer_t decoded_buf;
		isc__buffer_init(&decoded_buf, socket->h2.buf,
				 MAX_DNS_MESSAGE_SIZE);
		if (isc_base64_decodestring(socket->h2.query_data,
					    &decoded_buf) != ISC_R_SUCCESS)
		{
			code = ISC_HTTP_ERROR_GENERIC;
			goto error;
		}
		isc__buffer_usedregion(&decoded_buf, &data);
	} else if (socket->h2.request_type == ISC_HTTP_REQ_POST) {
		INSIST(socket->h2.content_length > 0);
		data = (isc_region_t){ socket->h2.buf, socket->h2.bufsize };
	} else {
		INSIST(0);
		ISC_UNREACHABLE();
	}

	addr = isc_nmhandle_peeraddr(session->handle);
	handle = isc__nmhandle_get(socket, &addr, NULL);
	socket->h2.handler_cb(handle, ISC_R_SUCCESS, &data,
			      socket->h2.handler_cbarg);
	isc_nmhandle_detach(&handle);
	return (0);

error:
	if (server_send_error_response(code, ngsession, socket) != 0) {
		return (NGHTTP2_ERR_CALLBACK_FAILURE);
	}
	return (0);
}

void
isc__nm_http_send(isc_nmhandle_t *handle, const isc_region_t *region,
		  isc_nm_cb_t cb, void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc__nm_uvreq_t *uvreq = NULL;
	isc__netievent_httpsend_t *ievent = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(handle->httpsession != NULL);
	REQUIRE(VALID_NMSOCK(sock));

	/* TODO: should be called from within the context of an NM thread? */
	if (inactive(sock) || handle->httpsession->closed) {
		cb(handle, ISC_R_CANCELED, cbarg);
		return;
	}

	INSIST(VALID_NMHANDLE(handle->httpsession->handle));
	INSIST(VALID_NMSOCK(handle->httpsession->handle->sock));
	INSIST(sock->tid == handle->httpsession->handle->sock->tid);

	uvreq = isc__nm_uvreq_get(sock->mgr, sock);
	isc_nmhandle_attach(handle, &uvreq->handle);
	uvreq->cb.send = cb;
	uvreq->cbarg = cbarg;

	uvreq->uvbuf.base = (char *)region->base;
	uvreq->uvbuf.len = region->length;

	ievent = isc__nm_get_netievent_httpsend(sock->mgr, sock, uvreq);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_async_httpsend(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_httpsend_t *ievent = (isc__netievent_httpsend_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;
	isc__nm_uvreq_t *req = ievent->req;
	isc_nmhandle_t *handle = NULL;
	isc_nm_cb_t cb = NULL;
	void *cbarg = NULL;
	isc_result_t res;
	size_t content_length_str_len;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));

	ievent->req = NULL;
	handle = req->handle;
	cb = req->cb.send;
	cbarg = req->cbarg;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMHANDLE(handle->httpsession->handle));
	REQUIRE(VALID_NMSOCK(handle->httpsession->handle->sock));
	REQUIRE(handle->httpsession->handle->sock->tid == isc_nm_tid());

	UNUSED(worker);

	memmove(sock->h2.buf, req->uvbuf.base, req->uvbuf.len);
	sock->h2.bufsize = req->uvbuf.len;

	content_length_str_len =
		snprintf(sock->h2.response_content_length_str,
			 sizeof(sock->h2.response_content_length_str), "%lu",
			 (unsigned long)req->uvbuf.len);
	const nghttp2_nv hdrs[] = {
		MAKE_NV2(":status", "200"),
		MAKE_NV2("Content-Type", "application/dns-message"),
		MAKE_NV("Content-Length", sock->h2.response_content_length_str,
			content_length_str_len)
	};
	if (server_send_response(handle->httpsession->ngsession,
				 sock->h2.stream_id, hdrs,
				 sizeof(hdrs) / sizeof(nghttp2_nv), sock) != 0)
	{
		res = ISC_R_FAILURE;
	} else {
		res = ISC_R_SUCCESS;
	}

	http2_do_bio(handle->httpsession); /*TODO: Should we call it only
					    * on success? */
	cb(handle, res, cbarg);

	isc__nm_uvreq_put(&req, sock);
}

static int
server_on_frame_recv_callback(nghttp2_session *ngsession,
			      const nghttp2_frame *frame, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;
	isc_nmsocket_t *socket = NULL;

	switch (frame->hd.type) {
	case NGHTTP2_DATA:
	case NGHTTP2_HEADERS:
		/* Check that the client request has finished */
		if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
			socket = nghttp2_session_get_stream_user_data(
				ngsession, frame->hd.stream_id);

			/*
			 * For DATA and HEADERS frame, this callback may be
			 * called after on_stream_close_callback. Check that
			 * the stream is still alive.
			 */
			if (socket == NULL) {
				return (0);
			}

			return (server_on_request_recv(ngsession, session,
						       socket));
		}
		break;
	default:
		break;
	}
	return (0);
}

static void
initialize_nghttp2_server_session(isc_nm_http2_session_t *session) {
	nghttp2_session_callbacks *callbacks = NULL;

	RUNTIME_CHECK(nghttp2_session_callbacks_new(&callbacks) == 0);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, on_stream_close_callback);

	nghttp2_session_callbacks_set_on_header_callback(
		callbacks, server_on_header_callback);

	nghttp2_session_callbacks_set_on_begin_headers_callback(
		callbacks, server_on_begin_headers_callback);

	nghttp2_session_callbacks_set_on_frame_recv_callback(
		callbacks, server_on_frame_recv_callback);

	nghttp2_session_server_new(&session->ngsession, callbacks, session);

	nghttp2_session_callbacks_del(callbacks);
}

static int
server_send_connection_header(isc_nm_http2_session_t *session) {
	nghttp2_settings_entry iv[1] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
	};
	int rv;

	rv = nghttp2_submit_settings(session->ngsession, NGHTTP2_FLAG_NONE, iv,
				     1);
	if (rv != 0) {
		return (-1);
	}
	return (0);
}

static isc_result_t
httplisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *httplistensock = (isc_nmsocket_t *)cbarg;
	isc_nm_http2_session_t *session = NULL;
	isc_nmsocket_t *listener = NULL, *httpserver = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	if (handle->sock->type == isc_nm_tlssocket) {
		REQUIRE(VALID_NMSOCK(handle->sock->listener));
		listener = handle->sock->listener;
		httpserver = listener->h2.httpserver;
	} else {
		REQUIRE(VALID_NMSOCK(handle->sock->server));
		listener = handle->sock->server;
		REQUIRE(VALID_NMSOCK(listener->parent));
		httpserver = listener->parent->h2.httpserver;
	}

	/*
	 * NOTE: HTTP listener socket might be destroyed by the time this
	 * function gets invoked, so we need to do extra sanity checks to
	 * detect this case.
	 */
	if (inactive(handle->sock) || httpserver == NULL) {
		return (ISC_R_CANCELED);
	}

	if (result != ISC_R_SUCCESS) {
		/* XXXWPK do nothing? */
		return (result);
	}

	REQUIRE(VALID_NMSOCK(httplistensock));
	INSIST(httplistensock == httpserver);

	if (inactive(httplistensock) ||
	    !atomic_load(&httplistensock->listening)) {
		return (ISC_R_CANCELED);
	}

	session = isc_mem_get(httplistensock->mgr->mctx,
			      sizeof(isc_nm_http2_session_t));
	*session = (isc_nm_http2_session_t){ .magic = HTTP2_SESSION_MAGIC,
					     .ssl_ctx_created = false,
					     .client = false };
	initialize_nghttp2_server_session(session);
	handle->sock->h2.session = session;

	isc_mem_attach(httplistensock->mgr->mctx, &session->mctx);
	isc_nmhandle_attach(handle, &session->handle);
	isc__nmsocket_attach(httplistensock, &session->serversocket);
	session->serversocket = httplistensock;
	server_send_connection_header(session);

	/* TODO H2 */
	http2_do_bio(session);
	return (ISC_R_SUCCESS);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int
next_proto_cb(SSL *ssl, const unsigned char **data, unsigned int *len,
	      void *arg) {
	UNUSED(ssl);
	UNUSED(arg);

	*data = (const unsigned char *)NGHTTP2_PROTO_ALPN;
	*len = (unsigned int)NGHTTP2_PROTO_ALPN_LEN;
	return (SSL_TLSEXT_ERR_OK);
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int
alpn_select_proto_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
		     const unsigned char *in, unsigned int inlen, void *arg) {
	int ret;

	UNUSED(ssl);
	UNUSED(arg);

	ret = nghttp2_select_next_protocol((unsigned char **)(uintptr_t)out,
					   outlen, in, inlen);

	if (ret != 1) {
		return (SSL_TLSEXT_ERR_NOACK);
	}

	return (SSL_TLSEXT_ERR_OK);
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

isc_result_t
isc_nm_listenhttp(isc_nm_t *mgr, isc_nmiface_t *iface, int backlog,
		  isc_quota_t *quota, SSL_CTX *ctx, isc_nmsocket_t **sockp) {
	isc_nmsocket_t *sock = NULL;
	isc_result_t result;

	sock = isc_mem_get(mgr->mctx, sizeof(*sock));
	isc__nmsocket_init(sock, mgr, isc_nm_httplistener, iface);

	if (ctx != NULL) {
#ifndef OPENSSL_NO_NEXTPROTONEG
		SSL_CTX_set_next_protos_advertised_cb(ctx, next_proto_cb, NULL);
#endif // OPENSSL_NO_NEXTPROTONEG
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		SSL_CTX_set_alpn_select_cb(ctx, alpn_select_proto_cb, NULL);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
		result = isc_nm_listentls(mgr, iface, httplisten_acceptcb, sock,
					  sizeof(isc_nm_http2_session_t),
					  backlog, quota, ctx, &sock->outer);
	} else {
		result = isc_nm_listentcp(mgr, iface, httplisten_acceptcb, sock,
					  sizeof(isc_nm_http2_session_t),
					  backlog, quota, &sock->outer);
	}

	if (result != ISC_R_SUCCESS) {
		atomic_store(&sock->closed, true);
		isc__nmsocket_detach(&sock);
		return (result);
	}

	sock->outer->h2.httpserver = sock;

	sock->nchildren = sock->outer->nchildren;
	sock->result = ISC_R_DEFAULT;
	sock->tid = isc_random_uniform(sock->nchildren);
	sock->fd = (uv_os_sock_t)-1;

	atomic_store(&sock->listening, true);
	*sockp = sock;
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_nm_http_add_endpoint(isc_nmsocket_t *sock, const char *uri,
			 isc_nm_http_cb_t cb, void *cbarg,
			 size_t extrahandlesize) {
	isc_nm_http2_server_handler_t *handler = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_httplistener);

	if (find_server_request_handler(uri, sock) == NULL) {
		handler = isc_mem_get(sock->mgr->mctx, sizeof(*handler));
		*handler = (isc_nm_http2_server_handler_t){
			.cb = cb,
			.cbarg = cbarg,
			.extrahandlesize = extrahandlesize,
			.path = isc_mem_strdup(sock->mgr->mctx, uri)
		};
		ISC_LINK_INIT(handler, link);

		RWLOCK(&sock->h2.handlers_lock, isc_rwlocktype_write);
		ISC_LIST_APPEND(sock->h2.handlers, handler, link);
		RWUNLOCK(&sock->h2.handlers_lock, isc_rwlocktype_write);
	}

	return (ISC_R_SUCCESS);
}

/*
 * In DoH we just need to intercept the request - the response can be sent
 * to the client code via the nmhandle directly as it's always just the
 * http * content.
 */
static void
doh_callback(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *data,
	     void *arg) {
	isc_nm_http_doh_cbarg_t *dohcbarg = arg;

	REQUIRE(VALID_NMHANDLE(handle));

	if (result != ISC_R_SUCCESS) {
		/* Shut down the client, then ourselves */
		dohcbarg->cb(handle, result, NULL, dohcbarg->cbarg);
		/* XXXWPK FREE */
		return;
	}
	dohcbarg->cb(handle, result, data, dohcbarg->cbarg);
}

isc_result_t
isc_nm_http_add_doh_endpoint(isc_nmsocket_t *sock, const char *uri,
			     isc_nm_recv_cb_t cb, void *cbarg,
			     size_t extrahandlesize) {
	isc_result_t result;
	isc_nm_http_doh_cbarg_t *dohcbarg = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_httplistener);

	dohcbarg = isc_mem_get(sock->mgr->mctx,
			       sizeof(isc_nm_http_doh_cbarg_t));
	*dohcbarg = (isc_nm_http_doh_cbarg_t){ .cb = cb, .cbarg = cbarg };
	ISC_LINK_INIT(dohcbarg, link);

	result = isc_nm_http_add_endpoint(sock, uri, doh_callback, dohcbarg,
					  extrahandlesize);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(sock->mgr->mctx, dohcbarg,
			    sizeof(isc_nm_http_doh_cbarg_t));
	}

	RWLOCK(&sock->h2.handlers_lock, isc_rwlocktype_write);
	ISC_LIST_APPEND(sock->h2.handlers_cbargs, dohcbarg, link);
	RWUNLOCK(&sock->h2.handlers_lock, isc_rwlocktype_write);

	return (result);
}

void
isc__nm_http_stoplistening(isc_nmsocket_t *sock) {
	isc__netievent_httpstop_t *ievent = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_httplistener);

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		INSIST(0);
		ISC_UNREACHABLE();
	}

	ievent = isc__nm_get_netievent_httpstop(sock->mgr, sock);
	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_http_clear_handlers(isc_nmsocket_t *sock) {
	isc_nm_http2_server_handler_t *handler = NULL;
	isc_nm_http_doh_cbarg_t *dohcbarg = NULL;

	/* delete all handlers */
	RWLOCK(&sock->h2.handlers_lock, isc_rwlocktype_write);
	handler = ISC_LIST_HEAD(sock->h2.handlers);
	while (handler != NULL) {
		isc_nm_http2_server_handler_t *next;

		next = ISC_LIST_NEXT(handler, link);
		ISC_LIST_DEQUEUE(sock->h2.handlers, handler, link);
		isc_mem_free(sock->mgr->mctx, handler->path);
		isc_mem_put(sock->mgr->mctx, handler, sizeof(*handler));
		handler = next;
	}

	dohcbarg = ISC_LIST_HEAD(sock->h2.handlers_cbargs);
	while (dohcbarg != NULL) {
		isc_nm_http_doh_cbarg_t *next;

		next = ISC_LIST_NEXT(dohcbarg, link);
		ISC_LIST_DEQUEUE(sock->h2.handlers_cbargs, dohcbarg, link);
		isc_mem_put(sock->mgr->mctx, dohcbarg,
			    sizeof(isc_nm_http_doh_cbarg_t));
		dohcbarg = next;
	}
	RWUNLOCK(&sock->h2.handlers_lock, isc_rwlocktype_write);
}

void
isc__nm_http_clear_session(isc_nmsocket_t *sock) {
	if (sock->type != isc_nm_httpstream && sock->h2.session != NULL) {
		isc_nm_http2_session_t *session = sock->h2.session;
		INSIST(ISC_LIST_EMPTY(session->sstreams));
		session->magic = 0;
		if (session->ssl_ctx_created) {
			SSL_CTX_free(session->ssl_ctx);
		}
		isc_mem_putanddetach(&sock->h2.session->mctx, session,
				     sizeof(isc_nm_http2_session_t));
		sock->h2.session = NULL;
	}
}

void
isc__nm_async_httpstop(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_httpstop_t *ievent = (isc__netievent_httpstop_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	UNUSED(worker);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	atomic_store(&sock->listening, false);
	atomic_store(&sock->closing, false);
	atomic_store(&sock->closed, true);
	if (sock->outer != NULL) {
		sock->outer->h2.httpserver = NULL;
		isc_nm_stoplistening(sock->outer);
		isc_nmsocket_close(&sock->outer);
	}
}

static void
http_close_direct(isc_nmsocket_t *sock) {
	bool sessions_empty;
	isc_nm_http2_session_t *session;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_HTTP2_SESSION(sock->h2.session));

	atomic_store(&sock->closed, true);
	session = sock->h2.session;

	if (ISC_LINK_LINKED(&sock->h2, link)) {
		ISC_LIST_UNLINK(session->sstreams, &sock->h2, link);
#ifdef NETMGR_TRACE
		session->sstreams_count--;
#endif /* NETMGR_TRACE */
	}

	sessions_empty = ISC_LIST_EMPTY(session->sstreams);
	if (!sessions_empty) {
		http2_do_bio(session);
	} else if (session->reading) {
		session->reading = false;
		if (session->handle != NULL) {
			isc_nm_cancelread(session->handle);
		}
	}
	/* If session is closed then the only reference to the socket is
	 * the one, created when handling the netievent. */
	if (!session->closed) {
		INSIST(session->handle != NULL);
		isc__nmsocket_detach(&sock);
	} else {
		INSIST(isc_refcount_current(&sock->references) == 1);
	}
}

void
isc__nm_http_close(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_httpstream);
	REQUIRE(!isc__nmsocket_active(sock));

	if (!atomic_compare_exchange_strong(&sock->closing, &(bool){ false },
					    true)) {
		return;
	}

	isc__netievent_httpclose_t *ievent =
		isc__nm_get_netievent_httpclose(sock->mgr, sock);

	isc__nm_enqueue_ievent(&sock->mgr->workers[sock->tid],
			       (isc__netievent_t *)ievent);
}

void
isc__nm_async_httpclose(isc__networker_t *worker, isc__netievent_t *ev0) {
	isc__netievent_httpclose_t *ievent = (isc__netievent_httpclose_t *)ev0;
	isc_nmsocket_t *sock = ievent->sock;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_nm_tid());

	UNUSED(worker);

	http_close_direct(sock);
}

static void
failed_httpstream_read_cb(isc_nmsocket_t *sock, isc_result_t result,
			  isc_nm_http2_session_t *session) {
	isc_nmhandle_t *handle = NULL;
	isc_sockaddr_t addr;

	REQUIRE(VALID_NMSOCK(sock));
	INSIST(sock->type == isc_nm_httpstream);

	if (!sock->h2.request_path) {
		return;
	}

	INSIST(sock->h2.handler_cbarg != NULL);

	(void)nghttp2_submit_rst_stream(
		session->ngsession, NGHTTP2_FLAG_END_STREAM, sock->h2.stream_id,
		NGHTTP2_REFUSED_STREAM);
	addr = isc_nmhandle_peeraddr(session->handle);
	handle = isc__nmhandle_get(sock, &addr, NULL);
	sock->h2.handler_cb(handle, result,
			    &(isc_region_t){ sock->h2.buf, sock->h2.bufsize },
			    sock->h2.handler_cbarg);
	isc_nmhandle_detach(&handle);
}

static void
failed_read_cb(isc_result_t result, isc_nm_http2_session_t *session) {
	REQUIRE(VALID_HTTP2_SESSION(session));

	if (session->client) {
		http2_client_stream_t *cstream = NULL;
		cstream = ISC_LIST_HEAD(session->cstreams);
		while (cstream != NULL) {
			http2_client_stream_t *next = ISC_LIST_NEXT(cstream,
								    link);
			ISC_LIST_DEQUEUE(session->cstreams, cstream, link);

			cstream->read_cb(session->handle, result,
					 &(isc_region_t){ cstream->rbuf,
							  cstream->rbufsize },
					 cstream->read_cbarg);

			put_http2_client_stream(session->mctx, cstream);
			cstream = next;
		}
	} else {
		isc_nmsocket_h2_t *h2data = NULL; /* stream socket */
		session->closed = true;
		for (h2data = ISC_LIST_HEAD(session->sstreams); h2data != NULL;
		     h2data = ISC_LIST_NEXT(h2data, link))
		{
			failed_httpstream_read_cb(h2data->psock, result,
						  session);
		}

		h2data = ISC_LIST_HEAD(session->sstreams);
		while (h2data != NULL) {
			isc_nmsocket_h2_t *next = ISC_LIST_NEXT(h2data, link);
			ISC_LIST_DEQUEUE(session->sstreams, h2data, link);
			/* Cleanup socket in place */
			atomic_store(&h2data->psock->active, false);
			atomic_store(&h2data->psock->closed, true);
			isc__nmsocket_detach(&h2data->psock);

			h2data = next;
		}
	}
	finish_http2_session(session);
}

static const bool base64url_validation_table[256] = {
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, true,  false, false, true,  true,
	true,  true,  true,  true,  true,  true,  true,	 true,	false, false,
	false, false, false, false, false, true,  true,	 true,	true,  true,
	true,  true,  true,  true,  true,  true,  true,	 true,	true,  true,
	true,  true,  true,  true,  true,  true,  true,	 true,	true,  true,
	true,  false, false, false, false, true,  false, true,	true,  true,
	true,  true,  true,  true,  true,  true,  true,	 true,	true,  true,
	true,  true,  true,  true,  true,  true,  true,	 true,	true,  true,
	true,  true,  true,  false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false
};

char *
isc__nm_base64url_to_base64(isc_mem_t *mem, const char *base64url,
			    const size_t base64url_len, size_t *res_len) {
	char *res = NULL;
	size_t i, k, len;

	if (mem == NULL || base64url == NULL || base64url_len == 0) {
		return (NULL);
	}

	len = base64url_len % 4 ? base64url_len + (4 - base64url_len % 4)
				: base64url_len;
	res = isc_mem_allocate(mem, len + 1); /* '\0' */

	for (i = 0; i < base64url_len; i++) {
		switch (base64url[i]) {
		case '-':
			res[i] = '+';
			break;
		case '_':
			res[i] = '/';
			break;
		default:
			if (base64url_validation_table[(size_t)base64url[i]]) {
				res[i] = base64url[i];
			} else {
				isc_mem_free(mem, res);
				return (NULL);
			}
			break;
		}
	}

	if (base64url_len % 4 != 0) {
		for (k = 0; k < (4 - base64url_len % 4); k++, i++) {
			res[i] = '=';
		}
	}

	INSIST(i == len);

	if (res_len) {
		*res_len = len;
	}

	res[len] = '\0';

	return (res);
}

char *
isc__nm_base64_to_base64url(isc_mem_t *mem, const char *base64,
			    const size_t base64_len, size_t *res_len) {
	char *res = NULL;
	size_t i;

	if (mem == NULL || base64 == NULL || base64_len == 0) {
		return (NULL);
	}

	res = isc_mem_allocate(mem, base64_len + 1); /* '\0' */

	for (i = 0; i < base64_len; i++) {
		switch (base64[i]) {
		case '+':
			res[i] = '-';
			break;
		case '/':
			res[i] = '_';
			break;
		case '=':
			goto end;
			break;
		default:
			/* All other characters from the alphabet are the same
			 * for both base64 and base64url, so we can reuse the
			 * validation table for the rest of the characters. */
			if (base64[i] != '-' && base64[i] != '_' &&
			    base64url_validation_table[(size_t)base64[i]])
			{
				res[i] = base64[i];
			} else {
				isc_mem_free(mem, res);
				return (NULL);
			}
			break;
		}
	}
end:
	if (res_len) {
		*res_len = i;
	}

	res[i] = '\0';

	return (res);
}

/* DoH GET Query String Scanner-less Recursive Descent Parser/Verifier

It is based on the following grammar (using WSN/EBNF):

S                = query-string.
query-string     = ['?'] { key-value-pair } EOF.
key-value-pair   = key '=' value [ '&' ].
key              = ('_' | alpha) { '_' | alnum}.
value            = value-char {value-char}.
value-char       = unreserved-char | percent-charcode.
unreserved-char  = alnum |'_' | '.' | '-' | '~'. (* RFC3986, Section 2.3 *)
percent-charcode = '%' hexdigit hexdigit.
...

Should be good enough.
*/

typedef struct isc_doh_query_parser_state {
	const char *str;

	const char *last_key;
	size_t last_key_len;

	const char *last_value;
	size_t last_value_len;

	bool doh_query_found;
	const char *doh_query;
	size_t doh_query_length;
} isc_doh_query_parser_state_t;

#define MATCH(ch)      (st->str[0] == (ch))
#define MATCH_ALPHA()  isalpha(st->str[0])
#define MATCH_ALNUM()  isalnum(st->str[0])
#define MATCH_XDIGIT() isxdigit(st->str[0])
#define ADVANCE()      st->str++
#define GETP()	       (st->str)

static bool
rule_query_string(isc_doh_query_parser_state_t *st);

bool
isc__nm_parse_doh_query_string(const char *query_string, const char **start,
			       size_t *len) {
	isc_doh_query_parser_state_t state;

	REQUIRE(start != NULL);
	REQUIRE(len != 0);

	if (query_string == NULL || *query_string == '\0' || start == NULL ||
	    len == 0) {
		return (false);
	}

	memset(&state, 0, sizeof(state));
	state.str = query_string;
	if (!rule_query_string(&state)) {
		return (false);
	}

	if (!state.doh_query_found) {
		return (false);
	}

	*start = state.doh_query;
	*len = state.doh_query_length;

	return (true);
}

static bool
rule_key_value_pair(isc_doh_query_parser_state_t *st);

static bool
rule_key(isc_doh_query_parser_state_t *st);

static bool
rule_value(isc_doh_query_parser_state_t *st);

static bool
rule_value_char(isc_doh_query_parser_state_t *st);

static bool
rule_percent_charcode(isc_doh_query_parser_state_t *st);

static bool
rule_unreserved_char(isc_doh_query_parser_state_t *st);

static bool
rule_query_string(isc_doh_query_parser_state_t *st) {
	if (MATCH('?')) {
		ADVANCE();
	}

	while (rule_key_value_pair(st)) {
		/* skip */;
	}

	if (!MATCH('\0')) {
		return (false);
	}

	ADVANCE();
	return (true);
}

static bool
rule_key_value_pair(isc_doh_query_parser_state_t *st) {
	if (!rule_key(st)) {
		return (false);
	}

	if (MATCH('=')) {
		ADVANCE();
	} else {
		return (false);
	}

	if (rule_value(st)) {
		const char dns[] = "dns";
		if (st->last_key_len == sizeof(dns) - 1 &&
		    memcmp(st->last_key, dns, sizeof(dns) - 1) == 0)
		{
			st->doh_query_found = true;
			st->doh_query = st->last_value;
			st->doh_query_length = st->last_value_len;
		}
	} else {
		return (false);
	}

	if (MATCH('&')) {
		ADVANCE();
	}

	return (true);
}

static bool
rule_key(isc_doh_query_parser_state_t *st) {
	if (MATCH('_') || MATCH_ALPHA()) {
		st->last_key = GETP();
		ADVANCE();
	} else {
		return (false);
	}

	while (MATCH('_') || MATCH_ALNUM()) {
		ADVANCE();
	}

	st->last_key_len = GETP() - st->last_key;
	return (true);
}

static bool
rule_value(isc_doh_query_parser_state_t *st) {
	const char *s = GETP();
	if (!rule_value_char(st)) {
		return (false);
	}

	st->last_value = s;
	while (rule_value_char(st)) {
		/* skip */;
	}
	st->last_value_len = GETP() - st->last_value;
	return (true);
}

static bool
rule_value_char(isc_doh_query_parser_state_t *st) {
	if (rule_unreserved_char(st)) {
		return (true);
	}

	return (rule_percent_charcode(st));
}

static bool
rule_unreserved_char(isc_doh_query_parser_state_t *st) {
	if (MATCH_ALNUM() || MATCH('_') || MATCH('.') || MATCH('-') ||
	    MATCH('~')) {
		ADVANCE();
		return (true);
	}
	return (false);
}

static bool
rule_percent_charcode(isc_doh_query_parser_state_t *st) {
	if (MATCH('%')) {
		ADVANCE();
	} else {
		return (false);
	}

	if (!MATCH_XDIGIT()) {
		return (false);
	}
	ADVANCE();

	if (!MATCH_XDIGIT()) {
		return (false);
	}
	ADVANCE();

	return (true);
}
