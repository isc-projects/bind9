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

#include <nghttp2/nghttp2.h>
#include <signal.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/base64.h>
#include <isc/netmgr.h>
#include <isc/print.h>
#include <isc/url.h>

#include "netmgr-int.h"

#define AUTHEXTRA 7

typedef struct http2_client_stream {
	isc_nm_recv_cb_t cb;
	void *cbarg;

	char *uri;
	isc_url_parser_t up;

	char *authority;
	size_t authoritylen;
	char *path;

	uint8_t rbuf[65535];
	size_t rbufsize;

	size_t pathlen;
	int32_t stream_id;
	isc_region_t *postdata;
	size_t postdata_pos;
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
	http2_client_stream_t *cstream;
	ISC_LIST(isc_nmsocket_h2_t) sstreams;

	isc_nmhandle_t *handle;
	isc_nmsocket_t *serversocket;

	isc_region_t r;
	uint8_t buf[65535];
	size_t bufsize;

	SSL_CTX *ctx;
};

static bool
http2_do_bio(isc_nm_http2_session_t *session);

static isc_result_t
get_http2_client_stream(isc_mem_t *mctx, http2_client_stream_t **streamp,
			const char *uri, uint16_t *port) {
	http2_client_stream_t *stream = NULL;
	int rv;

	REQUIRE(streamp != NULL && *streamp == NULL);
	REQUIRE(uri != NULL);
	REQUIRE(port != NULL);

	stream = isc_mem_get(mctx, sizeof(http2_client_stream_t));
	*stream = (http2_client_stream_t){ .stream_id = -1 };

	stream->uri = isc_mem_strdup(mctx, uri);

	rv = isc_url_parse(stream->uri, strlen(stream->uri), 0, &stream->up);
	if (rv != 0) {
		isc_mem_put(mctx, stream, sizeof(http2_client_stream_t));
		isc_mem_free(mctx, stream->uri);
		return (ISC_R_FAILURE);
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

	*port = 443;
	if ((stream->up.field_set & (1 << ISC_UF_PORT)) != 0) {
		*port = stream->up.port;
	}

	*streamp = stream;

	return (ISC_R_SUCCESS);
}

static void
put_http2_client_stream(isc_mem_t *mctx, http2_client_stream_t *stream) {
	isc_mem_put(mctx, stream->path, stream->pathlen);
	isc_mem_put(mctx, stream->authority, stream->authoritylen + AUTHEXTRA);
	isc_mem_put(mctx, stream, sizeof(http2_client_stream_t));
}

static void
delete_http2_session(isc_nm_http2_session_t *session) {
	if (session->handle != NULL) {
		isc_nm_pauseread(session->handle);
		isc_nmhandle_detach(&session->handle);
	}
	if (session->ngsession != NULL) {
		nghttp2_session_del(session->ngsession);
		session->ngsession = NULL;
	}
	if (session->cstream != NULL) {
		put_http2_client_stream(session->mctx, session->cstream);
		session->cstream = NULL;
	}

	/*
	 * There might be leftover callbacks waiting to be received
	 */
	if (session->sending) {
		session->closed = true;
	} else if (!session->reading) {
		session->magic = 0;
		isc_mem_putanddetach(&session->mctx, session,
				     sizeof(isc_nm_http2_session_t));
	}
}

static int
on_data_chunk_recv_callback(nghttp2_session *ngsession, uint8_t flags,
			    int32_t stream_id, const uint8_t *data, size_t len,
			    void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;

	UNUSED(ngsession);
	UNUSED(flags);

	if (session->cstream != NULL) {
		if (session->cstream->stream_id == stream_id) {
			/* TODO buffer overrun! */
			memmove(session->cstream->rbuf +
					session->cstream->rbufsize,
				data, len);
			session->cstream->rbufsize += len;
		}
	} else {
		isc_nmsocket_h2_t *sock_h2 = ISC_LIST_HEAD(session->sstreams);
		while (sock_h2 != NULL) {
			if (stream_id == sock_h2->stream_id) {
				memmove(sock_h2->buf + sock_h2->bufsize, data,
					len);
				sock_h2->bufsize += len;
				break;
			}
			sock_h2 = ISC_LIST_NEXT(sock_h2, link);
		}
	}

	return (0);
}

static int
on_stream_close_callback(nghttp2_session *ngsession, int32_t stream_id,
			 uint32_t error_code, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;

	REQUIRE(VALID_HTTP2_SESSION(session));

	UNUSED(error_code);

	if (session->cstream != NULL) {
		if (session->cstream->stream_id == stream_id) {
			int rv;

			session->cstream->cb(
				NULL, ISC_R_SUCCESS,
				&(isc_region_t){ session->cstream->rbuf,
						 session->cstream->rbufsize },
				session->cstream->cbarg);
			rv = nghttp2_session_terminate_session(
				ngsession, NGHTTP2_NO_ERROR);
			if (rv != 0) {
				return (NGHTTP2_ERR_CALLBACK_FAILURE);
			}
		}
	} else {
		/* XXX */
	}

	/* XXXWPK TODO we need to close the session */

	return (0);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * NPN TLS extension client callback. We check that server advertised
 * the HTTP/2 protocol the nghttp2 library supports. If not, exit the
 * program.
 */
static int
select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
		     const unsigned char *in, unsigned int inlen, void *arg) {
	UNUSED(ssl);
	UNUSED(arg);

	if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
		/* TODO */
	}
	return (SSL_TLSEXT_ERR_OK);
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

/* Create SSL_CTX. */
static SSL_CTX *
create_ssl_ctx(void) {
	SSL_CTX *ssl_ctx = NULL;

	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	RUNTIME_CHECK(ssl_ctx != NULL);

	SSL_CTX_set_options(
		ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
				 SSL_OP_NO_COMPRESSION |
				 SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

	return (ssl_ctx);
}

static void
initialize_nghttp2_client_session(isc_nm_http2_session_t *session) {
	nghttp2_session_callbacks *callbacks = NULL;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, on_stream_close_callback);

	nghttp2_session_client_new(&session->ngsession, callbacks, session);

	nghttp2_session_callbacks_del(callbacks);
}

static void
send_client_connection_header(isc_nm_http2_session_t *session) {
	nghttp2_settings_entry iv[1] = {
		{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
	};
	int rv;

	rv = nghttp2_submit_settings(session->ngsession, NGHTTP2_FLAG_NONE, iv,
				     1);
	if (rv != 0) {
		/* TODO */
	}

	http2_do_bio(session);
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
client_post_read_callback(nghttp2_session *ngsession, int32_t stream_id,
			  uint8_t *buf, size_t length, uint32_t *data_flags,
			  nghttp2_data_source *source, void *user_data) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)user_data;

	REQUIRE(session->cstream != NULL);

	UNUSED(ngsession);
	UNUSED(source);

	if (session->cstream->stream_id == stream_id) {
		size_t len = session->cstream->postdata->length -
			     session->cstream->postdata_pos;

		if (len > length) {
			len = length;
		}

		memmove(buf,
			session->cstream->postdata->base +
				session->cstream->postdata_pos,
			len);
		session->cstream->postdata_pos += len;

		if (session->cstream->postdata_pos ==
		    session->cstream->postdata->length) {
			*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		}

		return (len);
	}

	return (0);
}

/* Send HTTP request to the remote peer */
static isc_result_t
client_submit_request(isc_nm_http2_session_t *session) {
	int32_t stream_id;
	http2_client_stream_t *stream = session->cstream;
	char *uri = stream->uri;
	isc_url_parser_t *up = &stream->up;
	nghttp2_data_provider dp;
	char p[64];

	snprintf(p, 64, "%u", stream->postdata->length);

	nghttp2_nv hdrs[] = {
		MAKE_NV2(":method", "POST"),
		MAKE_NV(":scheme", &uri[up->field_data[ISC_UF_SCHEMA].off],
			up->field_data[ISC_UF_SCHEMA].len),
		MAKE_NV(":authority", stream->authority, stream->authoritylen),
		MAKE_NV(":path", stream->path, stream->pathlen),
		MAKE_NV2("content-type", "application/dns-message"),
		MAKE_NV2("accept", "application/dns-message"),
		MAKE_NV("content-length", p, strlen(p)),
	};

	dp = (nghttp2_data_provider){ .read_callback =
					      client_post_read_callback };
	stream_id = nghttp2_submit_request(session->ngsession, NULL, hdrs, 7,
					   &dp, stream);
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
	UNUSED(result);

	if (result != ISC_R_SUCCESS) {
		session->reading = false;
		delete_http2_session(session);
		/* TODO callback! */
		return;
	}

	readlen = nghttp2_session_mem_recv(session->ngsession, region->base,
					   region->length);
	if (readlen < 0) {
		delete_http2_session(session);
		/* TODO callback! */
		return;
	}

	if (readlen < region->length) {
		INSIST(session->bufsize == 0);
		INSIST(region->length - readlen < 65535);
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
	UNUSED(result);

	session->sending = false;
	isc_mem_put(session->mctx, session->r.base, session->r.length);
	session->r.base = NULL;
	http2_do_bio(session);
}

static bool
http2_do_bio(isc_nm_http2_session_t *session) {
	REQUIRE(VALID_HTTP2_SESSION(session));

	if (session->closed ||
	    (nghttp2_session_want_read(session->ngsession) == 0 &&
	     nghttp2_session_want_write(session->ngsession) == 0))
	{
		delete_http2_session(session);
		return (false);
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
			return (false);
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
		INSIST(session->r.base == NULL);
		session->r.base = isc_mem_get(session->mctx, sz);
		session->r.length = sz;
		memmove(session->r.base, data, sz);
		session->sending = true;
		isc_nm_send(session->handle, &session->r, https_writecb,
			    session);
		return (true);
	}

	return (false);
}

static void
https_connect_cb(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	isc_nm_http2_session_t *session = (isc_nm_http2_session_t *)arg;

	if (result != ISC_R_SUCCESS) {
		delete_http2_session(session);
		return;
	}

	isc_nmhandle_attach(handle, &session->handle);

#if 0
/* TODO H2 */
#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	if (alpn == NULL) {
		SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
	}
#endif

	if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
		delete_http2_session(session);
		return;
	}
#endif

	initialize_nghttp2_client_session(session);
	send_client_connection_header(session);
	client_submit_request(session);
	http2_do_bio(session);
}

isc_result_t
isc_nm_httpsconnect(isc_nm_t *mgr, isc_nmiface_t *local, isc_nmiface_t *peer,
		    const char *uri, isc_nm_cb_t cb, void *cbarg,
		    unsigned int timeout, size_t extrahandlesize) {
	REQUIRE(VALID_NM(mgr));

	UNUSED(local);
	UNUSED(peer);
	UNUSED(uri);
	UNUSED(cb);
	UNUSED(cbarg);
	UNUSED(timeout);
	UNUSED(extrahandlesize);

	return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
isc_nm_doh_request(isc_nm_t *mgr, const char *uri, isc_region_t *region,
		   isc_nm_recv_cb_t cb, void *cbarg, SSL_CTX *ctx) {
	uint16_t port;
	char *host = NULL;
	isc_nm_http2_session_t *session = NULL;
	http2_client_stream_t *cstream = NULL;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	isc_sockaddr_t local, peer;
	isc_result_t result;
	int s;

	if (ctx == NULL) {
		ctx = create_ssl_ctx();
	}

	session = isc_mem_get(mgr->mctx, sizeof(isc_nm_http2_session_t));
	*session = (isc_nm_http2_session_t){ .magic = HTTP2_SESSION_MAGIC,
					     .ctx = ctx };
	isc_mem_attach(mgr->mctx, &session->mctx);

	result = get_http2_client_stream(mgr->mctx, &cstream, uri, &port);
	if (result != ISC_R_SUCCESS) {
		delete_http2_session(session);
		return (result);
	}

	cstream->postdata = region;
	cstream->postdata_pos = 0;
	cstream->cb = cb;
	cstream->cbarg = cbarg;

	session->cstream = cstream;

#ifndef WIN32 /* FIXME */
	hints = (struct addrinfo){ .ai_family = PF_UNSPEC,
				   .ai_socktype = SOCK_STREAM,
				   .ai_flags = AI_CANONNAME };
	host = isc_mem_strndup(mgr->mctx, cstream->authority,
			       cstream->authoritylen + 1);

	s = getaddrinfo(host, NULL, &hints, &res);
	isc_mem_free(mgr->mctx, host);
	if (s != 0) {
		delete_http2_session(session);
		return (ISC_R_FAILURE);
	}
#endif /* WIN32 */

	isc_sockaddr_fromsockaddr(&peer, res->ai_addr);
	isc_sockaddr_setport(&peer, port);
	isc_sockaddr_anyofpf(&local, res->ai_family);

	freeaddrinfo(res);

	result = isc_nm_tlsconnect(mgr, (isc_nmiface_t *)&local,
				   (isc_nmiface_t *)&peer, https_connect_cb,
				   session, ctx, 30000, 0);
	/* XXX: timeout is hard-coded to 30 seconds - make it a parameter */
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	return (ISC_R_SUCCESS);
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
	socket->h2 = (isc_nmsocket_h2_t){ .bufpos = 0,
					  .bufsize = 0,
					  .psock = socket,
					  .handler = NULL,
					  .request_path = NULL,
					  .query_data = NULL,
					  .stream_id = frame->hd.stream_id,
					  .session = session };

	ISC_LINK_INIT(&socket->h2, link);
	ISC_LIST_APPEND(session->sstreams, &socket->h2, link);
	nghttp2_session_set_stream_user_data(ngsession, frame->hd.stream_id,
					     socket);
	return (0);
}

static int
server_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
			  const uint8_t *name, size_t namelen,
			  const uint8_t *value, size_t valuelen, uint8_t flags,
			  void *user_data) {
	isc_nmsocket_t *socket = NULL;
	const char path[] = ":path";

	UNUSED(flags);
	UNUSED(user_data);

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
			break;
		}

		socket = nghttp2_session_get_stream_user_data(
			session, frame->hd.stream_id);
		if (socket == NULL || socket->h2.request_path != NULL) {
			break;
		}

		if (namelen == sizeof(path) - 1 &&
		    memcmp(path, name, namelen) == 0) {
			size_t j;
			for (j = 0; j < valuelen && value[j] != '?'; ++j)
				;
			socket->h2.request_path = isc_mem_strndup(
				socket->mgr->mctx, (const char *)value, j + 1);
			if (j < valuelen) {
				socket->h2.query_data = isc_mem_strndup(
					socket->mgr->mctx, (char *)value + j,
					valuelen - j);
			}
		}
		break;
	}

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
	int rv;
	nghttp2_data_provider data_prd;
	data_prd.source.ptr = socket;
	data_prd.read_callback = server_read_callback;

	rv = nghttp2_submit_response(ngsession, stream_id, nva, nvlen,
				     &data_prd);
	if (rv != 0) {
		return (-1);
	}
	return (0);
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
				 "<body><h1>404 Not Found</h1></body></html>";

static int
error_reply(nghttp2_session *ngsession, isc_nmsocket_t *socket) {
	const nghttp2_nv hdrs[] = { MAKE_NV2(":status", "404") };

	memmove(socket->h2.buf, ERROR_HTML, sizeof(ERROR_HTML));
	socket->h2.bufsize = sizeof(ERROR_HTML);
	socket->h2.bufpos = 0;

	server_send_response(ngsession, socket->h2.stream_id, hdrs,
			     sizeof(hdrs) / sizeof(nghttp2_nv), socket);
	return (0);
}

static int
server_on_request_recv(nghttp2_session *ngsession,
		       isc_nm_http2_session_t *session,
		       isc_nmsocket_t *socket) {
	isc_nm_http2_server_handler_t *handler = NULL;
	isc_nmhandle_t *handle = NULL;
	isc_sockaddr_t addr;

	if (!socket->h2.request_path) {
		if (error_reply(ngsession, socket) != 0) {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
		return (0);
	}

	for (handler = ISC_LIST_HEAD(session->serversocket->handlers);
	     handler != NULL; handler = ISC_LIST_NEXT(handler, link))
	{
		if (!strcmp(socket->h2.request_path, handler->path)) {
			break;
		}
	}

	if (handler == NULL) {
		if (error_reply(ngsession, socket) != 0) {
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		}
		return (0);
	}

	socket->extrahandlesize = handler->extrahandlesize;
	addr = isc_nmhandle_peeraddr(session->handle);
	handle = isc__nmhandle_get(socket, &addr, NULL);
	handler->cb(handle, ISC_R_SUCCESS,
		    &(isc_region_t){ socket->h2.buf, socket->h2.bufsize },
		    &(isc_region_t){ (unsigned char *)socket->h2.query_data,
				     strlen(socket->h2.query_data) + 1 },
		    handler->cbarg);
	return (0);
}

void
isc__nm_http_send(isc_nmhandle_t *handle, const isc_region_t *region,
		  isc_nm_cb_t cb, void *cbarg) {
	const nghttp2_nv hdrs[] = { MAKE_NV2(":status", "200") };
	isc_nmsocket_t *sock = handle->sock;

	/* TODO FIXME do it asynchronously!!! */
	memcpy(sock->h2.buf, region->base, region->length);
	sock->h2.bufsize = region->length;
	if (server_send_response(handle->httpsession->ngsession,
				 sock->h2.stream_id, hdrs,
				 sizeof(hdrs) / sizeof(nghttp2_nv), sock) != 0)
	{
		cb(handle, ISC_R_FAILURE, cbarg);
	} else {
		cb(handle, ISC_R_SUCCESS, cbarg);
	}
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

	nghttp2_session_callbacks_new(&callbacks);

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

	if (result != ISC_R_SUCCESS) {
		/* XXXWPK do nothing? */
		return (result);
	}

	session = isc_mem_get(httplistensock->mgr->mctx,
			      sizeof(isc_nm_http2_session_t));
	*session = (isc_nm_http2_session_t){ .magic = HTTP2_SESSION_MAGIC };
	initialize_nghttp2_server_session(session);

	isc_mem_attach(httplistensock->mgr->mctx, &session->mctx);
	isc_nmhandle_attach(handle, &session->handle);
	isc__nmsocket_attach(httplistensock, &session->serversocket);
	server_send_connection_header(session);

	/* TODO H2 */
	http2_do_bio(session);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_nm_listenhttps(isc_nm_t *mgr, isc_nmiface_t *iface, int backlog,
		   isc_quota_t *quota, SSL_CTX *ctx, isc_nmsocket_t **sockp) {
	isc_nmsocket_t *sock = NULL;
	isc_result_t result;

	isc_mem_get(mgr->mctx, sizeof(*sock));
	isc__nmsocket_init(sock, mgr, isc_nm_httplistener, iface);

	if (ctx != NULL) {
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

	handler = isc_mem_get(sock->mgr->mctx, sizeof(*handler));
	*handler = (isc_nm_http2_server_handler_t){
		.cb = cb,
		.cbarg = cbarg,
		.extrahandlesize = extrahandlesize,
		.path = isc_mem_strdup(sock->mgr->mctx, uri)
	};

	ISC_LINK_INIT(handler, link);
	ISC_LIST_APPEND(sock->handlers, handler, link);

	return (ISC_R_SUCCESS);
}

typedef struct {
	isc_nm_recv_cb_t cb;
	void *cbarg;
} cbarg_t;

static unsigned char doh_error[] =
	"<html><head><title>No request</title></head>"
	"<body><h1>No request</h1></body></html>";

static const isc_region_t doh_error_r = { doh_error, sizeof(doh_error) };

static void
https_sendcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	UNUSED(handle);
	UNUSED(result);
	UNUSED(cbarg);
}

/*
 * In DoH we just need to intercept the request - the response can be sent
 * to the client code via the nmhandle directly as it's always just the
 * http * content.
 */
static void
doh_callback(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *post,
	     isc_region_t *get, void *arg) {
	cbarg_t *dohcbarg = arg;
	isc_region_t *data = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	UNUSED(result);
	UNUSED(get);

	if (result != ISC_R_SUCCESS) {
		/* Shut down the client, then ourselves */
		dohcbarg->cb(NULL, result, NULL, dohcbarg->cbarg);
		/* XXXWPK FREE */
		return;
	}

	if (post != NULL) {
		data = post;
	} else if (get != NULL) {
		/* XXXWPK PARSE */
		data = NULL; /* FIXME */
	} else {
		/* Invalid request, just send the error response */
		isc_nm_send(handle, &doh_error_r, https_sendcb, dohcbarg);
		return;
	}

	dohcbarg->cb(handle, result, data, dohcbarg->cbarg);
}

isc_result_t
isc_nm_http_add_doh_endpoint(isc_nmsocket_t *sock, const char *uri,
			     isc_nm_recv_cb_t cb, void *cbarg,
			     size_t extrahandlesize) {
	isc_result_t result;
	cbarg_t *dohcbarg = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->type == isc_nm_httplistener);

	dohcbarg = isc_mem_get(sock->mgr->mctx, sizeof(cbarg_t));
	*dohcbarg = (cbarg_t){ cb, cbarg };

	result = isc_nm_http_add_endpoint(sock, uri, doh_callback, dohcbarg,
					  extrahandlesize);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(sock->mgr->mctx, dohcbarg, sizeof(cbarg_t));
	}

	return (result);
}
