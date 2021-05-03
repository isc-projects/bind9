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

#if HAVE_CMOCKA
#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <uv.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/mutex.h>
#include <isc/netmgr.h>
#include <isc/nonce.h>
#include <isc/os.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>

#include "uv_wrap.h"
#define KEEP_BEFORE

#include "../netmgr/http.c"
#include "../netmgr/netmgr-int.h"
#include "../netmgr/uv-compat.c"
#include "../netmgr/uv-compat.h"
#include "isctest.h"

#define MAX_NM 2

static isc_sockaddr_t tcp_listen_addr;

static uint64_t send_magic = 0;
static uint64_t stop_magic = 0;

static uv_buf_t send_msg = { .base = (char *)&send_magic,
			     .len = sizeof(send_magic) };

static atomic_int_fast64_t nsends = ATOMIC_VAR_INIT(0);
static atomic_int_fast64_t ssends = ATOMIC_VAR_INIT(0);
static atomic_int_fast64_t sreads = ATOMIC_VAR_INIT(0);
static atomic_int_fast64_t csends = ATOMIC_VAR_INIT(0);
static atomic_int_fast64_t creads = ATOMIC_VAR_INIT(0);
static atomic_int_fast64_t ctimeouts = ATOMIC_VAR_INIT(0);

static atomic_bool was_error;

static unsigned int workers = 0;

static bool reuse_supported = true;
static bool noanswer = false;

static atomic_bool POST = ATOMIC_VAR_INIT(true);

static atomic_bool slowdown = ATOMIC_VAR_INIT(false);

static atomic_bool use_TLS = ATOMIC_VAR_INIT(false);
static isc_tlsctx_t *server_tlsctx = NULL;
static isc_tlsctx_t *client_tlsctx = NULL;

/* Timeout for soft-timeout tests (0.05 seconds) */
#define T_SOFT 50

#define NSENDS	100
#define NWRITES 10

#define DOH_PATH "/dns-query"

#define CHECK_RANGE_FULL(v)                                       \
	{                                                         \
		int __v = atomic_load(&v);                        \
		assert_true(__v > NSENDS * NWRITES * 10 / 100);   \
		assert_true(__v <= NSENDS * NWRITES * 110 / 100); \
	}

#define CHECK_RANGE_HALF(v)                                       \
	{                                                         \
		int __v = atomic_load(&v);                        \
		assert_true(__v > NSENDS * NWRITES * 5 / 100);    \
		assert_true(__v <= NSENDS * NWRITES * 110 / 100); \
	}

/* Enable this to print values while running tests */
#undef PRINT_DEBUG
#ifdef PRINT_DEBUG
#define X(v) fprintf(stderr, #v " = %" PRIu64 "\n", atomic_load(&v))
#else
#define X(v)
#endif

typedef struct csdata {
	isc_nm_recv_cb_t reply_cb;
	void *cb_arg;
	isc_region_t region;
} csdata_t;

static void
connect_send_cb(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	csdata_t data;

	REQUIRE(VALID_NMHANDLE(handle));

	memmove(&data, arg, sizeof(data));
	isc_mem_put(handle->sock->mgr->mctx, arg, sizeof(data));
	if (result != ISC_R_SUCCESS) {
		atomic_store(&slowdown, true);
		goto error;
	}

	result = isc__nm_http_request(handle, &data.region, data.reply_cb,
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

static void
connect_send_request(isc_nm_t *mgr, const char *uri, bool post,
		     isc_region_t *region, isc_nm_recv_cb_t cb, void *cbarg,
		     bool tls, unsigned int timeout) {
	isc_region_t copy;
	csdata_t *data = NULL;
	isc_tlsctx_t *ctx = NULL;

	copy = (isc_region_t){ .base = isc_mem_get(mgr->mctx, region->length),
			       .length = region->length };
	memmove(copy.base, region->base, region->length);
	data = isc_mem_get(mgr->mctx, sizeof(*data));
	*data = (csdata_t){ .reply_cb = cb, .cb_arg = cbarg, .region = copy };
	if (tls) {
		ctx = client_tlsctx;
	}

	isc_nm_httpconnect(mgr, NULL, (isc_nmiface_t *)&tcp_listen_addr, uri,
			   post, connect_send_cb, data, ctx, timeout, 0);
}

static int
setup_ephemeral_port(isc_sockaddr_t *addr, sa_family_t family) {
	isc_result_t result;
	socklen_t addrlen = sizeof(*addr);
	int fd;
	int r;

	isc_sockaddr_fromin6(addr, &in6addr_loopback, 0);

	fd = socket(AF_INET6, family, 0);
	if (fd < 0) {
		perror("setup_ephemeral_port: socket()");
		return (-1);
	}

	r = bind(fd, (const struct sockaddr *)&addr->type.sa,
		 sizeof(addr->type.sin6));
	if (r != 0) {
		perror("setup_ephemeral_port: bind()");
		isc__nm_closesocket(fd);
		return (r);
	}

	r = getsockname(fd, (struct sockaddr *)&addr->type.sa, &addrlen);
	if (r != 0) {
		perror("setup_ephemeral_port: getsockname()");
		isc__nm_closesocket(fd);
		return (r);
	}

	result = isc__nm_socket_reuse(fd);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTIMPLEMENTED) {
		fprintf(stderr,
			"setup_ephemeral_port: isc__nm_socket_reuse(): %s",
			isc_result_totext(result));
		close(fd);
		return (-1);
	}

	result = isc__nm_socket_reuse_lb(fd);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTIMPLEMENTED) {
		fprintf(stderr,
			"setup_ephemeral_port: isc__nm_socket_reuse_lb(): %s",
			isc_result_totext(result));
		close(fd);
		return (-1);
	}
	if (result == ISC_R_NOTIMPLEMENTED) {
		reuse_supported = false;
	}

#if IPV6_RECVERR
#define setsockopt_on(socket, level, name) \
	setsockopt(socket, level, name, &(int){ 1 }, sizeof(int))

	r = setsockopt_on(fd, IPPROTO_IPV6, IPV6_RECVERR);
	if (r != 0) {
		perror("setup_ephemeral_port");
		close(fd);
		return (r);
	}
#endif

	return (fd);
}

static int
_setup(void **state) {
	char *p = NULL;

	UNUSED(state);

	if (workers == 0) {
		workers = isc_os_ncpus();
	}
	p = getenv("ISC_TASK_WORKERS");
	if (p != NULL) {
		workers = atoi(p);
	}
	INSIST(workers != 0);

	if (isc_test_begin(NULL, false, workers) != ISC_R_SUCCESS) {
		return (-1);
	}

	signal(SIGPIPE, SIG_IGN);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

/* Generic */

static void
noop_read_cb(isc_nmhandle_t *handle, isc_result_t result, isc_region_t *region,
	     void *cbarg) {
	UNUSED(handle);
	UNUSED(result);
	UNUSED(region);
	UNUSED(cbarg);
}

thread_local uint8_t tcp_buffer_storage[4096];
thread_local size_t tcp_buffer_length = 0;

static int
nm_setup(void **state) {
	size_t nworkers = ISC_MAX(ISC_MIN(workers, 32), 1);
	int tcp_listen_sock = -1;
	isc_nm_t **nm = NULL;

	tcp_listen_addr = (isc_sockaddr_t){ .length = 0 };
	tcp_listen_sock = setup_ephemeral_port(&tcp_listen_addr, SOCK_STREAM);
	if (tcp_listen_sock < 0) {
		return (-1);
	}
	close(tcp_listen_sock);
	tcp_listen_sock = -1;

	atomic_store(&nsends, NSENDS * NWRITES);

	atomic_store(&csends, 0);
	atomic_store(&creads, 0);
	atomic_store(&sreads, 0);
	atomic_store(&ssends, 0);
	atomic_store(&ctimeouts, 0);

	atomic_store(&was_error, false);

	atomic_store(&POST, false);
	atomic_store(&use_TLS, false);

	noanswer = false;

	isc_nonce_buf(&send_magic, sizeof(send_magic));
	isc_nonce_buf(&stop_magic, sizeof(stop_magic));
	if (send_magic == stop_magic) {
		return (-1);
	}

	nm = isc_mem_get(test_mctx, MAX_NM * sizeof(nm[0]));
	for (size_t i = 0; i < MAX_NM; i++) {
		nm[i] = isc_nm_start(test_mctx, nworkers);
		assert_non_null(nm[i]);
	}

	server_tlsctx = NULL;
	isc_tlsctx_createserver(NULL, NULL, &server_tlsctx);
	client_tlsctx = NULL;
	isc_tlsctx_createclient(&client_tlsctx);
	isc_tlsctx_enable_http2client_alpn(client_tlsctx);

	*state = nm;

	return (0);
}

static int
nm_teardown(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;

	for (size_t i = 0; i < MAX_NM; i++) {
		isc_nm_destroy(&nm[i]);
		assert_null(nm[i]);
	}
	isc_mem_put(test_mctx, nm, MAX_NM * sizeof(nm[0]));

	if (server_tlsctx != NULL) {
		isc_tlsctx_free(&server_tlsctx);
	}
	if (client_tlsctx != NULL) {
		isc_tlsctx_free(&client_tlsctx);
	}

	return (0);
}

thread_local size_t nwrites = NWRITES;

static void
sockaddr_to_url(isc_sockaddr_t *sa, const bool https, char *outbuf,
		size_t outbuf_len, const char *append) {
	uint16_t port;
	char saddr[INET6_ADDRSTRLEN] = { 0 };
	int family;

	if (sa == NULL || outbuf == NULL || outbuf_len == 0) {
		return;
	}

	family = ((struct sockaddr *)&sa->type.sa)->sa_family;

	port = ntohs(family == AF_INET ? sa->type.sin.sin_port
				       : sa->type.sin6.sin6_port);
	inet_ntop(family,
		  family == AF_INET
			  ? (struct sockaddr *)&sa->type.sin.sin_addr
			  : (struct sockaddr *)&sa->type.sin6.sin6_addr,
		  saddr, sizeof(saddr));

	snprintf(outbuf, outbuf_len, "%s://%s%s%s:%u%s",
		 https ? "https" : "http", family == AF_INET ? "" : "[", saddr,
		 family == AF_INET ? "" : "]", port, append ? append : "");
}

static void
doh_receive_reply_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		     isc_region_t *region, void *cbarg) {
	assert_non_null(handle);
	UNUSED(cbarg);
	UNUSED(region);

	(void)atomic_fetch_sub(&nsends, 1);

	if (eresult == ISC_R_SUCCESS) {
		atomic_fetch_add(&csends, 1);
		atomic_fetch_add(&creads, 1);
		isc_nm_resumeread(handle);
	} else {
		/* We failed to connect; try again */
		atomic_store(&was_error, true);
	}
}

static void
doh_reply_sent_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	assert_non_null(handle);

	if (eresult == ISC_R_SUCCESS) {
		atomic_fetch_add(&ssends, 1);
	}
}

static void
doh_receive_request_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	UNUSED(cbarg);
	assert_non_null(handle);

	if (eresult != ISC_R_SUCCESS) {
		atomic_store(&was_error, true);
		return;
	}

	atomic_fetch_add(&sreads, 1);

	memmove(tcp_buffer_storage + tcp_buffer_length, region->base,
		region->length);
	tcp_buffer_length += region->length;

	while (tcp_buffer_length >= sizeof(magic)) {
		magic = *(uint64_t *)tcp_buffer_storage;
		assert_true(magic == stop_magic || magic == send_magic);

		tcp_buffer_length -= sizeof(magic);
		memmove(tcp_buffer_storage, tcp_buffer_storage + sizeof(magic),
			tcp_buffer_length);

		if (magic == send_magic) {
			if (!noanswer) {
				isc_nm_send(handle, region, doh_reply_sent_cb,
					    NULL);
			}
			return;
		} else if (magic == stop_magic) {
			/*
			 * We are done, so we don't send anything back.
			 * There should be no more packets in the buffer.
			 */
			assert_int_equal(tcp_buffer_length, 0);
		}
	}
}

static void
mock_doh_uv_tcp_bind(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;

	WILL_RETURN(uv_tcp_bind, UV_EADDRINUSE);

	result = isc_nm_listenhttp(listen_nm, (isc_nmiface_t *)&tcp_listen_addr,
				   0, NULL, NULL, &listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(listen_sock);

	RESET_RETURN;
}

static void
doh_noop(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	char req_url[256];

	result = isc_nm_listenhttp(listen_nm, (isc_nmiface_t *)&tcp_listen_addr,
				   0, NULL, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_nm_http_endpoint(listen_sock, DOH_PATH, noop_read_cb, NULL,
				      0);

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);

	sockaddr_to_url(&tcp_listen_addr, false, req_url, sizeof(req_url),
			DOH_PATH);
	connect_send_request(connect_nm, req_url, atomic_load(&POST),
			     &(isc_region_t){ .base = (uint8_t *)send_msg.base,
					      .length = send_msg.len },
			     noop_read_cb, NULL, atomic_load(&use_TLS), 30000);

	isc_nm_closedown(connect_nm);

	assert_int_equal(0, atomic_load(&csends));
	assert_int_equal(0, atomic_load(&creads));
	assert_int_equal(0, atomic_load(&sreads));
	assert_int_equal(0, atomic_load(&ssends));
}

static void
doh_noop_POST(void **state) {
	atomic_store(&POST, true);
	doh_noop(state);
}

static void
doh_noop_GET(void **state) {
	atomic_store(&POST, false);
	doh_noop(state);
}

static void
doh_noresponse(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	char req_url[256];

	result = isc_nm_listenhttp(listen_nm, (isc_nmiface_t *)&tcp_listen_addr,
				   0, NULL, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH, noop_read_cb, NULL,
				      0);
	assert_int_equal(result, ISC_R_SUCCESS);

	sockaddr_to_url(&tcp_listen_addr, false, req_url, sizeof(req_url),
			DOH_PATH);
	connect_send_request(connect_nm, req_url, atomic_load(&POST),
			     &(isc_region_t){ .base = (uint8_t *)send_msg.base,
					      .length = send_msg.len },
			     noop_read_cb, NULL, atomic_load(&use_TLS), 30000);

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
	isc_nm_closedown(connect_nm);
}

static void
doh_noresponse_POST(void **state) {
	atomic_store(&POST, true);
	doh_noresponse(state);
}

static void
doh_noresponse_GET(void **state) {
	atomic_store(&POST, false);
	doh_noresponse(state);
}

static void
timeout_query_sent_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	assert_non_null(handle);

	if (eresult == ISC_R_SUCCESS) {
		atomic_fetch_add(&csends, 1);
	}

	isc_nmhandle_detach(&handle);
}

static void
timeout_retry_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		 isc_region_t *region, void *arg) {
	UNUSED(region);
	UNUSED(arg);

	assert_non_null(handle);

	atomic_fetch_add(&ctimeouts, 1);

	if (eresult == ISC_R_TIMEDOUT && atomic_load(&ctimeouts) < 5) {
		isc_nmhandle_settimeout(handle, T_SOFT);
		return;
	}

	isc_nmhandle_detach(&handle);
}

static void
timeout_request_cb(isc_nmhandle_t *handle, isc_result_t result, void *arg) {
	isc_nmhandle_t *sendhandle = NULL;
	isc_nmhandle_t *readhandle = NULL;

	REQUIRE(VALID_NMHANDLE(handle));

	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	isc_nmhandle_attach(handle, &sendhandle);
	isc_nm_send(handle,
		    &(isc_region_t){ .base = (uint8_t *)send_msg.base,
				     .length = send_msg.len },
		    timeout_query_sent_cb, arg);

	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, timeout_retry_cb, NULL);
	return;

error:
	atomic_store(&was_error, true);
}

static void
doh_timeout_recovery(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	isc_tlsctx_t *ctx = atomic_load(&use_TLS) ? server_tlsctx : NULL;
	char req_url[256];

	result = isc_nm_listenhttp(listen_nm, (isc_nmiface_t *)&tcp_listen_addr,
				   0, NULL, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Accept connections but don't send responses, forcing client
	 * reads to time out.
	 */
	noanswer = true;
	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Shorten all the TCP client timeouts to 0.05 seconds.
	 * timeout_retry_cb() will give up after five timeouts.
	 */
	isc_nm_settimeouts(connect_nm, T_SOFT, T_SOFT, T_SOFT, T_SOFT);
	sockaddr_to_url(&tcp_listen_addr, false, req_url, sizeof(req_url),
			DOH_PATH);
	isc_nm_httpconnect(connect_nm, NULL, (isc_nmiface_t *)&tcp_listen_addr,
			   req_url, atomic_load(&POST), timeout_request_cb,
			   NULL, ctx, T_SOFT, 0);

	/*
	 * Sleep until sends reaches 5.
	 */
	for (size_t i = 0; i < 1000; i++) {
		if (atomic_load(&ctimeouts) == 5) {
			break;
		}
		isc_test_nap(1000);
	}
	assert_true(atomic_load(&ctimeouts) == 5);

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
	isc_nm_closedown(connect_nm);
}

static void
doh_timeout_recovery_POST(void **state) {
	atomic_store(&POST, true);
	doh_timeout_recovery(state);
}

static void
doh_timeout_recovery_GET(void **state) {
	atomic_store(&POST, false);
	doh_timeout_recovery(state);
}

static void
doh_receive_send_reply_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  isc_region_t *region, void *cbarg) {
	int_fast64_t sends = atomic_fetch_sub(&nsends, 1);
	assert_non_null(handle);
	UNUSED(region);

	if (eresult == ISC_R_SUCCESS) {
		atomic_fetch_add(&csends, 1);
		atomic_fetch_add(&creads, 1);
		if (sends > 0) {
			size_t i;
			for (i = 0; i < NWRITES / 2; i++) {
				eresult = isc__nm_http_request(
					handle,
					&(isc_region_t){
						.base = (uint8_t *)send_msg.base,
						.length = send_msg.len },
					doh_receive_send_reply_cb, cbarg);
				assert_true(eresult == ISC_R_SUCCESS);
			}
		}
	} else {
		atomic_store(&was_error, true);
	}
}

static isc_threadresult_t
doh_connect_thread(isc_threadarg_t arg) {
	isc_nm_t *connect_nm = (isc_nm_t *)arg;
	char req_url[256];
	int64_t sends = atomic_load(&nsends);

	sockaddr_to_url(&tcp_listen_addr, atomic_load(&use_TLS), req_url,
			sizeof(req_url), DOH_PATH);

	while (sends > 0) {
		/*
		 * We need to back off and slow down if we start getting
		 * errors, to prevent a thundering herd problem.
		 */
		if (atomic_load(&slowdown)) {
			isc_test_nap(1000 * workers);
			atomic_store(&slowdown, false);
		}
		connect_send_request(
			connect_nm, req_url, atomic_load(&POST),
			&(isc_region_t){ .base = (uint8_t *)send_msg.base,
					 .length = send_msg.len },
			doh_receive_send_reply_cb, NULL, atomic_load(&use_TLS),
			30000);
		sends = atomic_load(&nsends);
	}

	return ((isc_threadresult_t)0);
}

static void
doh_recv_one(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	char req_url[256];

	atomic_store(&nsends, 1);

	result = isc_nm_listenhttp(
		listen_nm, (isc_nmiface_t *)&tcp_listen_addr, 0, NULL,
		atomic_load(&use_TLS) ? server_tlsctx : NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	sockaddr_to_url(&tcp_listen_addr, atomic_load(&use_TLS), req_url,
			sizeof(req_url), DOH_PATH);
	connect_send_request(connect_nm, req_url, atomic_load(&POST),
			     &(isc_region_t){ .base = (uint8_t *)send_msg.base,
					      .length = send_msg.len },
			     doh_receive_reply_cb, NULL, atomic_load(&use_TLS),
			     30000);

	while (atomic_load(&nsends) > 0) {
		if (atomic_load(&was_error)) {
			break;
		}
		isc_thread_yield();
	}

	while (atomic_load(&ssends) != 1 || atomic_load(&sreads) != 1 ||
	       atomic_load(&csends) != 1)
	{
		if (atomic_load(&was_error)) {
			break;
		}
		isc_thread_yield();
	}

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
	isc_nm_closedown(connect_nm);

	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	assert_int_equal(atomic_load(&csends), 1);
	assert_int_equal(atomic_load(&creads), 1);
	assert_int_equal(atomic_load(&sreads), 1);
	assert_int_equal(atomic_load(&ssends), 1);
}

static void
doh_recv_one_POST(void **state) {
	atomic_store(&POST, true);
	doh_recv_one(state);
}

static void
doh_recv_one_GET(void **state) {
	atomic_store(&POST, false);
	doh_recv_one(state);
}

static void
doh_recv_one_POST_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, true);
	doh_recv_one(state);
}

static void
doh_recv_one_GET_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, false);
	doh_recv_one(state);
}

static void
doh_connect_send_two_requests_cb(isc_nmhandle_t *handle, isc_result_t result,
				 void *arg) {
	REQUIRE(VALID_NMHANDLE(handle));
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	result = isc__nm_http_request(
		handle,
		&(isc_region_t){ .base = (uint8_t *)send_msg.base,
				 .length = send_msg.len },
		doh_receive_reply_cb, arg);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}

	result = isc__nm_http_request(
		handle,
		&(isc_region_t){ .base = (uint8_t *)send_msg.base,
				 .length = send_msg.len },
		doh_receive_reply_cb, arg);
	if (result != ISC_R_SUCCESS) {
		goto error;
	}
	return;
error:
	atomic_store(&was_error, true);
}

static void
doh_recv_two(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	char req_url[256];
	isc_tlsctx_t *ctx = NULL;

	atomic_store(&nsends, 2);

	result = isc_nm_listenhttp(
		listen_nm, (isc_nmiface_t *)&tcp_listen_addr, 0, NULL,
		atomic_load(&use_TLS) ? server_tlsctx : NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	sockaddr_to_url(&tcp_listen_addr, atomic_load(&use_TLS), req_url,
			sizeof(req_url), DOH_PATH);

	if (atomic_load(&use_TLS)) {
		ctx = client_tlsctx;
	}

	isc_nm_httpconnect(connect_nm, NULL, (isc_nmiface_t *)&tcp_listen_addr,
			   req_url, atomic_load(&POST),
			   doh_connect_send_two_requests_cb, NULL, ctx, 5000,
			   0);

	while (atomic_load(&nsends) > 0) {
		if (atomic_load(&was_error)) {
			break;
		}
		isc_thread_yield();
	}

	while (atomic_load(&ssends) != 2 || atomic_load(&sreads) != 2 ||
	       atomic_load(&csends) != 2)
	{
		if (atomic_load(&was_error)) {
			break;
		}
		isc_thread_yield();
	}

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
	isc_nm_closedown(connect_nm);

	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	assert_int_equal(atomic_load(&csends), 2);
	assert_int_equal(atomic_load(&creads), 2);
	assert_int_equal(atomic_load(&sreads), 2);
	assert_int_equal(atomic_load(&ssends), 2);
}

static void
doh_recv_two_POST(void **state) {
	atomic_store(&POST, true);
	doh_recv_two(state);
}

static void
doh_recv_two_GET(void **state) {
	atomic_store(&POST, false);
	doh_recv_two(state);
}

static void
doh_recv_two_POST_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, true);
	doh_recv_two(state);
}

static void
doh_recv_two_GET_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, false);
	doh_recv_two(state);
}

static void
doh_recv_send(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	size_t nthreads = ISC_MAX(ISC_MIN(workers, 32), 1);
	isc_thread_t threads[32] = { 0 };

	result = isc_nm_listenhttp(
		listen_nm, (isc_nmiface_t *)&tcp_listen_addr, 0, NULL,
		atomic_load(&use_TLS) ? server_tlsctx : NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_create(doh_connect_thread, connect_nm, &threads[i]);
	}

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_join(threads[i], NULL);
	}

	isc_nm_closedown(connect_nm);
	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);

	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	CHECK_RANGE_FULL(csends);
	CHECK_RANGE_FULL(creads);
	CHECK_RANGE_FULL(sreads);
	CHECK_RANGE_FULL(ssends);
}

static void
doh_recv_send_POST(void **state) {
	atomic_store(&POST, true);
	doh_recv_send(state);
}

static void
doh_recv_send_GET(void **state) {
	atomic_store(&POST, false);
	doh_recv_send(state);
}

static void
doh_recv_send_POST_TLS(void **state) {
	atomic_store(&POST, true);
	atomic_store(&use_TLS, true);
	doh_recv_send(state);
}

static void
doh_recv_send_GET_TLS(void **state) {
	atomic_store(&POST, false);
	atomic_store(&use_TLS, true);
	doh_recv_send(state);
}

static void
doh_recv_half_send(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	size_t nthreads = ISC_MAX(ISC_MIN(workers, 32), 1);
	isc_thread_t threads[32] = { 0 };

	result = isc_nm_listenhttp(
		listen_nm, (isc_nmiface_t *)&tcp_listen_addr, 0, NULL,
		atomic_load(&use_TLS) ? server_tlsctx : NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_create(doh_connect_thread, connect_nm, &threads[i]);
	}

	while (atomic_load(&nsends) >= (NSENDS * NWRITES) / 2) {
		isc_thread_yield();
	}

	isc_nm_closedown(connect_nm);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_join(threads[i], NULL);
	}

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);

	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	CHECK_RANGE_HALF(csends);
	CHECK_RANGE_HALF(creads);
	CHECK_RANGE_HALF(sreads);
	CHECK_RANGE_HALF(ssends);
}

static void
doh_recv_half_send_POST(void **state) {
	atomic_store(&POST, true);
	doh_recv_half_send(state);
}

static void
doh_recv_half_send_GET(void **state) {
	atomic_store(&POST, false);
	doh_recv_half_send(state);
}

static void
doh_recv_half_send_POST_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, true);
	doh_recv_half_send(state);
}

static void
doh_recv_half_send_GET_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, false);
	doh_recv_half_send(state);
}

static void
doh_half_recv_send(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	size_t nthreads = ISC_MAX(ISC_MIN(workers, 32), 1);
	isc_thread_t threads[32] = { 0 };

	result = isc_nm_listenhttp(
		listen_nm, (isc_nmiface_t *)&tcp_listen_addr, 0, NULL,
		atomic_load(&use_TLS) ? server_tlsctx : NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_create(doh_connect_thread, connect_nm, &threads[i]);
	}

	while (atomic_load(&nsends) >= (NSENDS * NWRITES) / 2) {
		isc_thread_yield();
	}

	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_join(threads[i], NULL);
	}

	isc_nm_closedown(connect_nm);

	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	CHECK_RANGE_HALF(csends);
	CHECK_RANGE_HALF(creads);
	CHECK_RANGE_HALF(sreads);
	CHECK_RANGE_HALF(ssends);
}

static void
doh_half_recv_send_POST(void **state) {
	atomic_store(&POST, true);
	doh_half_recv_send(state);
}

static void
doh_half_recv_send_GET(void **state) {
	atomic_store(&POST, false);
	doh_half_recv_send(state);
}

static void
doh_half_recv_send_POST_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, true);
	doh_half_recv_send(state);
}

static void
doh_half_recv_send_GET_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, false);
	doh_half_recv_send(state);
}

static void
doh_half_recv_half_send(void **state) {
	isc_nm_t **nm = (isc_nm_t **)*state;
	isc_nm_t *listen_nm = nm[0];
	isc_nm_t *connect_nm = nm[1];
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *listen_sock = NULL;
	size_t nthreads = ISC_MAX(ISC_MIN(workers, 32), 1);
	isc_thread_t threads[32] = { 0 };

	result = isc_nm_listenhttp(
		listen_nm, (isc_nmiface_t *)&tcp_listen_addr, 0, NULL,
		atomic_load(&use_TLS) ? server_tlsctx : NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_nm_http_endpoint(listen_sock, DOH_PATH,
				      doh_receive_request_cb, NULL, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_create(doh_connect_thread, connect_nm, &threads[i]);
	}

	while (atomic_load(&nsends) >= (NSENDS * NWRITES) / 2) {
		isc_thread_yield();
	}

	isc_nm_closedown(connect_nm);
	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);

	for (size_t i = 0; i < nthreads; i++) {
		isc_thread_join(threads[i], NULL);
	}

	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	CHECK_RANGE_HALF(csends);
	CHECK_RANGE_HALF(creads);
	CHECK_RANGE_HALF(sreads);
	CHECK_RANGE_HALF(ssends);
}

static void
doh_half_recv_half_send_POST(void **state) {
	atomic_store(&POST, true);
	doh_half_recv_half_send(state);
}

static void
doh_half_recv_half_send_GET(void **state) {
	atomic_store(&POST, false);
	doh_half_recv_half_send(state);
}

static void
doh_half_recv_half_send_POST_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, true);
	doh_half_recv_half_send(state);
}

static void
doh_half_recv_half_send_GET_TLS(void **state) {
	atomic_store(&use_TLS, true);
	atomic_store(&POST, false);
	doh_half_recv_half_send(state);
}

static void
doh_parse_GET_query_string(void **state) {
	UNUSED(state);
	/* valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] =
			"dns=AAABAAABAAAAAAAAAWE-"
			"NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3"
			"QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == strlen(str) - 4);
		assert_true(memcmp(queryp, str + 4, len) == 0);
	}
	/* valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] =
			"?dns=AAABAAABAAAAAAAAAWE-"
			"NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3"
			"QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == strlen(str) - 6);
		assert_true(memcmp(queryp, str + 5, len) == 0);
	}
	/* valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123&dns=567";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == 3);
		assert_true(memcmp(queryp, "567", 3) == 0);
	}
	/* valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?name1=123&dns=567&name2=123&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == 3);
		assert_true(memcmp(queryp, "567", 3) == 0);
	}
	/* complex, but still valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] =
			"?title=%D0%92%D1%96%D0%B4%D1%81%D0%BE%D1%82%D0%BA%D0%"
			"BE%D0%B2%D0%B5_%D0%BA%D0%BE%D0%B4%D1%83%D0%B2%D0%B0%"
			"D0%BD%D0%BD%D1%8F&dns=123&veaction=edit&section=0";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == 3);
		assert_true(memcmp(queryp, "123", 3) == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] =
			"?title=%D0%92%D1%96%D0%B4%D1%81%D0%BE%D1%82%D0%BA%D0%"
			"BE%D0%B2%D0%B5_%D0%BA%D0%BE%D0%B4%D1%83%D0%B2%D0%B0%"
			"D0%BD%D0%BD%D1%8F&veaction=edit&section=0";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123&&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123%12&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == 6);
		assert_true(memcmp(queryp, "123%12", 6) == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123%ZZ&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123%%&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* invalid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123%AZ&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_false(ret);
		assert_null(queryp);
		assert_true(len == 0);
	}
	/* valid */
	{
		bool ret;
		const char *queryp = NULL;
		size_t len = 0;
		char str[] = "?dns=123%0AZ&";

		ret = isc__nm_parse_httpquery(str, &queryp, &len);
		assert_true(ret);
		assert_non_null(queryp);
		assert_true(len > 0);
		assert_true(len == 7);
		assert_true(memcmp(queryp, "123%0AZ", 7) == 0);
	}
}

static void
doh_base64url_to_base64(void **state) {
	UNUSED(state);
	char *res;
	size_t res_len = 0;
	/* valid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhc3VyZS4";
		char res_test[] = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhcw";
		char res_test[] = "YW55IGNhcm5hbCBwbGVhcw==";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhc3Vy";
		char res_test[] = "YW55IGNhcm5hbCBwbGVhc3Vy";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhc3U";
		char res_test[] = "YW55IGNhcm5hbCBwbGVhc3U=";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhcw";
		char res_test[] = "YW55IGNhcm5hbCBwbGVhcw==";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char test[] = "PDw_Pz8-Pg";
		char res_test[] = "PDw/Pz8+Pg==";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char test[] = "PDw_Pz8-Pg";
		char res_test[] = "PDw/Pz8+Pg==";

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  NULL);
		assert_non_null(res);
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* invalid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhcw";
		res_len = 0;

		res = isc__nm_base64url_to_base64(test_mctx, test, 0, &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		char test[] = "";
		res_len = 0;

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		char test[] = "PDw_Pz8-Pg==";
		res_len = 0;

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		char test[] = "PDw_Pz8-Pg%3D%3D"; /* percent encoded "==" at the
						     end */
		res_len = 0;

		res = isc__nm_base64url_to_base64(test_mctx, test, strlen(test),
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		res_len = 0;

		res = isc__nm_base64url_to_base64(test_mctx, NULL, 31231,
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
}

static void
doh_base64_to_base64url(void **state) {
	char *res;
	size_t res_len = 0;
	UNUSED(state);
	/* valid */
	{
		char res_test[] = "YW55IGNhcm5hbCBwbGVhc3VyZS4";
		char test[] = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char res_test[] = "YW55IGNhcm5hbCBwbGVhcw";
		char test[] = "YW55IGNhcm5hbCBwbGVhcw==";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char res_test[] = "YW55IGNhcm5hbCBwbGVhc3Vy";
		char test[] = "YW55IGNhcm5hbCBwbGVhc3Vy";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char res_test[] = "YW55IGNhcm5hbCBwbGVhc3U";
		char test[] = "YW55IGNhcm5hbCBwbGVhc3U=";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char res_test[] = "YW55IGNhcm5hbCBwbGVhcw";
		char test[] = "YW55IGNhcm5hbCBwbGVhcw==";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char res_test[] = "PDw_Pz8-Pg";
		char test[] = "PDw/Pz8+Pg==";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_non_null(res);
		assert_true(res_len == strlen(res_test));
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* valid */
	{
		char res_test[] = "PDw_Pz8-Pg";
		char test[] = "PDw/Pz8+Pg==";

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  NULL);
		assert_non_null(res);
		assert_true(strcmp(res, res_test) == 0);
		isc_mem_free(test_mctx, res);
	}
	/* invalid */
	{
		char test[] = "YW55IGNhcm5hbCBwbGVhcw";
		res_len = 0;

		res = isc__nm_base64_to_base64url(test_mctx, test, 0, &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		char test[] = "";
		res_len = 0;

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		char test[] = "PDw_Pz8-Pg==";
		res_len = 0;

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		char test[] = "PDw_Pz8-Pg%3D%3D"; /* percent encoded "==" at the
						     end */
		res_len = 0;

		res = isc__nm_base64_to_base64url(test_mctx, test, strlen(test),
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
	/* invalid */
	{
		res_len = 0;

		res = isc__nm_base64_to_base64url(test_mctx, NULL, 31231,
						  &res_len);
		assert_null(res);
		assert_true(res_len == 0);
	}
}

int
main(void) {
	const struct CMUnitTest tests_short[] = {
		cmocka_unit_test_setup_teardown(mock_doh_uv_tcp_bind, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_parse_GET_query_string,
						NULL, NULL),
		cmocka_unit_test_setup_teardown(doh_base64url_to_base64, NULL,
						NULL),
		cmocka_unit_test_setup_teardown(doh_base64_to_base64url, NULL,
						NULL),
		cmocka_unit_test_setup_teardown(doh_noop_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_noop_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_noresponse_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_noresponse_GET, nm_setup,
						nm_teardown),
	};

	const struct CMUnitTest tests_long[] = {
		cmocka_unit_test_setup_teardown(mock_doh_uv_tcp_bind, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_parse_GET_query_string,
						NULL, NULL),
		cmocka_unit_test_setup_teardown(doh_base64url_to_base64, NULL,
						NULL),
		cmocka_unit_test_setup_teardown(doh_base64_to_base64url, NULL,
						NULL),
		cmocka_unit_test_setup_teardown(doh_noop_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_noop_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_noresponse_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_noresponse_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_timeout_recovery_POST,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_timeout_recovery_GET,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_one_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_one_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_one_POST_TLS, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_one_GET_TLS, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_two_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_two_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_two_POST_TLS, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_two_GET_TLS, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_send_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_send_POST, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_send_GET_TLS, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_send_POST_TLS,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_half_send_GET,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_half_send_POST,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_half_send_GET_TLS,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_recv_half_send_POST_TLS,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_send_GET,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_send_POST,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_send_GET_TLS,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_send_POST_TLS,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_half_send_GET,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_half_send_POST,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(doh_half_recv_half_send_GET_TLS,
						nm_setup, nm_teardown),
		cmocka_unit_test_setup_teardown(
			doh_half_recv_half_send_POST_TLS, nm_setup,
			nm_teardown),
		/*cmocka_unit_test_setup_teardown(doh_cloudflare_GET, nm_setup,
						nm_teardown),
		cmocka_unit_test_setup_teardown(doh_cloudflare_POST, nm_setup,
		nm_teardown)*/
	};
	int result = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	UNUSED(tests_long);
	result = (cmocka_run_group_tests(tests_short, _setup, _teardown));
#else
	if (getenv("CI") != NULL || !reuse_supported) {
		result = (cmocka_run_group_tests(tests_short, _setup,
						 _teardown));
	} else {
		result =
			(cmocka_run_group_tests(tests_long, _setup, _teardown));
	}
#endif
	return result;
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
