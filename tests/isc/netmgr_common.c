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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * As a workaround, include an OpenSSL header file before including cmocka.h,
 * because OpenSSL 3.1.0 uses __attribute__(malloc), conflicting with a
 * redefined malloc in cmocka.h.
 */
#include <openssl/err.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/async.h>
#include <isc/nonce.h>
#include <isc/os.h>
#include <isc/quota.h>
#include <isc/refcount.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <isc/uv.h>
#define KEEP_BEFORE

#include "netmgr_common.h"

#include <tests/isc.h>

isc_nm_t *listen_nm = NULL;
isc_nm_t *connect_nm = NULL;

isc_sockaddr_t tcp_listen_addr;
isc_sockaddr_t tcp_connect_addr;
isc_tlsctx_t *tcp_listen_tlsctx = NULL;
isc_tlsctx_t *tcp_connect_tlsctx = NULL;
isc_tlsctx_client_session_cache_t *tcp_tlsctx_client_sess_cache = NULL;

uint64_t send_magic = 0;

isc_region_t send_msg = { .base = (unsigned char *)&send_magic,
			  .length = sizeof(send_magic) };

atomic_bool do_send = false;

atomic_int_fast64_t nsends = 0;
int_fast64_t esends = 0; /* expected sends */

atomic_int_fast64_t ssends = 0;
atomic_int_fast64_t sreads = 0;
atomic_int_fast64_t saccepts = 0;

atomic_int_fast64_t cconnects = 0;
atomic_int_fast64_t csends = 0;
atomic_int_fast64_t creads = 0;
atomic_int_fast64_t ctimeouts = 0;

int expected_ssends;
int expected_sreads;
int expected_csends;
int expected_cconnects;
int expected_creads;
int expected_saccepts;
int expected_ctimeouts;

bool ssends_shutdown;
bool sreads_shutdown;
bool saccepts_shutdown;
bool csends_shutdown;
bool cconnects_shutdown;
bool creads_shutdown;
bool ctimeouts_shutdown;

isc_refcount_t active_cconnects = 0;
isc_refcount_t active_csends = 0;
isc_refcount_t active_creads = 0;
isc_refcount_t active_ssends = 0;
isc_refcount_t active_sreads = 0;

isc_nmsocket_t *listen_sock = NULL;

isc_quota_t listener_quota;
atomic_bool check_listener_quota = false;

bool allow_send_back = false;
bool noanswer = false;
bool stream_use_TLS = false;
bool stream = false;
in_port_t stream_port = 0;

isc_nm_recv_cb_t connect_readcb = NULL;

int
setup_netmgr_test(void **state) {
	tcp_connect_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&tcp_connect_addr, &in6addr_loopback, 0);

	tcp_listen_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&tcp_listen_addr, &in6addr_loopback, stream_port);

	esends = NSENDS * workers;

	atomic_store(&nsends, esends);

	atomic_store(&saccepts, 0);
	atomic_store(&sreads, 0);
	atomic_store(&ssends, 0);

	atomic_store(&cconnects, 0);
	atomic_store(&csends, 0);
	atomic_store(&creads, 0);
	atomic_store(&ctimeouts, 0);
	allow_send_back = false;

	expected_cconnects = -1;
	expected_csends = -1;
	expected_creads = -1;
	expected_sreads = -1;
	expected_ssends = -1;
	expected_saccepts = -1;
	expected_ctimeouts = -1;

	ssends_shutdown = true;
	sreads_shutdown = true;
	saccepts_shutdown = true;
	csends_shutdown = true;
	cconnects_shutdown = true;
	creads_shutdown = true;
	ctimeouts_shutdown = true;

	do_send = false;

	isc_refcount_init(&active_cconnects, 0);
	isc_refcount_init(&active_csends, 0);
	isc_refcount_init(&active_creads, 0);
	isc_refcount_init(&active_ssends, 0);
	isc_refcount_init(&active_sreads, 0);

	isc_nonce_buf(&send_magic, sizeof(send_magic));

	setup_loopmgr(state);
	isc_netmgr_create(mctx, loopmgr, &listen_nm);
	assert_non_null(listen_nm);
	isc_nm_settimeouts(listen_nm, T_INIT, T_IDLE, T_KEEPALIVE,
			   T_ADVERTISED);

	isc_netmgr_create(mctx, loopmgr, &connect_nm);
	assert_non_null(connect_nm);
	isc_nm_settimeouts(connect_nm, T_INIT, T_IDLE, T_KEEPALIVE,
			   T_ADVERTISED);

	isc_quota_init(&listener_quota, 0);
	atomic_store(&check_listener_quota, false);

	connect_readcb = connect_read_cb;
	noanswer = false;

	if (isc_tlsctx_createserver(NULL, NULL, &tcp_listen_tlsctx) !=
	    ISC_R_SUCCESS)
	{
		return (-1);
	}
	if (isc_tlsctx_createclient(&tcp_connect_tlsctx) != ISC_R_SUCCESS) {
		return (-1);
	}

	isc_tlsctx_enable_dot_client_alpn(tcp_connect_tlsctx);

	isc_tlsctx_client_session_cache_create(
		mctx, tcp_connect_tlsctx,
		ISC_TLSCTX_CLIENT_SESSION_CACHE_DEFAULT_SIZE,
		&tcp_tlsctx_client_sess_cache);

	return (0);
}

int
teardown_netmgr_test(void **state ISC_ATTR_UNUSED) {
	UNUSED(state);

	isc_tlsctx_client_session_cache_detach(&tcp_tlsctx_client_sess_cache);

	isc_tlsctx_free(&tcp_connect_tlsctx);
	isc_tlsctx_free(&tcp_listen_tlsctx);

	isc_netmgr_destroy(&connect_nm);
	assert_null(connect_nm);

	isc_netmgr_destroy(&listen_nm);
	assert_null(listen_nm);

	teardown_loopmgr(state);

	isc_refcount_destroy(&active_cconnects);
	isc_refcount_destroy(&active_csends);
	isc_refcount_destroy(&active_creads);
	isc_refcount_destroy(&active_ssends);
	isc_refcount_destroy(&active_sreads);

	return (0);
}

void
stop_listening(void *arg ISC_ATTR_UNUSED) {
	isc_nm_stoplistening(listen_sock);
	isc_nmsocket_close(&listen_sock);
	assert_null(listen_sock);
}

/* Callbacks */

void
noop_recv_cb(isc_nmhandle_t *handle ISC_ATTR_UNUSED,
	     isc_result_t eresult ISC_ATTR_UNUSED,
	     isc_region_t *region ISC_ATTR_UNUSED,
	     void *cbarg ISC_ATTR_UNUSED) {
	F();
}

isc_result_t
noop_accept_cb(isc_nmhandle_t *handle ISC_ATTR_UNUSED, unsigned int eresult,
	       void *cbarg ISC_ATTR_UNUSED) {
	F();

	if (eresult == ISC_R_SUCCESS) {
		(void)atomic_fetch_add(&saccepts, 1);
	}

	return (ISC_R_SUCCESS);
}

void
connect_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg);

void
connect_send(isc_nmhandle_t *handle);

void
connect_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *sendhandle = handle;

	assert_non_null(sendhandle);

	UNUSED(cbarg);

	F();

	switch (eresult) {
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
		/* Abort */
		if (!stream) {
			isc_nm_cancelread(handle);
		}
		break;
	case ISC_R_SUCCESS:
		if (have_expected_csends(atomic_fetch_add(&csends, 1) + 1)) {
			do_csends_shutdown(loopmgr);
		}
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_refcount_decrement(&active_csends);
	isc_nmhandle_detach(&sendhandle);
}

void
connect_send(isc_nmhandle_t *handle) {
	isc_nmhandle_t *sendhandle = NULL;
	isc_refcount_increment0(&active_csends);
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nmhandle_setwritetimeout(handle, T_IDLE);
	isc_nm_send(sendhandle, &send_msg, connect_send_cb, NULL);
}

void
connect_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	UNUSED(cbarg);

	assert_non_null(handle);

	F();

	switch (eresult) {
	case ISC_R_SUCCESS:
		assert_true(region->length >= sizeof(magic));

		memmove(&magic, region->base, sizeof(magic));

		assert_true(magic == send_magic);

		if (have_expected_creads(atomic_fetch_add(&creads, 1) + 1)) {
			do_creads_shutdown(loopmgr);
		}

		if (magic == send_magic && allow_send_back) {
			connect_send(handle);
			return;
		}

		/* This will initiate one more read callback */
		if (stream) {
			isc_nmhandle_close(handle);
		}
		break;
	case ISC_R_TIMEDOUT:
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_CONNREFUSED:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_refcount_decrement(&active_creads);
	isc_nmhandle_detach(&handle);
}

void
connect_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;

	F();

	isc_refcount_decrement(&active_cconnects);

	if (eresult != ISC_R_SUCCESS || connect_readcb == NULL) {
		return;
	}

	/* We are finished, initiate the shutdown */
	if (have_expected_cconnects(atomic_fetch_add(&cconnects, 1) + 1)) {
		do_cconnects_shutdown(loopmgr);
	} else if (do_send) {
		isc_async_current(loopmgr, stream_recv_send_connect,
				  (cbarg == NULL
					   ? get_stream_connect_function()
					   : (stream_connect_function)cbarg));
	}

	isc_refcount_increment0(&active_creads);
	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, connect_readcb, NULL);

	connect_send(handle);
}

void
listen_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *sendhandle = handle;

	UNUSED(cbarg);
	UNUSED(eresult);

	assert_non_null(sendhandle);

	F();

	switch (eresult) {
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
		break;
	case ISC_R_SUCCESS:
		if (have_expected_ssends(atomic_fetch_add(&ssends, 1) + 1)) {
			do_ssends_shutdown(loopmgr);
		}
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_refcount_decrement(&active_ssends);
	isc_nmhandle_detach(&sendhandle);
}

void
listen_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
	       isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	assert_non_null(handle);

	F();

	switch (eresult) {
	case ISC_R_SUCCESS:
		memmove(&magic, region->base, sizeof(magic));
		assert_true(magic == send_magic);

		if (have_expected_sreads(atomic_fetch_add(&sreads, 1) + 1)) {
			do_sreads_shutdown(loopmgr);
		}

		assert_true(region->length >= sizeof(magic));

		memmove(&magic, region->base, sizeof(magic));
		assert_true(magic == send_magic);

		if (!noanswer) {
			/* Answer and continue to listen */
			isc_nmhandle_t *sendhandle = NULL;
			isc_nmhandle_attach(handle, &sendhandle);
			isc_refcount_increment0(&active_ssends);
			isc_nmhandle_setwritetimeout(sendhandle, T_IDLE);
			isc_nm_send(sendhandle, &send_msg, listen_send_cb,
				    cbarg);
		}
		/* Continue to listen */
		return;
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_refcount_decrement(&active_sreads);
	isc_nmhandle_detach(&handle);
}

isc_result_t
listen_accept_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(handle);
	UNUSED(cbarg);

	F();

	if (eresult != ISC_R_SUCCESS) {
		return (eresult);
	}

	if (have_expected_saccepts(atomic_fetch_add(&saccepts, 1) + 1)) {
		do_saccepts_shutdown(loopmgr);
	}

	isc_nmhandle_attach(handle, &(isc_nmhandle_t *){ NULL });
	isc_refcount_increment0(&active_sreads);

	return (eresult);
}

isc_result_t
stream_accept_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;

	UNUSED(cbarg);

	F();

	if (eresult != ISC_R_SUCCESS) {
		return (eresult);
	}

	if (have_expected_saccepts(atomic_fetch_add(&saccepts, 1) + 1)) {
		do_saccepts_shutdown(loopmgr);
	}

	isc_refcount_increment0(&active_sreads);

	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, listen_read_cb, readhandle);

	return (ISC_R_SUCCESS);
}

void
stream_recv_send_connect(void *arg) {
	connect_func connect = (connect_func)arg;
	isc_sockaddr_t connect_addr;

	connect_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&connect_addr, &in6addr_loopback, 0);

	isc_refcount_increment0(&active_cconnects);
	connect(connect_nm);
}

/* Common stream protocols code */

void
timeout_retry_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		 isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	assert_non_null(handle);

	F();

	if (eresult == ISC_R_TIMEDOUT &&
	    atomic_fetch_add(&ctimeouts, 1) + 1 < expected_ctimeouts)
	{
		isc_nmhandle_settimeout(handle, T_SOFT);
		connect_send(handle);
		return;
	}

	isc_refcount_decrement(&active_creads);
	isc_nmhandle_detach(&handle);

	isc_loopmgr_shutdown(loopmgr);
}

isc_quota_t *
tcp_listener_init_quota(size_t nthreads) {
	isc_quota_t *quotap = NULL;
	if (atomic_load(&check_listener_quota)) {
		unsigned int max_quota = ISC_MAX(nthreads / 2, 1);
		isc_quota_max(&listener_quota, max_quota);
		quotap = &listener_quota;
	}
	return (quotap);
}

static void
tcp_connect(isc_nm_t *nm) {
	isc_nm_tcpconnect(nm, &tcp_connect_addr, &tcp_listen_addr,
			  connect_connect_cb, NULL, T_CONNECT);
}

static void
tls_connect(isc_nm_t *nm) {
	isc_nm_tlsconnect(nm, &tcp_connect_addr, &tcp_listen_addr,
			  connect_connect_cb, NULL, tcp_connect_tlsctx,
			  tcp_tlsctx_client_sess_cache, T_CONNECT);
}

stream_connect_function
get_stream_connect_function(void) {
	if (stream_use_TLS) {
		return (tls_connect);
	}
	return (tcp_connect);
}

isc_result_t
stream_listen(isc_nm_accept_cb_t accept_cb, void *accept_cbarg, int backlog,
	      isc_quota_t *quota, isc_nmsocket_t **sockp) {
	isc_result_t result = ISC_R_SUCCESS;

	if (stream_use_TLS) {
		result = isc_nm_listentls(listen_nm, ISC_NM_LISTEN_ALL,
					  &tcp_listen_addr, accept_cb,
					  accept_cbarg, backlog, quota,
					  tcp_listen_tlsctx, sockp);
		return (result);
	}
	result = isc_nm_listentcp(listen_nm, ISC_NM_LISTEN_ALL,
				  &tcp_listen_addr, accept_cb, accept_cbarg,
				  backlog, quota, sockp);

	return (result);
}

void
stream_connect(isc_nm_cb_t cb, void *cbarg, unsigned int timeout) {
	isc_refcount_increment0(&active_cconnects);

	if (stream_use_TLS) {
		isc_nm_tlsconnect(connect_nm, &tcp_connect_addr,
				  &tcp_listen_addr, cb, cbarg,
				  tcp_connect_tlsctx,
				  tcp_tlsctx_client_sess_cache, timeout);
		return;
	}
	isc_nm_tcpconnect(connect_nm, &tcp_connect_addr, &tcp_listen_addr, cb,
			  cbarg, timeout);
}

void
connect_success_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(handle);
	UNUSED(cbarg);

	F();

	isc_refcount_decrement(&active_cconnects);
	assert_int_equal(eresult, ISC_R_SUCCESS);

	if (have_expected_cconnects(atomic_fetch_add(&cconnects, 1) + 1)) {
		do_cconnects_shutdown(loopmgr);
		return;
	}
}

int
stream_noop_setup(void **state ISC_ATTR_UNUSED) {
	int r = setup_netmgr_test(state);
	expected_cconnects = 1;
	return (r);
}

void
stream_noop(void **state ISC_ATTR_UNUSED) {
	isc_result_t result = ISC_R_SUCCESS;

	result = stream_listen(noop_accept_cb, NULL, 128, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_loop_teardown(mainloop, stop_listening, listen_sock);

	connect_readcb = NULL;
	stream_connect(connect_success_cb, NULL, T_CONNECT);
}

int
stream_noop_teardown(void **state ISC_ATTR_UNUSED) {
	atomic_assert_int_eq(cconnects, 1);
	atomic_assert_int_eq(csends, 0);
	atomic_assert_int_eq(creads, 0);
	atomic_assert_int_eq(sreads, 0);
	atomic_assert_int_eq(ssends, 0);
	return (teardown_netmgr_test(state));
}

static void
noresponse_readcb(isc_nmhandle_t *handle, isc_result_t eresult,
		  isc_region_t *region, void *cbarg) {
	UNUSED(handle);
	UNUSED(region);
	UNUSED(cbarg);

	F();

	assert_true(eresult == ISC_R_CANCELED ||
		    eresult == ISC_R_CONNECTIONRESET || eresult == ISC_R_EOF);

	isc_refcount_decrement(&active_creads);
	isc_nmhandle_detach(&handle);

	isc_loopmgr_shutdown(loopmgr);
}

static void
noresponse_sendcb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(cbarg);
	UNUSED(eresult);

	F();

	assert_non_null(handle);
	atomic_fetch_add(&csends, 1);
	isc_nmhandle_detach(&handle);
	isc_refcount_decrement(&active_csends);
}

static void
noresponse_connectcb(isc_nmhandle_t *handle, isc_result_t eresult,
		     void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;
	isc_nmhandle_t *sendhandle = NULL;

	F();

	isc_refcount_decrement(&active_cconnects);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	atomic_fetch_add(&cconnects, 1);

	isc_refcount_increment0(&active_creads);
	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, noresponse_readcb, NULL);

	isc_refcount_increment0(&active_csends);
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nmhandle_setwritetimeout(handle, T_IDLE);

	isc_nm_send(handle, (isc_region_t *)&send_msg, noresponse_sendcb,
		    cbarg);
}

int
stream_noresponse_setup(void **state ISC_ATTR_UNUSED) {
	int r = setup_netmgr_test(state);
	expected_cconnects = 1;
	expected_saccepts = 1;
	return (r);
}

void
stream_noresponse(void **state ISC_ATTR_UNUSED) {
	isc_result_t result = ISC_R_SUCCESS;

	result = stream_listen(noop_accept_cb, NULL, 128, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_loop_teardown(mainloop, stop_listening, listen_sock);

	stream_connect(noresponse_connectcb, NULL, T_CONNECT);
}

int
stream_noresponse_teardown(void **state ISC_ATTR_UNUSED) {
	X(cconnects);
	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	atomic_assert_int_eq(cconnects, 1);
	atomic_assert_int_eq(creads, 0);
	atomic_assert_int_eq(sreads, 0);
	atomic_assert_int_eq(ssends, 0);

	return (teardown_netmgr_test(state));
}

int
stream_timeout_recovery_setup(void **state ISC_ATTR_UNUSED) {
	int r = setup_netmgr_test(state);

	expected_ctimeouts = 4;
	ctimeouts_shutdown = false;

	expected_sreads = 5;
	sreads_shutdown = true;

	return (r);
}

void
stream_timeout_recovery(void **state ISC_ATTR_UNUSED) {
	isc_result_t result = ISC_R_SUCCESS;

	/*
	 * Accept connections but don't send responses, forcing client
	 * reads to time out.
	 */
	noanswer = true;
	result = stream_listen(stream_accept_cb, NULL, 128, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_loop_teardown(mainloop, stop_listening, listen_sock);

	/*
	 * Shorten all the client timeouts to 0.05 seconds.
	 */
	isc_nm_settimeouts(connect_nm, T_SOFT, T_SOFT, T_SOFT, T_SOFT);
	connect_readcb = timeout_retry_cb;
	stream_connect(connect_connect_cb, NULL, T_SOFT);
}

int
stream_timeout_recovery_teardown(void **state ISC_ATTR_UNUSED) {
	atomic_assert_int_eq(ctimeouts, expected_ctimeouts);
	return (teardown_netmgr_test(state));
}

int
stream_recv_one_setup(void **state ISC_ATTR_UNUSED) {
	int r = setup_netmgr_test(state);

	expected_cconnects = 1;
	cconnects_shutdown = false;

	expected_csends = 1;
	csends_shutdown = false;

	expected_saccepts = 1;
	saccepts_shutdown = false;

	expected_sreads = 1;
	sreads_shutdown = false;

	expected_ssends = 1;
	ssends_shutdown = false;

	expected_creads = 1;
	creads_shutdown = true;

	return (r);
}

void
stream_recv_one(void **state ISC_ATTR_UNUSED) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_quota_t *quotap = tcp_listener_init_quota(1);

	atomic_store(&nsends, 1);

	result = stream_listen(stream_accept_cb, NULL, 128, quotap,
			       &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_loop_teardown(mainloop, stop_listening, listen_sock);

	stream_connect(connect_connect_cb, NULL, T_CONNECT);
}

int
stream_recv_one_teardown(void **state ISC_ATTR_UNUSED) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(csends, expected_csends);
	atomic_assert_int_eq(saccepts, expected_saccepts);
	atomic_assert_int_eq(sreads, expected_sreads);
	atomic_assert_int_eq(ssends, expected_ssends);
	atomic_assert_int_eq(creads, expected_creads);

	return (teardown_netmgr_test(state));
}

int
stream_recv_two_setup(void **state ISC_ATTR_UNUSED) {
	int r = setup_netmgr_test(state);

	expected_cconnects = 2;
	cconnects_shutdown = false;

	expected_csends = 2;
	csends_shutdown = false;

	expected_saccepts = 2;
	saccepts_shutdown = false;

	expected_sreads = 2;
	sreads_shutdown = false;

	expected_ssends = 2;
	ssends_shutdown = false;

	expected_creads = 2;
	creads_shutdown = true;

	return (r);
}

void
stream_recv_two(void **state ISC_ATTR_UNUSED) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_quota_t *quotap = tcp_listener_init_quota(1);

	atomic_store(&nsends, 2);

	result = stream_listen(stream_accept_cb, NULL, 128, quotap,
			       &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_loop_teardown(mainloop, stop_listening, listen_sock);

	stream_connect(connect_connect_cb, NULL, T_CONNECT);

	stream_connect(connect_connect_cb, NULL, T_CONNECT);
}

int
stream_recv_two_teardown(void **state ISC_ATTR_UNUSED) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(csends, expected_csends);
	atomic_assert_int_eq(sreads, expected_saccepts);
	atomic_assert_int_eq(sreads, expected_sreads);
	atomic_assert_int_eq(ssends, expected_ssends);
	atomic_assert_int_eq(creads, expected_creads);

	return (teardown_netmgr_test(state));
}

int
stream_recv_send_setup(void **state ISC_ATTR_UNUSED) {
	int r = setup_netmgr_test(state);
	expected_cconnects = workers;
	cconnects_shutdown = false;
	nsends = expected_creads = workers;
	do_send = true;

	return (r);
}

void
stream_recv_send(void **state ISC_ATTR_UNUSED) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_quota_t *quotap = tcp_listener_init_quota(workers);

	result = stream_listen(stream_accept_cb, NULL, 128, quotap,
			       &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_loop_teardown(mainloop, stop_listening, listen_sock);

	for (size_t i = 0; i < workers; i++) {
		isc_async_run(isc_loop_get(loopmgr, i),
			      stream_recv_send_connect,
			      get_stream_connect_function());
	}
}

int
stream_recv_send_teardown(void **state ISC_ATTR_UNUSED) {
	X(cconnects);
	X(csends);
	X(creads);
	X(sreads);
	X(ssends);

	CHECK_RANGE_FULL(csends);
	CHECK_RANGE_FULL(creads);
	CHECK_RANGE_FULL(sreads);
	CHECK_RANGE_FULL(ssends);

	return (teardown_netmgr_test(state));
}
