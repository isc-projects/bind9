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
#include <isc/job.h>
#include <isc/nonce.h>
#include <isc/os.h>
#include <isc/quota.h>
#include <isc/refcount.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "uv_wrap.h"
#define KEEP_BEFORE

#include "netmgr/socket.c"
#include "netmgr/udp.c"
#include "netmgr_common.h"
#include "uv.c"

#include <tests/isc.h>

static isc_sockaddr_t udp_listen_addr;
static isc_sockaddr_t udp_connect_addr;

/* Timeout for soft-timeout tests (0.05 seconds) */
#define T_SOFT 50

/* Timeouts in miliseconds */
#define T_INIT	     120 * 1000
#define T_IDLE	     120 * 1000
#define T_KEEPALIVE  120 * 1000
#define T_ADVERTISED 120 * 1000
#define T_CONNECT    30 * 1000

static int
setup_test(void **state) {
	setup_loopmgr(state);
	setup_netmgr(state);

	udp_connect_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&udp_connect_addr, &in6addr_loopback, 0);

	udp_listen_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&udp_listen_addr, &in6addr_loopback,
			     UDP_TEST_PORT);

	atomic_store(&sreads, 0);
	atomic_store(&ssends, 0);

	atomic_store(&cconnects, 0);
	atomic_store(&csends, 0);
	atomic_store(&creads, 0);
	atomic_store(&ctimeouts, 0);

	isc_refcount_init(&active_cconnects, 0);
	isc_refcount_init(&active_csends, 0);
	isc_refcount_init(&active_creads, 0);
	isc_refcount_init(&active_ssends, 0);
	isc_refcount_init(&active_sreads, 0);

	expected_cconnects = -1;
	expected_csends = -1;
	expected_creads = -1;
	expected_sreads = -1;
	expected_ssends = -1;
	expected_ctimeouts = -1;

	ssends_shutdown = true;
	sreads_shutdown = true;
	csends_shutdown = true;
	cconnects_shutdown = true;
	creads_shutdown = true;

	isc_nonce_buf(&send_magic, sizeof(send_magic));

	connect_readcb = connect_read_cb;

	return (0);
}

static int
teardown_test(void **state) {
	UNUSED(state);

	isc_refcount_destroy(&active_cconnects);
	isc_refcount_destroy(&active_csends);
	isc_refcount_destroy(&active_creads);
	isc_refcount_destroy(&active_ssends);
	isc_refcount_destroy(&active_sreads);

	teardown_netmgr(state);
	teardown_loopmgr(state);

	return (0);
}

/* Callbacks */

static void
mock_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	     void *cbarg) {
	UNUSED(handle);
	UNUSED(eresult);
	UNUSED(region);
	UNUSED(cbarg);
}

static void
udp_listen_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	if (eresult != ISC_R_SUCCESS) {
		isc_refcount_increment0(&active_sreads);
	}
	listen_read_cb(handle, eresult, region, cbarg);
}

static void
connect_nomemory_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(handle);
	UNUSED(cbarg);

	isc_refcount_decrement(&active_cconnects);
	assert_int_equal(eresult, ISC_R_NOMEMORY);

	isc_loopmgr_shutdown(loopmgr);
}

static void
start_listening(uint32_t nworkers, isc_nm_recv_cb_t cb) {
	isc_result_t result = isc_nm_listenudp(
		netmgr, nworkers, &udp_listen_addr, cb, NULL, &listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_loop_teardown(mainloop, stop_listening, listen_sock);
}

/* UDP */

ISC_LOOP_TEST_IMPL(mock_listenudp_uv_udp_open) {
	isc_result_t result = ISC_R_SUCCESS;

	WILL_RETURN(uv_udp_open, UV_ENOMEM);

	result = isc_nm_listenudp(netmgr, ISC_NM_LISTEN_ALL, &udp_listen_addr,
				  mock_recv_cb, NULL, &listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(listen_sock);

	RESET_RETURN;

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(mock_listenudp_uv_udp_bind) {
	isc_result_t result = ISC_R_SUCCESS;

	WILL_RETURN(uv_udp_bind, UV_EADDRINUSE);

	result = isc_nm_listenudp(netmgr, ISC_NM_LISTEN_ALL, &udp_listen_addr,
				  mock_recv_cb, NULL, &listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(listen_sock);

	RESET_RETURN;

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(mock_listenudp_uv_udp_recv_start) {
	isc_result_t result = ISC_R_SUCCESS;

	WILL_RETURN(uv_udp_recv_start, UV_EADDRINUSE);

	result = isc_nm_listenudp(netmgr, ISC_NM_LISTEN_ALL, &udp_listen_addr,
				  mock_recv_cb, NULL, &listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(listen_sock);

	RESET_RETURN;

	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_udp_open) {
	WILL_RETURN(uv_udp_open, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  connect_nomemory_cb, NULL, T_CONNECT);
	isc_loopmgr_shutdown(loopmgr);

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_udp_bind) {
	WILL_RETURN(uv_udp_bind, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  connect_nomemory_cb, NULL, T_CONNECT);
	isc_loopmgr_shutdown(loopmgr);

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_udp_connect) {
	WILL_RETURN(uv_udp_connect, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  connect_nomemory_cb, NULL, T_CONNECT);
	isc_loopmgr_shutdown(loopmgr);

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_recv_buffer_size) {
	WILL_RETURN(uv_recv_buffer_size, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  connect_success_cb, NULL, T_CONNECT);
	isc_loopmgr_shutdown(loopmgr);

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_send_buffer_size) {
	WILL_RETURN(uv_send_buffer_size, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  connect_success_cb, NULL, T_CONNECT);
	isc_loopmgr_shutdown(loopmgr);

	RESET_RETURN;
}

ISC_SETUP_TEST_IMPL(udp_noop) {
	setup_test(state);
	expected_cconnects = 1;
	cconnects_shutdown = true;
	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_noop) {
	atomic_assert_int_eq(cconnects, 1);
	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_noop) {
	/* isc_result_t result = ISC_R_SUCCESS; */

	/* result = isc_nm_listenudp(netmgr, ISC_NM_LISTEN_ALL,
	 * &udp_listen_addr, */
	/* 			  mock_recv_cb, NULL, &listen_sock); */
	/* assert_int_equal(result, ISC_R_SUCCESS); */

	/* isc_nm_stoplistening(listen_sock); */
	/* isc_nmsocket_close(&listen_sock); */
	/* assert_null(listen_sock); */

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  connect_success_cb, NULL, T_CONNECT);
}

static void
udp_noresponse_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       isc_region_t *region, void *cbarg) {
	UNUSED(handle);
	UNUSED(eresult);
	UNUSED(region);
	UNUSED(cbarg);
}

static void
udp_noresponse_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	assert_int_equal(eresult, ISC_R_TIMEDOUT);

	isc_refcount_decrement(&active_creads);

	atomic_fetch_add(&creads, 1);

	isc_nmhandle_detach(&handle);

	isc_loopmgr_shutdown(loopmgr);
}

static void
udp_noresponse_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       void *cbarg) {
	UNUSED(cbarg);

	assert_non_null(handle);
	assert_int_equal(eresult, ISC_R_SUCCESS);
	atomic_fetch_add(&csends, 1);
	isc_nmhandle_detach(&handle);
	isc_refcount_decrement(&active_csends);
}

static void
udp_noresponse_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;
	isc_nmhandle_t *sendhandle = NULL;

	isc_refcount_decrement(&active_cconnects);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	/* Read */
	isc_refcount_increment0(&active_creads);
	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, udp_noresponse_read_cb, cbarg);

	/* Send */
	isc_refcount_increment0(&active_csends);
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nmhandle_setwritetimeout(handle, T_IDLE);

	isc_nm_send(sendhandle, (isc_region_t *)&send_msg,
		    udp_noresponse_send_cb, cbarg);

	atomic_fetch_add(&cconnects, 1);
}

ISC_SETUP_TEST_IMPL(udp_noresponse) {
	setup_test(state);
	expected_csends = 1;
	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_noresponse) {
	atomic_assert_int_eq(csends, expected_csends);
	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_noresponse) {
	start_listening(ISC_NM_LISTEN_ONE, udp_noresponse_recv_cb);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  udp_noresponse_connect_cb, listen_sock, T_SOFT);
}

static void
udp_timeout_recovery_ssend_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			      void *cbarg) {
	UNUSED(cbarg);

	isc_refcount_decrement(&active_ssends);
	assert_non_null(handle);
	assert_int_equal(eresult, ISC_R_SUCCESS);
	atomic_fetch_add(&ssends, 1);
	isc_nmhandle_detach(&handle);
}

static void
udp_timeout_recovery_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			     isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;
	isc_nmhandle_t *sendhandle = NULL;
	int _creads = atomic_fetch_add(&creads, 1) + 1;

	assert_non_null(handle);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	assert_true(region->length == sizeof(magic));

	memmove(&magic, region->base, sizeof(magic));
	assert_true(magic == send_magic);
	assert_true(_creads < 6);

	if (_creads == 5) {
		isc_nmhandle_attach(handle, &sendhandle);
		isc_refcount_increment0(&active_ssends);
		isc_nmhandle_setwritetimeout(sendhandle, T_IDLE);
		isc_nm_send(sendhandle, (isc_region_t *)&send_msg,
			    udp_timeout_recovery_ssend_cb, cbarg);
	}
}

static void
udp_timeout_recovery_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			     isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	assert_non_null(handle);

	F();

	if (eresult == ISC_R_TIMEDOUT &&
	    atomic_fetch_add(&ctimeouts, 1) + 1 < expected_ctimeouts)
	{
		isc_nmhandle_settimeout(handle, T_SOFT);
		return;
	}

	isc_refcount_decrement(&active_creads);
	isc_nmhandle_detach(&handle);

	atomic_fetch_add(&creads, 1);
	isc_loopmgr_shutdown(loopmgr);
}

static void
udp_timeout_recovery_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			     void *cbarg) {
	UNUSED(cbarg);

	assert_non_null(handle);
	assert_int_equal(eresult, ISC_R_SUCCESS);
	atomic_fetch_add(&csends, 1);

	isc_nmhandle_detach(&handle);
	isc_refcount_decrement(&active_csends);
}

static void
udp_timeout_recovery_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
				void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;
	isc_nmhandle_t *sendhandle = NULL;

	F();

	isc_refcount_decrement(&active_cconnects);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	/* Read */
	isc_refcount_increment0(&active_creads);
	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, udp_timeout_recovery_read_cb, cbarg);

	/* Send */
	isc_refcount_increment0(&active_csends);
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nmhandle_setwritetimeout(handle, T_IDLE);
	isc_nm_send(sendhandle, (isc_region_t *)&send_msg,
		    udp_timeout_recovery_send_cb, cbarg);

	atomic_fetch_add(&cconnects, 1);
}

ISC_SETUP_TEST_IMPL(udp_timeout_recovery) {
	setup_test(state);
	expected_cconnects = 1;
	expected_csends = 1;
	expected_creads = 1;
	expected_ctimeouts = 4;
	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_timeout_recovery) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(csends, expected_csends);
	atomic_assert_int_eq(csends, expected_creads);
	atomic_assert_int_eq(ctimeouts, expected_ctimeouts);
	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_timeout_recovery) {
	/*
	 * Listen using the noop callback so that client reads will time out.
	 */
	start_listening(ISC_NM_LISTEN_ONE, udp_timeout_recovery_recv_cb);

	/*
	 * Connect with client timeout set to 0.05 seconds, then sleep for at
	 * least a second for each 'tick'. timeout_retry_cb() will give up
	 * after five timeouts.
	 */
	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  udp_timeout_recovery_connect_cb, listen_sock, T_SOFT);
}

static void
udp_shutdown_connect_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
				void *cbarg) {
	UNUSED(handle);
	UNUSED(cbarg);

	isc_refcount_decrement(&active_cconnects);

	assert_int_equal(eresult, ISC_R_SHUTTINGDOWN);

	atomic_fetch_add(&cconnects, 1);
}

static void
udp_connect_udpconnect(void *arg ISC_ATTR_UNUSED) {
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  udp_shutdown_connect_connect_cb, NULL, T_SOFT);
}

ISC_SETUP_TEST_IMPL(udp_shutdown_connect) {
	setup_test(state);
	expected_cconnects = 1;
	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_shutdown_connect) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_shutdown_connect) {
	isc_loopmgr_shutdown(loopmgr);
	isc_refcount_increment0(&active_cconnects);
	isc_async_current(loopmgr, udp_connect_udpconnect, netmgr);
}

static void
udp_shutdown_read_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	UNUSED(cbarg);

	assert_non_null(handle);

	F();

	assert_int_equal(eresult, ISC_R_SUCCESS);

	assert_true(region->length == sizeof(magic));

	memmove(&magic, region->base, sizeof(magic));
	assert_true(magic == send_magic);
}

static void
udp_shutdown_read_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  void *cbarg) {
	UNUSED(cbarg);

	F();

	assert_non_null(handle);
	assert_int_equal(eresult, ISC_R_SUCCESS);

	atomic_fetch_add(&csends, 1);

	isc_loopmgr_shutdown(loopmgr);

	isc_nmhandle_detach(&handle);
	isc_refcount_decrement(&active_csends);
}

static void
udp_shutdown_read_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	assert_true(eresult == ISC_R_SHUTTINGDOWN || eresult == ISC_R_TIMEDOUT);

	isc_refcount_decrement(&active_creads);

	atomic_fetch_add(&creads, 1);

	isc_nmhandle_detach(&handle);
}

static void
udp_shutdown_read_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			     void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;
	isc_nmhandle_t *sendhandle = NULL;

	isc_refcount_decrement(&active_cconnects);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	/* Read */
	isc_refcount_increment0(&active_creads);
	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, udp_shutdown_read_read_cb, cbarg);
	assert_true(handle->sock->reading);

	/* Send */
	isc_refcount_increment0(&active_csends);
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nmhandle_setwritetimeout(handle, T_IDLE);
	isc_nm_send(sendhandle, (isc_region_t *)&send_msg,
		    udp_shutdown_read_send_cb, cbarg);

	atomic_fetch_add(&cconnects, 1);
}

ISC_SETUP_TEST_IMPL(udp_shutdown_read) {
	setup_test(state);
	expected_cconnects = 1;
	expected_creads = 1;
	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_shutdown_read) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(creads, expected_creads);
	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_shutdown_read) {
	start_listening(ISC_NM_LISTEN_ONE, udp_shutdown_read_recv_cb);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  udp_shutdown_read_connect_cb, NULL, T_SOFT);
}

static void
udp_cancel_read_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	UNUSED(cbarg);

	assert_non_null(handle);

	F();

	assert_int_equal(eresult, ISC_R_SUCCESS);

	assert_true(region->length == sizeof(magic));

	memmove(&magic, region->base, sizeof(magic));
	assert_true(magic == send_magic);
}

static void
udp_cancel_read_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			void *cbarg) {
	UNUSED(cbarg);

	F();

	assert_non_null(handle);
	assert_int_equal(eresult, ISC_R_SUCCESS);

	atomic_fetch_add(&csends, 1);

	isc_nm_cancelread(handle);

	isc_nmhandle_detach(&handle);
	isc_refcount_decrement(&active_csends);
}

static void
udp_cancel_read_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			isc_region_t *region, void *cbarg) {
	isc_nmhandle_t *sendhandle = NULL;
	isc_nmhandle_t *readhandle = NULL;

	UNUSED(region);

	F();

	switch (eresult) {
	case ISC_R_TIMEDOUT:

		/* Read again */
		isc_refcount_increment0(&active_creads);
		isc_nmhandle_attach(handle, &readhandle);
		isc_nm_read(handle, udp_cancel_read_read_cb, cbarg);

		/* Send only once */
		if (isc_refcount_increment0(&active_csends) == 0) {
			isc_nmhandle_attach(handle, &sendhandle);
			isc_nmhandle_setwritetimeout(handle, T_IDLE);
			isc_nm_send(sendhandle, (isc_region_t *)&send_msg,
				    udp_cancel_read_send_cb, cbarg);
		}
		break;
	case ISC_R_CANCELED:
		/* The read has been canceled */
		atomic_fetch_add(&creads, 1);
		isc_loopmgr_shutdown(loopmgr);
		break;
	default:
		UNREACHABLE();
	}

	isc_refcount_decrement(&active_creads);

	isc_nmhandle_detach(&handle);
}

static void
udp_cancel_read_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			   void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;

	isc_refcount_decrement(&active_cconnects);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	isc_refcount_increment0(&active_creads);
	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, udp_cancel_read_read_cb, cbarg);

	atomic_fetch_add(&cconnects, 1);
}

ISC_SETUP_TEST_IMPL(udp_cancel_read) {
	setup_test(state);
	expected_cconnects = 1;
	expected_creads = 1;
	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_cancel_read) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(creads, expected_creads);
	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_cancel_read) {
	start_listening(ISC_NM_LISTEN_ONE, udp_cancel_read_recv_cb);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  udp_cancel_read_connect_cb, NULL, T_SOFT);
}

static void
udp__send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *sendhandle = handle;

	assert_non_null(sendhandle);

	F();

	switch (eresult) {
	case ISC_R_SUCCESS:
		if (have_expected_csends(atomic_fetch_add(&csends, 1) + 1)) {
			if (csends_shutdown) {
				isc_nm_cancelread(handle);
				isc_loopmgr_shutdown(loopmgr);
			}
		}
		break;
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_nmhandle_detach(&sendhandle);
	isc_refcount_decrement(&active_csends);
}

static void
udp__connect_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg);
static void
udp__connect(void *arg ISC_ATTR_UNUSED) {
	isc_sockaddr_t connect_addr;

	connect_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&connect_addr, &in6addr_loopback, 0);

	isc_refcount_increment0(&active_cconnects);

	isc_nm_udpconnect(netmgr, &udp_connect_addr, &udp_listen_addr,
			  udp__connect_cb, NULL, T_CONNECT);
}

static void
udp__connect_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		     isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	assert_non_null(handle);

	F();

	switch (eresult) {
	case ISC_R_TIMEDOUT:
		/*
		 * We are operating on the localhost, UDP cannot get lost, but
		 * it could be delayed, so we read again until we get the
		 * answer.
		 */
		isc_nm_read(handle, connect_readcb, cbarg);
		return;
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

		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_refcount_decrement(&active_creads);

	isc_nmhandle_detach(&handle);
}

static void
udp__connect_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;
	isc_nmhandle_t *sendhandle = NULL;

	F();

	isc_refcount_decrement(&active_cconnects);

	switch (eresult) {
	case ISC_R_SUCCESS:
		if (have_expected_cconnects(atomic_fetch_add(&cconnects, 1) +
					    1))
		{
			do_cconnects_shutdown(loopmgr);
		} else if (do_send) {
			isc_async_current(loopmgr, udp__connect, cbarg);
		}

		isc_refcount_increment0(&active_creads);
		isc_nmhandle_attach(handle, &readhandle);
		isc_nm_read(handle, connect_readcb, cbarg);

		isc_refcount_increment0(&active_csends);
		isc_nmhandle_attach(handle, &sendhandle);
		isc_nmhandle_setwritetimeout(handle, T_IDLE);

		isc_nm_send(sendhandle, (isc_region_t *)&send_msg, udp__send_cb,
			    cbarg);

		break;
	case ISC_R_ADDRINUSE:
		/* Try again */
		udp__connect(NULL);
		break;
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}
}

ISC_SETUP_TEST_IMPL(udp_recv_one) {
	setup_test(state);

	connect_readcb = udp__connect_read_cb;

	expected_cconnects = 1;
	cconnects_shutdown = false;

	expected_csends = 1;
	csends_shutdown = false;

	expected_sreads = 1;
	sreads_shutdown = false;

	expected_ssends = 1;
	ssends_shutdown = false;

	expected_creads = 1;
	creads_shutdown = true;

	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_recv_one) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(csends, expected_csends);
	atomic_assert_int_eq(sreads, expected_sreads);
	atomic_assert_int_eq(ssends, expected_ssends);
	atomic_assert_int_eq(creads, expected_creads);

	teardown_test(state);

	return (0);
}

ISC_LOOP_TEST_IMPL(udp_recv_one) {
	start_listening(ISC_NM_LISTEN_ONE, udp_listen_read_cb);

	udp__connect(NULL);
}

ISC_SETUP_TEST_IMPL(udp_recv_two) {
	setup_test(state);

	connect_readcb = udp__connect_read_cb;

	expected_cconnects = 2;
	cconnects_shutdown = false;

	expected_csends = 2;
	csends_shutdown = false;

	expected_sreads = 2;
	sreads_shutdown = false;

	expected_ssends = 2;
	ssends_shutdown = false;

	expected_creads = 2;
	creads_shutdown = true;

	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_recv_two) {
	atomic_assert_int_eq(cconnects, expected_cconnects);
	atomic_assert_int_eq(csends, expected_csends);
	atomic_assert_int_eq(sreads, expected_sreads);
	atomic_assert_int_eq(ssends, expected_ssends);
	atomic_assert_int_eq(creads, expected_creads);

	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_recv_two) {
	start_listening(ISC_NM_LISTEN_ONE, udp_listen_read_cb);

	udp__connect(NULL);
	udp__connect(NULL);
}

ISC_SETUP_TEST_IMPL(udp_recv_send) {
	setup_test(state);

	/* Allow some leeway (+1) as datagram service is unreliable */
	expected_cconnects = (workers + 1) * NSENDS;
	cconnects_shutdown = false;

	expected_creads = workers * NSENDS;
	do_send = true;

	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_recv_send) {
	atomic_assert_int_ge(cconnects, expected_creads);
	atomic_assert_int_ge(csends, expected_creads);
	atomic_assert_int_ge(sreads, expected_creads);
	atomic_assert_int_ge(ssends, expected_creads);
	atomic_assert_int_ge(creads, expected_creads);

	teardown_test(state);
	return (0);
}

ISC_LOOP_TEST_IMPL(udp_recv_send) {
	start_listening(ISC_NM_LISTEN_ALL, udp_listen_read_cb);

	for (size_t i = 0; i < workers; i++) {
		isc_async_run(isc_loop_get(loopmgr, i), udp__connect, NULL);
	}
}

static void
double_read_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	assert_non_null(handle);

	F();

	isc_refcount_decrement(&active_ssends);

	switch (eresult) {
	case ISC_R_SUCCESS:
		if (have_expected_ssends(atomic_fetch_add(&ssends, 1) + 1)) {
			do_ssends_shutdown(loopmgr);
		} else {
			isc_nmhandle_t *sendhandle = NULL;
			isc_nmhandle_attach(handle, &sendhandle);
			isc_nmhandle_setwritetimeout(sendhandle, T_IDLE);
			isc_refcount_increment0(&active_ssends);
			isc_nm_send(sendhandle, &send_msg, double_read_send_cb,
				    cbarg);
			break;
		}
		break;
	case ISC_R_CANCELED:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_nmhandle_detach(&handle);
}

static void
double_read_listen_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;

	assert_non_null(handle);

	F();

	switch (eresult) {
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
		break;
	case ISC_R_SUCCESS:
		memmove(&magic, region->base, sizeof(magic));
		assert_true(magic == send_magic);

		assert_true(region->length >= sizeof(magic));

		memmove(&magic, region->base, sizeof(magic));
		assert_true(magic == send_magic);

		isc_nmhandle_t *sendhandle = NULL;
		isc_nmhandle_attach(handle, &sendhandle);
		isc_nmhandle_setwritetimeout(sendhandle, T_IDLE);
		isc_refcount_increment0(&active_ssends);
		isc_nm_send(sendhandle, &send_msg, double_read_send_cb, cbarg);
		return;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	isc_refcount_decrement(&active_sreads);

	isc_nmhandle_detach(&handle);
}

static void
double_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
	       isc_region_t *region, void *cbarg) {
	uint64_t magic = 0;
	bool detach = false;

	assert_non_null(handle);

	F();

	switch (eresult) {
	case ISC_R_TIMEDOUT:
		/*
		 * We are operating on the localhost, UDP cannot get lost, but
		 * it could be delayed, so we read again until we get the
		 * answer.
		 */
		detach = false;
		break;
	case ISC_R_SUCCESS:
		assert_true(region->length >= sizeof(magic));

		memmove(&magic, region->base, sizeof(magic));

		assert_true(magic == send_magic);

		if (have_expected_creads(atomic_fetch_add(&creads, 1) + 1)) {
			do_creads_shutdown(loopmgr);
			detach = true;
		}

		if (magic == send_magic && allow_send_back) {
			connect_send(handle);
			return;
		}

		break;
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
		detach = true;
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	if (detach) {
		isc_refcount_decrement(&active_creads);
		isc_nmhandle_detach(&handle);
	} else {
		isc_nm_read(handle, connect_readcb, cbarg);
	}
}

ISC_SETUP_TEST_IMPL(udp_double_read) {
	setup_test(state);

	expected_cconnects = 1;
	cconnects_shutdown = false;

	expected_csends = 1;
	csends_shutdown = false;

	expected_sreads = 1;
	sreads_shutdown = false;

	expected_ssends = 2;
	ssends_shutdown = false;

	expected_creads = 2;
	creads_shutdown = true;

	connect_readcb = double_read_cb;

	return (0);
}

ISC_TEARDOWN_TEST_IMPL(udp_double_read) {
	atomic_assert_int_eq(creads, expected_creads);

	teardown_test(state);

	return (0);
}

ISC_LOOP_TEST_IMPL(udp_double_read) {
	start_listening(ISC_NM_LISTEN_ALL, double_read_listen_cb);

	udp__connect(NULL);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY_CUSTOM(mock_listenudp_uv_udp_open, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_listenudp_uv_udp_bind, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_listenudp_uv_udp_recv_start, setup_test,
		      teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_udp_open, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_udp_bind, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_udp_connect, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_recv_buffer_size, setup_test,
		      teardown_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_send_buffer_size, setup_test,
		      teardown_test)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_noop)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_noresponse)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_shutdown_connect)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_shutdown_read)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_cancel_read)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_timeout_recovery)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_double_read)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_recv_one)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_recv_two)
ISC_TEST_ENTRY_SETUP_TEARDOWN(udp_recv_send)

ISC_TEST_LIST_END

ISC_TEST_MAIN
