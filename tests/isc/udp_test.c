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
#include <isc/lib.h>
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
udp_connect_nomemory_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			void *cbarg) {
	UNUSED(handle);
	UNUSED(cbarg);

	isc_refcount_decrement(&active_cconnects);
	assert_int_equal(eresult, ISC_R_NOMEMORY);

	isc_loopmgr_shutdown();
}

#ifdef USE_ROUTE_SOCKET
static unsigned int route_overflow_reads;

static void
route_overflow_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       isc_region_t *region, void *cbarg) {
	UNUSED(cbarg);

	assert_int_equal(eresult, ISC_R_NORESOURCES);
	assert_non_null(region);
	assert_null(region->base);
	assert_int_equal(region->length, 0);
	route_overflow_reads++;
	isc_nm_read(handle, route_overflow_read_cb, NULL);
}

static void
route_overflow_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  void *cbarg) {
	isc_nmsocket_t *sock = NULL;
	uv_buf_t buf = { 0 };

	UNUSED(cbarg);

	assert_int_equal(eresult, ISC_R_SUCCESS);

	sock = handle->sock;
	assert_true(sock->route_sock);

	isc_nm_read(handle, route_overflow_read_cb, NULL);

	/*
	 * Deliver ENOBUFS the way libuv does: the receive buffer has
	 * already been allocated when the read fails.
	 */
	isc__nm_alloc_cb(&sock->uv_handle.handle, 0, &buf);
	isc__nm_udp_read_cb(&sock->uv_handle.udp, UV_ENOBUFS, &buf, NULL, 0);

	/* The error was passed on, the read re-armed, the buffer released */
	assert_int_equal(route_overflow_reads, 1);
	assert_true(sock->reading);
	assert_false(isc__nmsocket_closing(sock));
	assert_false(sock->worker->recvbuf_inuse);

	isc_nmhandle_close(handle);
	isc_loopmgr_shutdown();
}
#endif /* USE_ROUTE_SOCKET */

/* UDP */

ISC_LOOP_TEST_IMPL(mock_listenudp_uv_udp_open) {
	isc_result_t result = ISC_R_SUCCESS;

	WILL_RETURN(uv_udp_open, UV_ENOMEM);

	result = isc_nm_listenudp(ISC_NM_LISTEN_ALL, &udp_listen_addr,
				  mock_recv_cb, NULL, &udp_listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(udp_listen_sock);

	RESET_RETURN;

	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(mock_listenudp_uv_udp_bind) {
	isc_result_t result = ISC_R_SUCCESS;

	WILL_RETURN(uv_udp_bind, UV_EADDRINUSE);

	result = isc_nm_listenudp(ISC_NM_LISTEN_ALL, &udp_listen_addr,
				  mock_recv_cb, NULL, &udp_listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(udp_listen_sock);

	RESET_RETURN;

	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(mock_listenudp_uv_udp_recv_start) {
	isc_result_t result = ISC_R_SUCCESS;

	WILL_RETURN(uv_udp_recv_start, UV_EADDRINUSE);

	result = isc_nm_listenudp(ISC_NM_LISTEN_ALL, &udp_listen_addr,
				  mock_recv_cb, NULL, &udp_listen_sock);
	assert_int_not_equal(result, ISC_R_SUCCESS);
	assert_null(udp_listen_sock);

	RESET_RETURN;

	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_udp_open) {
	WILL_RETURN(uv_udp_open, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(&udp_connect_addr, &udp_listen_addr,
			  udp_connect_nomemory_cb, NULL, UDP_T_CONNECT);
	isc_loopmgr_shutdown();

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_udp_bind) {
	WILL_RETURN(uv_udp_bind, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(&udp_connect_addr, &udp_listen_addr,
			  udp_connect_nomemory_cb, NULL, UDP_T_CONNECT);
	isc_loopmgr_shutdown();

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_udp_connect) {
	WILL_RETURN(uv_udp_connect, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(&udp_connect_addr, &udp_listen_addr,
			  udp_connect_nomemory_cb, NULL, UDP_T_CONNECT);
	isc_loopmgr_shutdown();

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_recv_buffer_size) {
	WILL_RETURN(uv_recv_buffer_size, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(&udp_connect_addr, &udp_listen_addr,
			  connect_success_cb, NULL, UDP_T_CONNECT);
	isc_loopmgr_shutdown();

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(mock_udpconnect_uv_send_buffer_size) {
	WILL_RETURN(uv_send_buffer_size, UV_ENOMEM);

	isc_refcount_increment0(&active_cconnects);
	isc_nm_udpconnect(&udp_connect_addr, &udp_listen_addr,
			  connect_success_cb, NULL, UDP_T_CONNECT);
	isc_loopmgr_shutdown();

	RESET_RETURN;
}

ISC_LOOP_TEST_IMPL(udp_listener_child_ref) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_nmsocket_t *child = NULL;
	isc_nmsocket_t *hold = NULL;
	uint_fast32_t listener_refs;
	uint_fast32_t child_refs;

	result = isc_nm_listenudp(ISC_NM_LISTEN_ONE, &udp_listen_addr,
				  mock_recv_cb, NULL, &udp_listen_sock);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(udp_listen_sock);
	assert_int_equal(udp_listen_sock->nchildren, 1);

	child = udp_listen_sock->children[0];
	assert_non_null(child);
	assert_int_equal(child->type, isc_nm_udpsocket);
	assert_null(child->parent);

	listener_refs = isc_refcount_current(&udp_listen_sock->references);
	child_refs = isc_refcount_current(&child->references);

	isc__nmsocket_attach(child, &hold);
	assert_ptr_equal(hold, child);
	assert_int_equal(isc_refcount_current(&child->references),
			 child_refs + 1);
	assert_int_equal(isc_refcount_current(&udp_listen_sock->references),
			 listener_refs);

	isc__nmsocket_detach(&hold);
	assert_null(hold);

	isc_nm_udplistener_stop(udp_listen_sock);
	isc_nm_udplistener_detach(&udp_listen_sock);
	assert_null(udp_listen_sock);

	isc_loopmgr_shutdown();
}

#ifdef USE_ROUTE_SOCKET
ISC_LOOP_TEST_IMPL(udp_route_overflow) {
	isc_result_t result;

	route_overflow_reads = 0;
	result = isc_nm_routeconnect(route_overflow_connect_cb, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
}
#else
ISC_RUN_TEST_IMPL(udp_route_overflow) { skip(); }
#endif /* USE_ROUTE_SOCKET */

ISC_LOOP_TEST_IMPL(udp_noop) { udp_noop(arg); }

ISC_LOOP_TEST_IMPL(udp_noresponse) { udp_noresponse(arg); }

ISC_LOOP_TEST_IMPL(udp_timeout_recovery) { udp_timeout_recovery(arg); }

ISC_LOOP_TEST_IMPL(udp_shutdown_connect) { udp_shutdown_connect(arg); }

ISC_LOOP_TEST_IMPL(udp_shutdown_read) { udp_shutdown_read(arg); }

ISC_LOOP_TEST_IMPL(udp_cancel_read) { udp_cancel_read(arg); }

ISC_LOOP_TEST_IMPL(udp_recv_one) { udp_recv_one(arg); }

ISC_LOOP_TEST_IMPL(udp_recv_two) { udp_recv_two(arg); }

ISC_LOOP_TEST_IMPL(udp_recv_send) { udp_recv_send(arg); }

ISC_LOOP_TEST_IMPL(udp_double_read) { udp_double_read(arg); }

ISC_TEST_LIST_START

ISC_TEST_ENTRY_CUSTOM(mock_listenudp_uv_udp_open, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_listenudp_uv_udp_bind, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_listenudp_uv_udp_recv_start, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_udp_open, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_udp_bind, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_udp_connect, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_recv_buffer_size, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(mock_udpconnect_uv_send_buffer_size, setup_udp_test,
		      teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(udp_listener_child_ref, setup_udp_test, teardown_udp_test)
ISC_TEST_ENTRY_CUSTOM(udp_route_overflow, setup_udp_test, teardown_udp_test)

ISC_TEST_ENTRY_CUSTOM(udp_noop, udp_noop_setup, udp_noop_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_noresponse, udp_noresponse_setup,
		      udp_noresponse_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_timeout_recovery, udp_timeout_recovery_setup,
		      udp_timeout_recovery_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_shutdown_read, udp_shutdown_read_setup,
		      udp_shutdown_read_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_cancel_read, udp_cancel_read_setup,
		      udp_cancel_read_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_shutdown_connect, udp_shutdown_connect_setup,
		      udp_shutdown_connect_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_double_read, udp_double_read_setup,
		      udp_double_read_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_recv_one, udp_recv_one_setup, udp_recv_one_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_recv_two, udp_recv_two_setup, udp_recv_two_teardown)
ISC_TEST_ENTRY_CUSTOM(udp_recv_send, udp_recv_send_setup,
		      udp_recv_send_teardown)

ISC_TEST_LIST_END

ISC_TEST_MAIN
