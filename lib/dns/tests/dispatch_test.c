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
#include <string.h>
#include <unistd.h>
#include <uv.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/app.h>
#include <isc/buffer.h>
#include <isc/managers.h>
#include <isc/refcount.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/name.h>
#include <dns/view.h>

#include "dnstest.h"

/* Timeouts in miliseconds */
#define T_INIT	     120 * 1000
#define T_IDLE	     120 * 1000
#define T_KEEPALIVE  120 * 1000
#define T_ADVERTISED 120 * 1000
#define T_CONNECT    30 * 1000

dns_dispatchmgr_t *dispatchmgr = NULL;
dns_dispatchset_t *dset = NULL;
isc_nm_t *connect_nm = NULL;
static isc_sockaddr_t server_addr;
static isc_sockaddr_t connect_addr;

static int
setup_ephemeral_port(isc_sockaddr_t *addr, sa_family_t family) {
	socklen_t addrlen = sizeof(*addr);
	uv_os_sock_t fd;
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
		close(fd);
		return (r);
	}

	r = getsockname(fd, (struct sockaddr *)&addr->type.sa, &addrlen);
	if (r != 0) {
		perror("setup_ephemeral_port: getsockname()");
		close(fd);
		return (r);
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
	isc_result_t result;
	uv_os_sock_t sock = -1;

	UNUSED(state);

	result = dns_test_begin(NULL, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	connect_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&connect_addr, &in6addr_loopback, 0);

	server_addr = (isc_sockaddr_t){ .length = 0 };
	sock = setup_ephemeral_port(&server_addr, SOCK_DGRAM);
	if (sock < 0) {
		return (-1);
	}
	close(sock);

	/* Create a secondary network manager */
	isc_managers_create(dt_mctx, ncpus, 0, 0, &connect_nm, NULL, NULL,
			    NULL);

	isc_nm_settimeouts(netmgr, T_INIT, T_IDLE, T_KEEPALIVE, T_ADVERTISED);
	isc_nm_settimeouts(connect_nm, T_INIT, T_IDLE, T_KEEPALIVE,
			   T_ADVERTISED);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_managers_destroy(&connect_nm, NULL, NULL, NULL);
	assert_null(connect_nm);

	dns_test_end();

	return (0);
}

static isc_result_t
make_dispatchset(unsigned int ndisps) {
	isc_result_t result;
	isc_sockaddr_t any;
	dns_dispatch_t *disp = NULL;

	result = dns_dispatchmgr_create(dt_mctx, netmgr, &dispatchmgr);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	isc_sockaddr_any(&any);
	result = dns_dispatch_createudp(dispatchmgr, taskmgr, &any, 0, &disp);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	result = dns_dispatchset_create(dt_mctx, taskmgr, disp, &dset, ndisps);
	dns_dispatch_detach(&disp);

	return (result);
}

static void
reset(void) {
	if (dset != NULL) {
		dns_dispatchset_destroy(&dset);
	}
	if (dispatchmgr != NULL) {
		dns_dispatchmgr_detach(&dispatchmgr);
	}
}

/* create dispatch set */
static void
dispatchset_create(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = make_dispatchset(1);
	assert_int_equal(result, ISC_R_SUCCESS);
	reset();

	result = make_dispatchset(10);
	assert_int_equal(result, ISC_R_SUCCESS);
	reset();
}

/* test dispatch set round-robin */
static void
dispatchset_get(void **state) {
	isc_result_t result;
	dns_dispatch_t *d1, *d2, *d3, *d4, *d5;

	UNUSED(state);

	result = make_dispatchset(1);
	assert_int_equal(result, ISC_R_SUCCESS);

	d1 = dns_dispatchset_get(dset);
	d2 = dns_dispatchset_get(dset);
	d3 = dns_dispatchset_get(dset);
	d4 = dns_dispatchset_get(dset);
	d5 = dns_dispatchset_get(dset);

	assert_ptr_equal(d1, d2);
	assert_ptr_equal(d2, d3);
	assert_ptr_equal(d3, d4);
	assert_ptr_equal(d4, d5);

	reset();

	result = make_dispatchset(4);
	assert_int_equal(result, ISC_R_SUCCESS);

	d1 = dns_dispatchset_get(dset);
	d2 = dns_dispatchset_get(dset);
	d3 = dns_dispatchset_get(dset);
	d4 = dns_dispatchset_get(dset);
	d5 = dns_dispatchset_get(dset);

	assert_ptr_equal(d1, d5);
	assert_ptr_not_equal(d1, d2);
	assert_ptr_not_equal(d2, d3);
	assert_ptr_not_equal(d3, d4);
	assert_ptr_not_equal(d4, d5);

	reset();
}

struct {
	isc_nmhandle_t *handle;
	atomic_uint_fast32_t responses;
} testdata;

static dns_dispatch_t *dispatch = NULL;
static dns_dispentry_t *dispentry = NULL;
static atomic_bool first = ATOMIC_VAR_INIT(true);

static void
server_senddone(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(handle);
	UNUSED(eresult);
	UNUSED(cbarg);

	return;
}

static void
nameserver(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	   void *cbarg) {
	isc_region_t response;
	static unsigned char buf1[16];
	static unsigned char buf2[16];

	UNUSED(eresult);
	UNUSED(cbarg);

	memmove(buf1, region->base, 12);
	memset(buf1 + 12, 0, 4);
	buf1[2] |= 0x80; /* qr=1 */

	memmove(buf2, region->base, 12);
	memset(buf2 + 12, 1, 4);
	buf2[2] |= 0x80; /* qr=1 */

	/*
	 * send message to be discarded.
	 */
	response.base = buf1;
	response.length = sizeof(buf1);
	isc_nm_send(handle, &response, server_senddone, NULL);

	/*
	 * send nextitem message.
	 */
	response.base = buf2;
	response.length = sizeof(buf2);
	isc_nm_send(handle, &response, server_senddone, NULL);
}

static void
response(isc_task_t *task, isc_event_t *event) {
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	bool exp_true = true;

	UNUSED(task);

	atomic_fetch_add_relaxed(&testdata.responses, 1);
	if (atomic_compare_exchange_strong(&first, &exp_true, false)) {
		isc_result_t result = dns_dispatch_getnext(dispentry, &devent);
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		dns_dispatch_removeresponse(&dispentry, &devent);
		isc_nmhandle_detach(&testdata.handle);
		isc_app_shutdown();
	}
}

static void
connected(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_region_t *r = (isc_region_t *)cbarg;

	UNUSED(eresult);

	isc_nmhandle_attach(handle, &testdata.handle);
	dns_dispatch_send(dispentry, r, -1);
}

static void
client_senddone(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(handle);
	UNUSED(eresult);
	UNUSED(cbarg);

	return;
}

static void
startit(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);
	dns_dispatch_connect(dispentry);
	isc_event_free(&event);
}

/* test dispatch getnext */
static void
dispatch_getnext(void **state) {
	isc_result_t result;
	isc_region_t region;
	isc_nmsocket_t *sock = NULL;
	isc_task_t *task = NULL;
	unsigned char message[12];
	unsigned char rbuf[12];
	uint16_t id;

	UNUSED(state);

	testdata.handle = NULL;
	atomic_init(&testdata.responses, 0);

	result = isc_task_create(taskmgr, 0, &task);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_dispatchmgr_create(dt_mctx, connect_nm, &dispatchmgr);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_dispatch_createudp(dispatchmgr, taskmgr, &connect_addr, 0,
					&dispatch);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Create a local udp nameserver on the loopback.
	 */
	result = isc_nm_listenudp(netmgr, &server_addr, nameserver, NULL, 0,
				  &sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	region.base = rbuf;
	region.length = sizeof(rbuf);
	result = dns_dispatch_addresponse(
		dispatch, 0, 10000, &server_addr, task, connected,
		client_senddone, response, NULL, &region, &id, &dispentry);
	assert_int_equal(result, ISC_R_SUCCESS);

	memset(message, 0, sizeof(message));
	message[0] = (id >> 8) & 0xff;
	message[1] = id & 0xff;

	region.base = message;
	region.length = sizeof(message);

	result = isc_app_onrun(dt_mctx, task, startit, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_app_run();
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_int_equal(atomic_load_acquire(&testdata.responses), 2);

	isc_nm_stoplistening(sock);
	isc_nmsocket_close(&sock);
	assert_null(sock);

	/*
	 * Shutdown nameserver.
	 */
	isc_task_detach(&task);

	/*
	 * Shutdown the dispatch.
	 */
	dns_dispatch_detach(&dispatch);
	dns_dispatchmgr_detach(&dispatchmgr);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(dispatchset_create, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(dispatchset_get, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(dispatch_getnext, _setup,
						_teardown),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
