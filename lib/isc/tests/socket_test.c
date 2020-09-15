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

/*! \file */

#include <config.h>

#if HAVE_CMOCKA
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <sched.h> /* IWYU pragma: keep */
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/mutex.h>
#include <isc/platform.h>
#include <isc/socket.h>
#include <isc/print.h>

#include "../task_p.h"
#include "../unix/socket_p.h"
#include "isctest.h"

static bool recv_dscp;
static unsigned int recv_dscp_value;
static bool recv_trunc;
isc_socket_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
isc_task_t *test_task = NULL;
static isc_mutex_t lock;

/*
 * Helper functions
 */

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = isc_test_begin(NULL, true, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	if (s1 != NULL) {
		isc_socket_detach(&s1);
	}
	if (s2 != NULL) {
		isc_socket_detach(&s2);
	}
	if (s3 != NULL) {
		isc_socket_detach(&s3);
	}
	if (test_task != NULL) {
		isc_task_detach(&test_task);
	}

	isc_test_end();

	return (0);
}

typedef struct {
	bool done;
	isc_result_t result;
	isc_socket_t *socket;
} completion_t;

static void
completion_init(completion_t *completion) {
	LOCK(&lock);
	completion->done = false;
	completion->socket = NULL;
	UNLOCK(&lock);
}

static void
accept_done(isc_task_t *task, isc_event_t *event) {
	isc_socket_newconnev_t *nevent = (isc_socket_newconnev_t *)event;
	completion_t *completion = event->ev_arg;

	UNUSED(task);

	LOCK(&lock);
	completion->result = nevent->result;
	completion->done = true;
	if (completion->result == ISC_R_SUCCESS) {
		completion->socket = nevent->newsocket;
	}
	UNLOCK(&lock);

	isc_event_free(&event);
}

static void
event_done(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sev = NULL;
	isc_socket_connev_t *connev = NULL;
	completion_t *completion = event->ev_arg;
	UNUSED(task);

	LOCK(&lock);
	switch (event->ev_type) {
	case ISC_SOCKEVENT_RECVDONE:
	case ISC_SOCKEVENT_SENDDONE:
		sev = (isc_socketevent_t *) event;
		completion->result = sev->result;
		if ((sev->attributes & ISC_SOCKEVENTATTR_DSCP) != 0) {
			recv_dscp = true;
			recv_dscp_value = sev->dscp;;
		} else {
			recv_dscp = false;
		}
		recv_trunc = ((sev->attributes & ISC_SOCKEVENTATTR_TRUNC) != 0);
		break;
	case ISC_SOCKEVENT_CONNECT:
		connev = (isc_socket_connev_t *) event;
		completion->result = connev->result;
		break;
	default:
		assert_false(true);
	}
	completion->done = true;
	UNLOCK(&lock);
	isc_event_free(&event);
}

static isc_result_t
waitfor(completion_t *completion) {
	int i = 0;

	LOCK(&lock);
	while (!completion->done && i++ < 5000) {
		UNLOCK(&lock);

#ifndef ISC_PLATFORM_USETHREADS
		while (isc__taskmgr_ready(taskmgr))
			isc__taskmgr_dispatch(taskmgr);
#endif
		isc_test_nap(1000);
		LOCK(&lock);
	}
	if (completion->done) {
		UNLOCK(&lock);
		return (ISC_R_SUCCESS);
	}
	UNLOCK(&lock);
	return (ISC_R_FAILURE);
}

static void
waitbody(void) {
#ifndef ISC_PLATFORM_USETHREADS
	struct timeval tv;
	isc_socketwait_t *swait = NULL;

	while (isc__taskmgr_ready(taskmgr))
		isc__taskmgr_dispatch(taskmgr);
	if (socketmgr != NULL) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000 ;
		if (isc__socketmgr_waitevents(socketmgr, &tv, &swait) > 0)
			isc__socketmgr_dispatch(socketmgr, swait);
	} else
#endif
		isc_test_nap(1000);
}

static isc_result_t
waitfor2(completion_t *c1, completion_t *c2) {
	int i = 0;

	LOCK(&lock);
	while (!(c1->done && c2->done) && i++ < 5000) {
		UNLOCK(&lock);
		waitbody();
		LOCK(&lock);
	}
	if (c1->done && c2->done) {
		UNLOCK(&lock);
		return (ISC_R_SUCCESS);
	}
	UNLOCK(&lock);
	return (ISC_R_FAILURE);
}

/*
 * Individual unit tests
 */

/* Test UDP sendto/recv (IPv4) */
static void
udp_sendto_test(void **state)  {
	isc_result_t result;
	isc_sockaddr_t addr1, addr2;
	struct in_addr in;
	char sendbuf[BUFSIZ], recvbuf[BUFSIZ];
	completion_t completion;
	isc_region_t r;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	in.s_addr = inet_addr("127.0.0.1");
	isc_sockaddr_fromin(&addr1, &in, 0);
	isc_sockaddr_fromin(&addr2, &in, 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s1);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s1, &addr1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s2);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s2, &addr2, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s2, &addr2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr2) != 0);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	completion_init(&completion);
	result = isc_socket_sendto(s1, &r, test_task, event_done, &completion,
				   &addr2, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s2, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}

/* Test UDP sendto/recv with duplicated socket */
static void
udp_dup_test(void **state) {
	isc_result_t result;
	isc_sockaddr_t addr1, addr2;
	struct in_addr in;
	char sendbuf[BUFSIZ], recvbuf[BUFSIZ];
	completion_t completion;
	isc_region_t r;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	in.s_addr = inet_addr("127.0.0.1");
	isc_sockaddr_fromin(&addr1, &in, 0);
	isc_sockaddr_fromin(&addr2, &in, 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s1);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s1, &addr1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s2);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s2, &addr2, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s2, &addr2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr2) != 0);

	result = isc_socket_dup(s2, &s3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	completion_init(&completion);
	result = isc_socket_sendto(s1, &r, test_task, event_done, &completion,
				   &addr2, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	snprintf(sendbuf, sizeof(sendbuf), "World");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	completion_init(&completion);
	result = isc_socket_sendto(s1, &r, test_task, event_done, &completion,
				   &addr2, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s2, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s3, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "World");

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}

/* Test UDP sendto/recv (IPv4) */
static void
udp_dscp_v4_test(void **state) {
	isc_result_t result;
	isc_sockaddr_t addr1, addr2;
	struct in_addr in;
	char sendbuf[BUFSIZ], recvbuf[BUFSIZ];
	completion_t completion;
	isc_region_t r;
	isc_socketevent_t *socketevent;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	in.s_addr = inet_addr("127.0.0.1");
	isc_sockaddr_fromin(&addr1, &in, 0);
	isc_sockaddr_fromin(&addr2, &in, 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s1);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s1, &addr1, ISC_SOCKET_REUSEADDRESS);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s2);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s2, &addr2, ISC_SOCKET_REUSEADDRESS);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s2, &addr2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr2) != 0);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	completion_init(&completion);

	socketevent = isc_socket_socketevent(mctx, s1, ISC_SOCKEVENT_SENDDONE,
					     event_done, &completion);
	assert_non_null(socketevent);

	if ((isc_net_probedscp() & ISC_NET_DSCPPKTV4) != 0) {
		socketevent->dscp = 056; /* EF */
		socketevent->attributes |= ISC_SOCKEVENTATTR_DSCP;
	} else if ((isc_net_probedscp() & ISC_NET_DSCPSETV4) != 0) {
		isc_socket_dscp(s1, 056);  /* EF */
		socketevent->dscp = 0;
		socketevent->attributes &= ~ISC_SOCKEVENTATTR_DSCP;
	}

	recv_dscp = false;
	recv_dscp_value = 0;

	result = isc_socket_sendto2(s1, &r, test_task, &addr2, NULL,
				    socketevent, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s2, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");

	if ((isc_net_probedscp() & ISC_NET_DSCPRECVV4) != 0) {
		assert_true(recv_dscp);
		assert_int_equal(recv_dscp_value, 056);
	} else {
		assert_false(recv_dscp);
	}

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}

#if defined(ISC_PLATFORM_HAVEIPV6) && defined(WANT_IPV6)
/* Test UDP sendto/recv (IPv6) */
static void
udp_dscp_v6_test(void **state) {
	isc_result_t result;
	isc_sockaddr_t addr1, addr2;
	struct in6_addr in6;
	char sendbuf[BUFSIZ], recvbuf[BUFSIZ];
	completion_t completion;
	isc_region_t r;
	isc_socketevent_t *socketevent;
	int n;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	n = inet_pton(AF_INET6, "::1", &in6.s6_addr);
	assert_true(n == 1);
	isc_sockaddr_fromin6(&addr1, &in6, 0);
	isc_sockaddr_fromin6(&addr2, &in6, 0);

	result = isc_socket_create(socketmgr, PF_INET6, isc_sockettype_udp,
				   &s1);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s1, &addr1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);

	result = isc_socket_create(socketmgr, PF_INET6, isc_sockettype_udp,
				   &s2);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s2, &addr2, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s2, &addr2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr2) != 0);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	completion_init(&completion);

	socketevent = isc_socket_socketevent(mctx, s1, ISC_SOCKEVENT_SENDDONE,
					     event_done, &completion);
	assert_non_null(socketevent);

	if ((isc_net_probedscp() & ISC_NET_DSCPPKTV6) != 0) {
		socketevent->dscp = 056; /* EF */
		socketevent->attributes = ISC_SOCKEVENTATTR_DSCP;
	} else if ((isc_net_probedscp() & ISC_NET_DSCPSETV6) != 0) {
		isc_socket_dscp(s1, 056);  /* EF */
	}

	recv_dscp = false;
	recv_dscp_value = 0;

	result = isc_socket_sendto2(s1, &r, test_task, &addr2, NULL,
				    socketevent, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s2, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");
	if ((isc_net_probedscp() & ISC_NET_DSCPRECVV6) != 0) {
		assert_true(recv_dscp);
		assert_int_equal(recv_dscp_value, 056);
	} else {
		assert_false(recv_dscp);
	}

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}
#endif

/* Test TCP sendto/recv (IPv4) */
static void
tcp_dscp_v4_test(void **state) {
	isc_result_t result;
	isc_sockaddr_t addr1;
	struct in_addr in;
	char sendbuf[BUFSIZ], recvbuf[BUFSIZ];
	completion_t completion, completion2;
	isc_region_t r;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	in.s_addr = inet_addr("127.0.0.1");
	isc_sockaddr_fromin(&addr1, &in, 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_tcp, &s1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_socket_bind(s1, &addr1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);

	result = isc_socket_listen(s1, 3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_tcp, &s2);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	completion_init(&completion2);
	result = isc_socket_accept(s1, test_task, accept_done, &completion2);
	assert_int_equal(result, ISC_R_SUCCESS);

	completion_init(&completion);
	result = isc_socket_connect(s2, &addr1, test_task, event_done,
				    &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor2(&completion, &completion2);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_true(completion2.done);
	assert_int_equal(completion2.result, ISC_R_SUCCESS);
	s3 = completion2.socket;

	isc_socket_dscp(s2, 056);  /* EF */

	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	recv_dscp = false;
	recv_dscp_value = 0;

	completion_init(&completion);
	result = isc_socket_sendto(s2, &r, test_task, event_done, &completion,
				   NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s3, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");

	if ((isc_net_probedscp() & ISC_NET_DSCPRECVV4) != 0) {
		if (recv_dscp) {
			assert_int_equal(recv_dscp_value, 056);
		}
	} else {
		assert_false(recv_dscp);
	}

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}

#if defined(ISC_PLATFORM_HAVEIPV6) && defined(WANT_IPV6)
/* Test TCP sendto/recv (IPv6) */
static void
tcp_dscp_v6_test(void **state) {
	isc_result_t result;
	isc_sockaddr_t addr1;
	struct in6_addr in6;
	char sendbuf[BUFSIZ], recvbuf[BUFSIZ];
	completion_t completion, completion2;
	isc_region_t r;
	int n;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	n = inet_pton(AF_INET6, "::1", &in6.s6_addr);
	assert_true(n == 1);
	isc_sockaddr_fromin6(&addr1, &in6, 0);

	result = isc_socket_create(socketmgr, PF_INET6, isc_sockettype_tcp,
				   &s1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_socket_bind(s1, &addr1, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);

	result = isc_socket_listen(s1, 3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_socket_create(socketmgr, PF_INET6, isc_sockettype_tcp,
				   &s2);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	completion_init(&completion2);
	result = isc_socket_accept(s1, test_task, accept_done, &completion2);
	assert_int_equal(result, ISC_R_SUCCESS);

	completion_init(&completion);
	result = isc_socket_connect(s2, &addr1, test_task, event_done,
				    &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor2(&completion, &completion2);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_true(completion2.done);
	assert_int_equal(completion2.result, ISC_R_SUCCESS);
	s3 = completion2.socket;

	isc_socket_dscp(s2, 056);  /* EF */

	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	recv_dscp = false;
	recv_dscp_value = 0;

	completion_init(&completion);
	result = isc_socket_sendto(s2, &r, test_task, event_done, &completion,
				   NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	result = isc_socket_recv(s3, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");

	if ((isc_net_probedscp() & ISC_NET_DSCPRECVV6) != 0) {
		/*
		 * IPV6_RECVTCLASS is undefined for TCP however
		 * if we do get it it should be the value we set.
		 */
		if (recv_dscp) {
			assert_int_equal(recv_dscp_value, 056);
		}
	} else {
		assert_false(recv_dscp);
	}

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}
#endif

/* probe dscp capabilities */
static void
net_probedscp_test(void **state) {
	unsigned int n;

	UNUSED(state);

	n = isc_net_probedscp();
	assert_true((n & ~ISC_NET_DSCPALL) == 0);

	/* ISC_NET_DSCPSETV4 MUST be set if any is set. */
	if (n & (ISC_NET_DSCPPKTV4|ISC_NET_DSCPRECVV4)) {
		assert_true((n & ISC_NET_DSCPSETV4) != 0);
	}

	/* ISC_NET_DSCPSETV6 MUST be set if any is set. */
	if (n & (ISC_NET_DSCPPKTV6|ISC_NET_DSCPRECVV6)) {
		assert_true((n & ISC_NET_DSCPSETV6) != 0);
	}

#if 0
	fprintf(stdout, "IPv4:%s%s%s\n",
		(n & ISC_NET_DSCPSETV4) ? " set" : "none",
		(n & ISC_NET_DSCPPKTV4) ? " packet" : "",
		(n & ISC_NET_DSCPRECVV4) ? " receive" : "");

	fprintf(stdout, "IPv6:%s%s%s\n",
		(n & ISC_NET_DSCPSETV6) ? " set" : "none",
		(n & ISC_NET_DSCPPKTV6) ? " packet" : "",
		(n & ISC_NET_DSCPRECVV6) ? " receive" : "");
#endif
}

/* Test UDP truncation detection */
static void
udp_trunc_test(void **state) {
	isc_result_t result;
	isc_sockaddr_t addr1, addr2;
	struct in_addr in;
	char sendbuf[BUFSIZ * 2], recvbuf[BUFSIZ];
	completion_t completion;
	isc_region_t r;
	isc_socketevent_t *socketevent;

	UNUSED(state);

	result = isc_mutex_init(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);

	in.s_addr = inet_addr("127.0.0.1");
	isc_sockaddr_fromin(&addr1, &in, 0);
	isc_sockaddr_fromin(&addr2, &in, 0);

	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s1);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s1, &addr1, ISC_SOCKET_REUSEADDRESS);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s1, &addr1);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr1) != 0);
	result = isc_socket_create(socketmgr, PF_INET, isc_sockettype_udp, &s2);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_bind(s2, &addr2, ISC_SOCKET_REUSEADDRESS);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_socket_getsockname(s2, &addr2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_getport(&addr2) != 0);

	result = isc_task_create(taskmgr, 0, &test_task);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Send a message that will not be truncated.
	 */
	memset(sendbuf, 0xff, sizeof(sendbuf));
	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = strlen(sendbuf) + 1;

	completion_init(&completion);

	socketevent = isc_socket_socketevent(mctx, s1, ISC_SOCKEVENT_SENDDONE,
					     event_done, &completion);
	assert_non_null(socketevent);

	result = isc_socket_sendto2(s1, &r, test_task, &addr2, NULL,
				    socketevent, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	recv_trunc = false;
	result = isc_socket_recv(s2, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");
	assert_false(recv_trunc);

	/*
	 * Send a message that will be truncated.
	 */
	memset(sendbuf, 0xff, sizeof(sendbuf));
	snprintf(sendbuf, sizeof(sendbuf), "Hello");
	r.base = (void *) sendbuf;
	r.length = sizeof(sendbuf);

	completion_init(&completion);

	socketevent = isc_socket_socketevent(mctx, s1, ISC_SOCKEVENT_SENDDONE,
					     event_done, &completion);
	assert_non_null(socketevent);

	result = isc_socket_sendto2(s1, &r, test_task, &addr2, NULL,
				    socketevent, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);

	r.base = (void *) recvbuf;
	r.length = BUFSIZ;
	completion_init(&completion);
	recv_trunc = false;
	result = isc_socket_recv(s2, &r, 1, test_task, event_done, &completion);
	assert_int_equal(result, ISC_R_SUCCESS);
	waitfor(&completion);
	assert_true(completion.done);
	assert_int_equal(completion.result, ISC_R_SUCCESS);
	assert_string_equal(recvbuf, "Hello");
	assert_true(recv_trunc);

	result = isc_mutex_destroy(&lock);
	assert_int_equal(result, ISC_R_SUCCESS);
}

/*
 * Main
 */
int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(udp_sendto_test,
						_setup, _teardown),
		cmocka_unit_test_setup_teardown(udp_dup_test,
						_setup, _teardown),
		cmocka_unit_test_setup_teardown(tcp_dscp_v4_test,
						_setup, _teardown),
#if defined(ISC_PLATFORM_HAVEIPV6) && defined(WANT_IPV6)
		cmocka_unit_test_setup_teardown(tcp_dscp_v6_test,
						_setup, _teardown),
#endif
		cmocka_unit_test_setup_teardown(udp_dscp_v4_test,
						_setup, _teardown),
#if defined(ISC_PLATFORM_HAVEIPV6) && defined(WANT_IPV6)
		cmocka_unit_test_setup_teardown(udp_dscp_v6_test,
						_setup, _teardown),
#endif
		cmocka_unit_test_setup_teardown(net_probedscp_test,
						_setup, _teardown),
		cmocka_unit_test_setup_teardown(udp_trunc_test,
						_setup, _teardown),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (0);

}

#endif
