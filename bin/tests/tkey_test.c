/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington (mostly copied from res_test.c)
 */

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/error.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/app.h>
#include <isc/mutex.h>
#include <isc/boolean.h>
#include <isc/net.h>
#include <isc/socket.h>
#include <isc/log.h>
#include <isc/util.h>
#include <isc/lex.h>
#include <isc/base64.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/resolver.h>
#include <dns/events.h>
#include <dns/tsig.h>
#include <dns/tkey.h>
#include <dns/keyvalues.h>
#include <dns/view.h>

#define CHECK(str, x) { \
	if ((x) != ISC_R_SUCCESS) { \
		printf("%s: %s\n", (str), isc_result_totext(x)); \
		exit(-1); \
	} \
}

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK (unsigned long)0x7F000001UL
#endif

static void buildquery(void);
static void buildquery2(void);

isc_mutex_t lock;
isc_taskmgr_t *taskmgr;
isc_task_t *task1, *task2;
dst_key_t *ourkey;
isc_socket_t *s;
isc_sockaddr_t address;
dns_message_t *query, *response, *query2, *response2;
isc_mem_t *mctx;
dns_tsigkey_t *tsigkey;
isc_log_t *log = NULL;
isc_logconfig_t *logconfig = NULL;
dns_tsig_keyring_t *ring = NULL;
dns_tkey_ctx_t *tctx = NULL;
isc_buffer_t *nonce = NULL;
dns_view_t *view = NULL;

static void
senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->type == ISC_SOCKEVENT_SENDDONE);
	REQUIRE(task == task1);

	printf("senddone\n");

	isc_event_free(&event);
}

static void
recvdone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	isc_buffer_t source;
	isc_result_t result;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->type == ISC_SOCKEVENT_RECVDONE);
	REQUIRE(task == task1);

	printf("recvdone\n");
	if (sevent->result != ISC_R_SUCCESS) {
		printf("failed\n");
		exit(-1);
	}

	isc_buffer_init(&source, sevent->region.base, sevent->region.length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, sevent->n);

	response = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &response);
	CHECK("dns_message_create", result);
	result = dns_message_parse(response, &source, ISC_FALSE);
	CHECK("dns_message_parse", result);

	tsigkey = NULL;
	result = dns_tkey_processdhresponse(query, response, ourkey, nonce,
					    &tsigkey, ring);
	CHECK("dns_tkey_processdhresponse", result);
	printf("response ok\n");

	buildquery2();
}

static void
senddone2(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->type == ISC_SOCKEVENT_SENDDONE);
	REQUIRE(task == task2);

	printf("senddone2\n");

	isc_event_free(&event);
}

static void
recvdone2(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	isc_buffer_t source;
	isc_result_t result;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->type == ISC_SOCKEVENT_RECVDONE);
	REQUIRE(task == task2);

	printf("recvdone2\n");
	if (sevent->result != ISC_R_SUCCESS) {
		printf("failed\n");
		exit(-1);
	}

	isc_buffer_init(&source, sevent->region.base, sevent->region.length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, sevent->n);

	response = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &response2);
	response2->querytsig = query2->tsig;
	query2->tsig = NULL;
	response2->tsigkey = query2->tsigkey;
	query2->tsigkey = NULL;
	CHECK("dns_message_create", result);
	result = dns_message_parse(response2, &source, ISC_FALSE);
	CHECK("dns_message_parse", result);
	result = dns_view_create(mctx, 0, "_test", &view);
	CHECK("dns_view_create", result);
	dns_view_setkeyring(view, ring);
	result = dns_message_checksig(response2, view);
	CHECK("dns_message_checksig", result);

	result = dns_tkey_processdeleteresponse(query2, response2, ring);
	CHECK("dns_tkey_processdeleteresponse", result);
	printf("response ok\n");
	exit(0);
}

static void
buildquery(void) {
	unsigned char qdata[1024], rdata[2048];
	isc_buffer_t qbuffer;
	isc_region_t r, inr;
	isc_result_t result;
	dns_fixedname_t keyname;
	dns_tsigkey_t *key = NULL;
	isc_buffer_t namestr, keybuf, keybufin;
	isc_lex_t *lex = NULL;
	unsigned char keydata[3];

	dns_fixedname_init(&keyname);
	isc_buffer_init(&namestr, "tkeytest.", 9, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&namestr, 9);
	result = dns_name_fromtext(dns_fixedname_name(&keyname), &namestr,
				   NULL, ISC_FALSE, NULL);
	CHECK("dns_name_fromtext", result);

	result = isc_lex_create(mctx, 1024, &lex);
	CHECK("isc_lex_create", result);

	isc_buffer_init(&keybufin, "1234", 4, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&keybufin, 4);
	result = isc_lex_openbuffer(lex, &keybufin);
	CHECK("isc_lex_openbuffer", result);

	isc_buffer_init(&keybuf, keydata, 3, ISC_BUFFERTYPE_TEXT);
	result = isc_base64_tobuffer(lex, &keybuf, -1);
	CHECK("isc_base64_tobuffer", result);

	isc_buffer_used(&keybuf, &r);

	result = dns_tsigkey_create(dns_fixedname_name(&keyname),
				    DNS_TSIG_HMACMD5_NAME,
				    r.base, r.length, ISC_FALSE,
				    NULL, 0, 0, mctx, ring, &key);
	CHECK("dns_tsigkey_create", result);

	result = isc_buffer_allocate(mctx, &nonce, 16, ISC_BUFFERTYPE_BINARY);
	CHECK("isc_buffer_allocate", result);

	result = dst_random_get(16, nonce);
	CHECK("dst_random_get", result);
	
	query = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &query);
	CHECK("dns_message_create", result);

	query->tsigkey = key;

	result = dns_tkey_builddhquery(query, ourkey, dns_rootname,
				       DNS_TSIG_HMACMD5_NAME, nonce, 3600);
	CHECK("dns_tkey_builddhquery", result);

	isc_buffer_init(&qbuffer, qdata, sizeof(qdata), ISC_BUFFERTYPE_BINARY);

	result = dns_message_renderbegin(query, &qbuffer);
	CHECK("dns_message_renderbegin", result);
	result = dns_message_rendersection(query, DNS_SECTION_QUESTION, 0);
	CHECK("dns_message_rendersection(question)", result);
	result = dns_message_rendersection(query, DNS_SECTION_ANSWER, 0);
	CHECK("dns_message_rendersection(answer)", result);
	result = dns_message_rendersection(query, DNS_SECTION_AUTHORITY, 0);
	CHECK("dns_message_rendersection(auth)", result);
	result = dns_message_rendersection(query, DNS_SECTION_ADDITIONAL, 0);
	CHECK("dns_message_rendersection(add)", result);
	result = dns_message_renderend(query);
	CHECK("dns_message_renderend", result);

	isc_buffer_used(&qbuffer, &r);
	result = isc_socket_sendto(s, &r, task1, senddone, NULL, &address,
				   NULL);
	CHECK("isc_socket_sendto", result);
	inr.base = rdata;
	inr.length = sizeof(rdata);
	result = isc_socket_recv(s, &inr, 1, task1, recvdone, NULL);
	CHECK("isc_socket_recv", result);
}

static void
buildquery2(void) {
	unsigned char qdata[1024], rdata[2048];
	isc_buffer_t qbuffer;
	isc_region_t r, inr;
	isc_result_t result;

	query2 = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &query2);
	CHECK("dns_message_create", result);
	query2->tsigkey = tsigkey;

	result = dns_tkey_builddeletequery(query2, tsigkey);
	CHECK("dns_tkey_builddeletequery", result);

	isc_buffer_init(&qbuffer, qdata, sizeof(qdata), ISC_BUFFERTYPE_BINARY);

	result = dns_message_renderbegin(query2, &qbuffer);
	CHECK("dns_message_renderbegin", result);
	result = dns_message_rendersection(query2, DNS_SECTION_QUESTION, 0);
	CHECK("dns_message_rendersection(question)", result);
	result = dns_message_rendersection(query2, DNS_SECTION_ANSWER, 0);
	CHECK("dns_message_rendersection(answer)", result);
	result = dns_message_rendersection(query2, DNS_SECTION_AUTHORITY, 0);
	CHECK("dns_message_rendersection(auth)", result);
	result = dns_message_rendersection(query2, DNS_SECTION_ADDITIONAL, 0);
	CHECK("dns_message_rendersection(add)", result);
	result = dns_message_renderend(query2);
	CHECK("dns_message_renderend", result);

	isc_buffer_used(&qbuffer, &r);
	result = isc_socket_sendto(s, &r, task2, senddone2, NULL, &address,
				   NULL);
	CHECK("isc_socket_sendto", result);
	inr.base = rdata;
	inr.length = sizeof(rdata);
	result = isc_socket_recv(s, &inr, 1, task2, recvdone2, NULL);
	CHECK("isc_socket_recv", result);
}

int
main(int argc, char *argv[]) {
	isc_boolean_t verbose = ISC_FALSE;
	unsigned int workers = 2;
	isc_timermgr_t *timermgr;
	int ch;
	isc_socketmgr_t *socketmgr;
	struct in_addr inaddr;
	isc_result_t result;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_mutex_init(&lock) == ISC_R_SUCCESS);

	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	while ((ch = isc_commandline_parse(argc, argv, "vw:")) != -1) {
		switch (ch) {
		case 'v':
			verbose = ISC_TRUE;
			break;
		case 'w':
			workers = (unsigned int)atoi(isc_commandline_argument);
			break;
		}
	}

	if (verbose) {
		printf("%u workers\n", workers);
		printf("IPv4: %s\n", isc_result_totext(isc_net_probeipv4()));
		printf("IPv6: %s\n", isc_result_totext(isc_net_probeipv6()));
	}

	dns_result_register();
	dst_result_register();

	taskmgr = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &taskmgr) ==
		      ISC_R_SUCCESS);
	task1 = NULL;
	RUNTIME_CHECK(isc_task_create(taskmgr, mctx, 0, &task1) ==
		      ISC_R_SUCCESS);
	task2 = NULL;
	RUNTIME_CHECK(isc_task_create(taskmgr, mctx, 0, &task2) ==
		      ISC_R_SUCCESS);
	timermgr = NULL;
	RUNTIME_CHECK(isc_timermgr_create(mctx, &timermgr) == ISC_R_SUCCESS);
	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_log_create(mctx, &log, &logconfig) == ISC_R_SUCCESS);
	ring = NULL;
	RUNTIME_CHECK(dns_tsigkeyring_create(mctx, &ring) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_tkeyctx_create(mctx, &tctx) == ISC_R_SUCCESS);

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc != 0)
		printf("ignoring trailing arguments\n");

	s = NULL;
	RUNTIME_CHECK(isc_socket_create(socketmgr, PF_INET,
					isc_sockettype_udp, &s) ==
		      ISC_R_SUCCESS);

	inaddr.s_addr = htonl(INADDR_LOOPBACK);
	isc_sockaddr_fromin(&address, &inaddr, 53);

	ourkey = NULL;
	result = dst_key_fromfile("client.", 2982, DNS_KEYALG_DH,
				  DST_TYPE_PRIVATE, mctx, &ourkey);
	CHECK("dst_key_fromfile", result);


	buildquery();

	(void)isc_app_run();

	/*
	 * XXXRTH if we get a control-C before we get to isc_app_run(),
	 * we're in trouble (because we might try to destroy things before
	 * they've been created.
	 */

	isc_task_shutdown(task1);
	isc_task_detach(&task1);
	isc_task_shutdown(task2);
	isc_task_detach(&task2);
	isc_taskmgr_destroy(&taskmgr);

	isc_socket_detach(&s);
	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	dns_tsigkeyring_destroy(&ring);
	dns_tkeyctx_destroy(&tctx);
	if (verbose)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_mutex_destroy(&lock);

	isc_app_finish();

	return (0);
}
