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

/* $Id: tkey_test.c,v 1.26 2000/06/22 21:50:57 tale Exp $ */

/*
 * Principal Author: Brian Wellington (core copied from res_test.c)
 */

#include <config.h>

#include <stdlib.h>

#include <isc/app.h>
#include <isc/base64.h>
#include <isc/commandline.h>
#include <isc/entropy.h>
#include <isc/lex.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/result.h>
#include <dns/tkey.h>
#include <dns/tsig.h>
#include <dns/view.h>

#include <dst/result.h>

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
isc_task_t *task1;
dst_key_t *ourkey;
isc_socket_t *s;
isc_sockaddr_t address;
dns_message_t *query, *response, *query2, *response2;
isc_mem_t *mctx;
isc_entropy_t *ectx;
dns_tsigkey_t *tsigkey;
isc_log_t *log = NULL;
isc_logconfig_t *logconfig = NULL;
dns_tsig_keyring_t *ring = NULL;
dns_tkeyctx_t *tctx = NULL;
isc_buffer_t *nonce = NULL;
dns_view_t *view = NULL;
char output[10 * 1024];
isc_buffer_t outbuf;

static void
senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->ev_type == ISC_SOCKEVENT_SENDDONE);
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
	REQUIRE(sevent->ev_type == ISC_SOCKEVENT_RECVDONE);
	REQUIRE(task == task1);

	printf("recvdone\n");
	if (sevent->result != ISC_R_SUCCESS) {
		printf("failed\n");
		exit(-1);
	}

	isc_buffer_init(&source, sevent->region.base, sevent->region.length);
	isc_buffer_add(&source, sevent->n);

	response = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &response);
	CHECK("dns_message_create", result);
	result = dns_message_parse(response, &source, ISC_FALSE);
	CHECK("dns_message_parse", result);

	isc_buffer_init(&outbuf, output, sizeof(output));
	result = dns_message_totext(response, 0, &outbuf);
	CHECK("dns_message_totext", result);
	printf("%.*s\n", (int)isc_buffer_usedlength(&outbuf),
	       (char *)isc_buffer_base(&outbuf));


	tsigkey = NULL;
	result = dns_tkey_processdhresponse(query, response, ourkey, nonce,
					    &tsigkey, ring);
	CHECK("dns_tkey_processdhresponse", result);
	printf("response ok\n");

	isc_buffer_free(&nonce);

	dns_message_destroy(&query);
	dns_message_destroy(&response);

	isc_event_free(&event);

	buildquery2();
}

static void
senddone2(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->ev_type == ISC_SOCKEVENT_SENDDONE);
	REQUIRE(task == task1);

	printf("senddone2\n");

	isc_event_free(&event);
}

static void
recvdone2(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *)event;
	isc_buffer_t source;
	isc_result_t result;
	isc_buffer_t *tsigbuf = NULL;

	REQUIRE(sevent != NULL);
	REQUIRE(sevent->ev_type == ISC_SOCKEVENT_RECVDONE);
	REQUIRE(task == task1);

	printf("recvdone2\n");
	if (sevent->result != ISC_R_SUCCESS) {
		printf("failed\n");
		exit(-1);
	}

	isc_buffer_init(&source, sevent->region.base, sevent->region.length);
	isc_buffer_add(&source, sevent->n);

	response = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &response2);
	result = dns_message_getquerytsig(query2, mctx, &tsigbuf);
	CHECK("dns_message_getquerytsig", result);
	result = dns_message_setquerytsig(response2, tsigbuf);
	CHECK("dns_message_setquerytsig", result);
	isc_buffer_free(&tsigbuf);
	dns_message_settsigkey(response2, tsigkey);
	CHECK("dns_message_create", result);
	result = dns_message_parse(response2, &source, ISC_FALSE);
	CHECK("dns_message_parse", result);
	isc_buffer_init(&outbuf, output, sizeof(output));
	result = dns_message_totext(response2, 0, &outbuf);
	CHECK("dns_message_totext", result);
	printf("%.*s\n", (int)isc_buffer_usedlength(&outbuf),
	       (char *)isc_buffer_base(&outbuf));
	result = dns_view_create(mctx, 0, "_test", &view);
	CHECK("dns_view_create", result);
	dns_view_setkeyring(view, ring);
	result = dns_message_checksig(response2, view);
	CHECK("dns_message_checksig", result);

	result = dns_tkey_processdeleteresponse(query2, response2, ring);
	CHECK("dns_tkey_processdeleteresponse", result);
	printf("response ok\n");

	dns_message_destroy(&query2);
	dns_message_destroy(&response2);

	isc_event_free(&event);

	isc_app_shutdown();
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
	isc_sockaddr_t sa;

	dns_fixedname_init(&keyname);
	isc_buffer_init(&namestr, "tkeytest.", 9);
	isc_buffer_add(&namestr, 9);
	result = dns_name_fromtext(dns_fixedname_name(&keyname), &namestr,
				   NULL, ISC_FALSE, NULL);
	CHECK("dns_name_fromtext", result);

	result = isc_lex_create(mctx, 1024, &lex);
	CHECK("isc_lex_create", result);

	isc_buffer_init(&keybufin, "1234", 4);
	isc_buffer_add(&keybufin, 4);
	result = isc_lex_openbuffer(lex, &keybufin);
	CHECK("isc_lex_openbuffer", result);

	isc_buffer_init(&keybuf, keydata, 3);
	result = isc_base64_tobuffer(lex, &keybuf, -1);
	CHECK("isc_base64_tobuffer", result);

	isc_lex_close(lex);
	isc_lex_destroy(&lex);

	isc_buffer_usedregion(&keybuf, &r);

	result = dns_tsigkey_create(dns_fixedname_name(&keyname),
				    DNS_TSIG_HMACMD5_NAME,
				    r.base, r.length, ISC_FALSE,
				    NULL, 0, 0, mctx, ring, &key);
	CHECK("dns_tsigkey_create", result);

	result = isc_buffer_allocate(mctx, &nonce, 16);
	CHECK("isc_buffer_allocate", result);

	result = isc_entropy_getdata(ectx, isc_buffer_base(nonce),
				     isc_buffer_length(nonce), NULL,
				     ISC_ENTROPY_BLOCKING);
	CHECK("isc_entropy_getdata", result);
	
	query = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &query);
	CHECK("dns_message_create", result);

	dns_message_settsigkey(query, key);

	result = dns_tkey_builddhquery(query, ourkey, dns_rootname,
				       DNS_TSIG_HMACMD5_NAME, nonce, 3600);
	CHECK("dns_tkey_builddhquery", result);

	isc_buffer_init(&qbuffer, qdata, sizeof(qdata));

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

	isc_buffer_init(&outbuf, output, sizeof(output));
	result = dns_message_totext(query, 0, &outbuf);
	CHECK("dns_message_totext", result);
	printf("%.*s\n", (int)isc_buffer_usedlength(&outbuf),
	       (char *)isc_buffer_base(&outbuf));

	isc_buffer_usedregion(&qbuffer, &r);
	isc_sockaddr_any(&sa);
	result = isc_socket_bind(s, &sa);
	CHECK("isc_socket_bind", result);
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
	dns_message_settsigkey(query2, tsigkey);

	result = dns_tkey_builddeletequery(query2, tsigkey);
	CHECK("dns_tkey_builddeletequery", result);

	isc_buffer_init(&qbuffer, qdata, sizeof(qdata));

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

	isc_buffer_init(&outbuf, output, sizeof(output));
	result = dns_message_totext(query2, 0, &outbuf);
	CHECK("dns_message_totext", result);
	printf("%.*s\n", (int)isc_buffer_usedlength(&outbuf),
	       (char *)isc_buffer_base(&outbuf));

	isc_buffer_usedregion(&qbuffer, &r);
	result = isc_socket_sendto(s, &r, task1, senddone2, NULL, &address,
				   NULL);
	CHECK("isc_socket_sendto", result);
	inr.base = rdata;
	inr.length = sizeof(rdata);
	result = isc_socket_recv(s, &inr, 1, task1, recvdone2, NULL);
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
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t b;
	isc_result_t result;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_mutex_init(&lock) == ISC_R_SUCCESS);

	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	ectx = NULL;
	RUNTIME_CHECK(isc_entropy_create(mctx, &ectx) == ISC_R_SUCCESS);

	result = isc_entropy_createfilesource(ectx, "/dev/random");
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr,
			"%s only runs when /dev/random is available.\n",
			argv[0]);
		exit(-1);
	}

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

	RUNTIME_CHECK(dst_lib_init(mctx, ectx,
				   ISC_ENTROPY_BLOCKING|ISC_ENTROPY_GOODONLY)
		      == ISC_R_SUCCESS);

	taskmgr = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &taskmgr) ==
		      ISC_R_SUCCESS);
	task1 = NULL;
	RUNTIME_CHECK(isc_task_create(taskmgr, 0, &task1) ==
		      ISC_R_SUCCESS);
	timermgr = NULL;
	RUNTIME_CHECK(isc_timermgr_create(mctx, &timermgr) == ISC_R_SUCCESS);
	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_log_create(mctx, &log, &logconfig) == ISC_R_SUCCESS);
	ring = NULL;
	RUNTIME_CHECK(dns_tsigkeyring_create(mctx, &ring) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_tkeyctx_create(mctx, ectx, &tctx) == ISC_R_SUCCESS);

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

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);
	isc_buffer_init(&b, "client.", strlen("client."));
	isc_buffer_add(&b, strlen("client."));
	result = dns_name_fromtext(name, &b, dns_rootname, ISC_FALSE, NULL);
	CHECK("dns_name_fromtext", result);

	ourkey = NULL;
	result = dst_key_fromfile(name, 2982, DNS_KEYALG_DH,
				  DST_TYPE_PRIVATE, NULL, mctx, &ourkey);
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
	isc_taskmgr_destroy(&taskmgr);

	isc_socket_detach(&s);
	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	dst_key_free(&ourkey);

	dns_tkeyctx_destroy(&tctx);

	dns_view_detach(&view);

	isc_log_destroy(&log);

	dst_lib_destroy();
	isc_entropy_detach(&ectx);

	if (verbose)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_mutex_destroy(&lock);

	isc_app_finish();

	return (0);
}
