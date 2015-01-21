/*
 * Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/base64.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/request.h>
#include <dns/result.h>
#include <dns/view.h>

#include <dns/events.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/types.h>

#include <dst/result.h>

#define CHECK(str, x) { \
	if ((x) != ISC_R_SUCCESS) { \
		fprintf(stderr, "I:%s: %s\n", (str), isc_result_totext(x)); \
		exit(-1); \
	} \
}

#define RUNCHECK(x) RUNTIME_CHECK((x) == ISC_R_SUCCESS)

#define PORT 5300
#define TIMEOUT 30

static isc_mem_t *mctx;
static dns_requestmgr_t *requestmgr;
isc_sockaddr_t address;
static int onfly;

static void
recvresponse(isc_task_t *task, isc_event_t *event) {
	dns_requestevent_t *reqev = (dns_requestevent_t *)event;
	isc_result_t result;
	dns_message_t *query, *response;
	isc_buffer_t outbuf;
	char output[1024];

	UNUSED(task);

	REQUIRE(reqev != NULL);

	if (reqev->result != ISC_R_SUCCESS) {
		fprintf(stderr, "I:request event result: %s\n",
			isc_result_totext(reqev->result));
		exit(-1);
	}

	query = reqev->ev_arg;

	response = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &response);
	CHECK("dns_message_create", result);

	result = dns_request_getresponse(reqev->request, response,
					 DNS_MESSAGEPARSE_PRESERVEORDER);
	CHECK("dns_request_getresponse", result);

	if (response->rcode != dns_rcode_noerror) {
		result = ISC_RESULTCLASS_DNSRCODE + response->rcode;
		fprintf(stderr, "I:response rcode: %s\n",
			isc_result_totext(result));
			exit(-1);
	}
	if (response->counts[DNS_SECTION_ANSWER] != 1U) {
		fprintf(stderr, "I:response answer count (%u!=1)\n",
			response->counts[DNS_SECTION_ANSWER]);
	}

	isc_buffer_init(&outbuf, output, sizeof(output));
	result = dns_message_sectiontotext(response, DNS_SECTION_ANSWER,
					   &dns_master_style_simple,
					   DNS_MESSAGETEXTFLAG_NOCOMMENTS,
					   &outbuf);
	CHECK("dns_message_sectiontotext", result);
	printf("%.*s", (int)isc_buffer_usedlength(&outbuf),
	       (char *)isc_buffer_base(&outbuf));
	fflush(stdout);

	dns_message_destroy(&query);
	dns_message_destroy(&response);
	dns_request_destroy(&reqev->request);
	isc_event_free(&event);

	if (--onfly == 0)
		isc_app_shutdown();
	return;
}

static isc_result_t
sendquery(isc_task_t *task)
{
	dns_request_t *request;
	dns_message_t *message;
	dns_name_t *qname;
	dns_rdataset_t *qrdataset;
	isc_result_t result;
	dns_fixedname_t queryname;
	isc_buffer_t buf;
	static char host[256];
	int c;

	c = scanf("%255s", host);
	if (c == EOF)
		return ISC_R_NOMORE;

	onfly++;

	dns_fixedname_init(&queryname);
	isc_buffer_init(&buf, host, strlen(host));
	isc_buffer_add(&buf, strlen(host));
	result = dns_name_fromtext(dns_fixedname_name(&queryname), &buf,
				   dns_rootname, 0, NULL);
	CHECK("dns_name_fromtext", result);

	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &message);
	CHECK("dns_message_create", result);

	message->opcode = dns_opcode_query;
	message->flags |= DNS_MESSAGEFLAG_RD;
	message->rdclass = dns_rdataclass_in;
	message->id = (unsigned short)(random() & 0xFFFF);

	qname = NULL;
	result = dns_message_gettempname(message, &qname);
	CHECK("dns_message_gettempname", result);

	qrdataset = NULL;
	result = dns_message_gettemprdataset(message, &qrdataset);
	CHECK("dns_message_gettemprdataset", result);

	dns_name_init(qname, NULL);
	dns_name_clone(dns_fixedname_name(&queryname), qname);
	dns_rdataset_init(qrdataset);
	dns_rdataset_makequestion(qrdataset, dns_rdataclass_in,
				  dns_rdatatype_a);
	ISC_LIST_APPEND(qname->list, qrdataset, link);
	dns_message_addname(message, qname, DNS_SECTION_QUESTION);

	request = NULL;
	result = dns_request_create(requestmgr, message, &address,
				    DNS_REQUESTOPT_TCP, NULL,
				    TIMEOUT, task, recvresponse,
				    message, &request);
	CHECK("dns_request_create", result);

	return ISC_R_SUCCESS;
}

static void
sendqueries(isc_task_t *task, isc_event_t *event)
{
	isc_result_t result;

	isc_event_free(&event);

	do {
		result = sendquery(task);
	} while (result == ISC_R_SUCCESS);

	if (onfly == 0)
		isc_app_shutdown();
	return;
}

static void
connecting(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock = (isc_socket_t *)(event->ev_arg);

	RUNCHECK(isc_socket_connect(sock, &address, task, sendqueries, NULL));

	isc_event_free(&event);
}

int
main(int argc, char *argv[])
{
	isc_taskmgr_t *taskmgr;
	isc_timermgr_t *timermgr;
	isc_socketmgr_t *socketmgr;
	isc_socket_t *sock;
	unsigned int attrs, attrmask;
	isc_sockaddr_t bind_addr;
	dns_dispatchmgr_t *dispatchmgr;
	dns_dispatch_t *dispatchv4;
	dns_dispatch_t *tcpdispatch;
	dns_view_t *view;
	isc_entropy_t *ectx;
	isc_task_t *task;
	isc_log_t *lctx;
	isc_logconfig_t *lcfg;
	struct in_addr inaddr;
	isc_result_t result;

	UNUSED(argv);

	RUNCHECK(isc_app_start());

	dns_result_register();

	mctx = NULL;
	RUNCHECK(isc_mem_create(0, 0, &mctx));

	lctx = NULL;
	lcfg = NULL;
	RUNCHECK(isc_log_create(mctx, &lctx, &lcfg));

	ectx = NULL;
	RUNCHECK(isc_entropy_create(mctx, &ectx));
	RUNCHECK(isc_entropy_createfilesource(ectx, "../random.data"));
	RUNCHECK(isc_hash_create(mctx, ectx, DNS_NAME_MAXWIRE));

	RUNCHECK(dst_lib_init(mctx, ectx, ISC_ENTROPY_GOODONLY));

	taskmgr = NULL;
	RUNCHECK(isc_taskmgr_create(mctx, 1, 0, &taskmgr));
	task = NULL;
	RUNCHECK(isc_task_create(taskmgr, 0, &task));
	timermgr = NULL;

	RUNCHECK(isc_timermgr_create(mctx, &timermgr));
	socketmgr = NULL;
	RUNCHECK(isc_socketmgr_create(mctx, &socketmgr));
	dispatchmgr = NULL;
	RUNCHECK(dns_dispatchmgr_create(mctx, ectx, &dispatchmgr));
	if (argc == 1) {
		isc_sockaddr_any(&bind_addr);
	} else {
		result = ISC_R_FAILURE;
		if (inet_pton(AF_INET, "10.53.0.7", &inaddr) != 1)
			CHECK("inet_pton", result);
		isc_sockaddr_fromin(&bind_addr, &inaddr, 0);
	}
	attrs = DNS_DISPATCHATTR_UDP |
		DNS_DISPATCHATTR_MAKEQUERY |
		DNS_DISPATCHATTR_IPV4;
	attrmask = DNS_DISPATCHATTR_UDP |
		   DNS_DISPATCHATTR_TCP |
		   DNS_DISPATCHATTR_IPV4 |
		   DNS_DISPATCHATTR_IPV6;
	dispatchv4 = NULL;
	RUNCHECK(dns_dispatch_getudp(dispatchmgr, socketmgr, taskmgr,
					  &bind_addr, 4096, 4, 2, 3, 5,
					  attrs, attrmask, &dispatchv4));
	requestmgr = NULL;
	RUNCHECK(dns_requestmgr_create(mctx, timermgr, socketmgr, taskmgr,
					    dispatchmgr, dispatchv4, NULL,
					    &requestmgr));

	view = NULL;
	RUNCHECK(dns_view_create(mctx, 0, "_test", &view));

	sock = NULL;
	RUNCHECK(isc_socket_create(socketmgr, PF_INET, isc_sockettype_tcp,
				   &sock));
	RUNCHECK(isc_socket_bind(sock, &bind_addr, 0));

	result = ISC_R_FAILURE;
	if (inet_pton(AF_INET, "10.53.0.4", &inaddr) != 1)
		CHECK("inet_pton", result);
	isc_sockaddr_fromin(&address, &inaddr, PORT);

	attrs = 0;
	attrs |= DNS_DISPATCHATTR_TCP;
	attrs |= DNS_DISPATCHATTR_IPV4;
	attrs |= DNS_DISPATCHATTR_MAKEQUERY;
	attrs |= DNS_DISPATCHATTR_CONNECTED;
	isc_socket_dscp(sock, -1);
	tcpdispatch = NULL;
	RUNCHECK(dns_dispatch_createtcp2(dispatchmgr, sock, taskmgr,
					 &bind_addr, &address,
					 4096, 20, 10, 3, 5,
					 attrs, &tcpdispatch));

	RUNCHECK(isc_app_onrun(mctx, task, connecting, sock));

	isc_socket_detach(&sock);

	(void)isc_app_run();

	dns_view_detach(&view);

	dns_requestmgr_shutdown(requestmgr);
	dns_requestmgr_detach(&requestmgr);

	dns_dispatch_detach(&dispatchv4);
	dns_dispatch_detach(&tcpdispatch);
	dns_dispatchmgr_destroy(&dispatchmgr);

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	isc_task_shutdown(task);
	isc_task_detach(&task);
	isc_taskmgr_destroy(&taskmgr);

	dst_lib_destroy();
	isc_hash_destroy();
	isc_entropy_detach(&ectx);

	isc_log_destroy(&lctx);

	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}

