/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#include <config.h>

#include <stdlib.h>
#include <unistd.h>

#include <isc/app.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/result.h>

isc_mem_t *mctx;
isc_taskmgr_t *taskmgr;
isc_socketmgr_t *socketmgr;
dns_dispatchmgr_t *dispatchmgr;
dns_dispatch_t *disp;
isc_task_t *t0;
isc_buffer_t render;
unsigned char render_buffer[1024];
dns_rdataset_t rdataset;
dns_rdatalist_t rdatalist;

void my_accept(isc_task_t *, isc_event_t *);
void got_request(isc_task_t *, isc_event_t *);
void got_response(isc_task_t *, isc_event_t *);
void start_response(void);
static inline void CHECKRESULT(isc_result_t, char *);
void send_done(isc_task_t *, isc_event_t *);
void hex_dump(isc_buffer_t *);

static isc_result_t
printmsg(dns_message_t *msg, FILE *out) {
	unsigned char text[8192];
	isc_buffer_t textbuf;
	int result;

	isc_buffer_init(&textbuf, text, sizeof text);
	result = dns_message_totext(msg, ISC_TRUE, ISC_TRUE,
				    ISC_FALSE, &textbuf);

	if (result != ISC_R_SUCCESS)
		return (result);

	fprintf(out, "msg:\n%*s\n",
		isc_buffer_usedlength(&textbuf),
		isc_buffer_base(&textbuf));

	return (ISC_R_SUCCESS);
}

void
hex_dump(isc_buffer_t *b) {
	unsigned int len;
	isc_region_t r;

	isc_buffer_remainingregion(b, &r);

	printf("Buffer %p (%p, %d):  used region base %p, length %d",
	       b, b->base, b->length, r.base, r.length);
	for (len = 0 ; len < r.length ; len++) {
		if (len % 16 == 0)
			printf("\n");
		printf("%02x ", r.base[len]);
	}
	printf("\n");
}

static inline void
CHECKRESULT(isc_result_t result, char *msg) {
	if (result != ISC_R_SUCCESS) {
		printf("%s: %s\n", msg, isc_result_totext(result));

		exit(1);
	}
}

void
my_accept(isc_task_t *task, isc_event_t *ev_in) {
	isc_socket_newconnev_t *ev = (isc_socket_newconnev_t *)ev_in;
	dns_dispentry_t *resp;
	unsigned int attrs;

	if (ev->result != ISC_R_SUCCESS) {
		isc_event_free(&ev_in);
		isc_app_shutdown();
	}

	/*
	 * Create a dispatch context
	 */
	attrs = 0;
	attrs |= DNS_DISPATCHATTR_IPV4;
	attrs |= DNS_DISPATCHATTR_TCP;
	disp = NULL;
	RUNTIME_CHECK(dns_dispatch_createtcp(dispatchmgr, ev->newsocket,
					     taskmgr, 4096, 64, 1024,
					     17, 19, attrs, &disp)
		      == ISC_R_SUCCESS);

	resp = NULL;
	RUNTIME_CHECK(dns_dispatch_addrequest(disp, task, got_request, NULL,
					      &resp)
		      == ISC_R_SUCCESS);

	isc_socket_detach(&ev->newsocket);

	isc_event_free(&ev_in);
}

void
send_done(isc_task_t *task, isc_event_t *ev_in) {
	isc_socketevent_t *ev = (isc_socketevent_t *)ev_in;
	dns_dispentry_t *resp = (dns_dispentry_t *)ev_in->ev_arg;

	(void)task;

	if (ev->result == ISC_R_SUCCESS) {
		printf("Send done (SUCCESS)\n");
		isc_event_free(&ev_in);
		return;
	}

	CHECKRESULT(ev->result, "send_done got event");

	isc_event_free(&ev_in);

	printf("--- removing response (FAILURE)\n");
	dns_dispatch_removeresponse(&resp, NULL);
	isc_app_shutdown();
}

void
start_response(void) {
	dns_dispentry_t *resp;
	dns_messageid_t id;
	isc_sockaddr_t from;
	dns_message_t *msg;
	isc_result_t result;
	dns_name_t *name;
	unsigned char namebuf[255];
	isc_buffer_t target;
	isc_buffer_t source;
	isc_region_t region;

#define QUESTION "flame.org."

	isc_buffer_init(&source, QUESTION, strlen(QUESTION));
	isc_buffer_add(&source, strlen(QUESTION));
	isc_buffer_setactive(&source, strlen(QUESTION));
	isc_buffer_init(&target, namebuf, sizeof(namebuf));

	memset(&from, 0, sizeof(from));
	from.length = sizeof(struct sockaddr_in);
#ifdef ISC_PLATFORM_HAVESALEN
	from.type.sa.sa_len = sizeof(struct sockaddr_in);
#endif
	from.type.sin.sin_port = htons(53);
	from.type.sa.sa_family = AF_INET;
	RUNTIME_CHECK(inet_aton("204.152.184.97",
				&from.type.sin.sin_addr) == 1);

	msg = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &msg);
	CHECKRESULT(result, "dns_message_create()");

	name = NULL;
	result = dns_message_gettempname(msg, &name);
	CHECKRESULT(result, "dns_message_gettempname()");

	dns_name_init(name, NULL);
	result = dns_name_fromtext(name, &source, dns_rootname, ISC_FALSE,
				   &target);
	CHECKRESULT(result, "dns_name_fromtext()");

	dns_message_addname(msg, name, DNS_SECTION_QUESTION);

	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 0;
	ISC_LIST_INIT(rdatalist.rdata);

	dns_rdataset_init(&rdataset);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	CHECKRESULT(result, "dns_rdatalist_tordataset()");

	ISC_LIST_APPEND(name->list, &rdataset, link);

	result = printmsg(msg, stderr);
	CHECKRESULT(result, "printmsg()");

	isc_buffer_init(&render, render_buffer, sizeof(render_buffer));
	result = dns_message_renderbegin(msg, &render);
	CHECKRESULT(result, "dns_message_renderbegin()");

	rdataset.attributes |= DNS_RDATASETATTR_QUESTION;

	result = dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0);
	CHECKRESULT(result, "dns_message_rendersection(QUESTION)");

	result = dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0);
	CHECKRESULT(result, "dns_message_rendersection(ANSWER)");

	result = dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0);
	CHECKRESULT(result, "dns_message_rendersection(ADDITIONAL)");

	result = dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0);
	CHECKRESULT(result, "dns_message_rendersection(AUTHORITY)");

	printf("--- adding response\n");
	resp = NULL;
	result = dns_dispatch_addresponse(disp, &from, t0, got_response, NULL,
					  &id, &resp);
	CHECKRESULT(result, "dns_dispatch_addresponse");

	printf("Assigned MessageID %d\n", id);

	msg->opcode = dns_opcode_query;
	msg->rcode = dns_rcode_noerror;
	msg->flags = DNS_MESSAGEFLAG_RD;
	msg->id = id;

	result = dns_message_renderend(msg);
	CHECKRESULT(result, "dns_message_renderend");

	dns_message_destroy(&msg);

	isc_buffer_usedregion(&render, &region);
	result = isc_socket_send(dns_dispatch_getsocket(disp), &region,
				 t0, send_done, resp);
	CHECKRESULT(result, "isc_socket_send()");
}

void
got_response(isc_task_t *task, isc_event_t *ev_in) {
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	dns_dispentry_t *resp = ev->ev_sender;
	dns_message_t *msg;
	isc_result_t result;

	(void)task;

	printf("App:  Got response (id %d).  Result: %s\n",
	       ev->id, isc_result_totext(ev->result));

	msg = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	CHECKRESULT(result, "dns_message_create() failed");

	result = dns_message_parse(msg, &ev->buffer, ISC_FALSE);
	CHECKRESULT(result, "dns_message_parse() failed");

	result = printmsg(msg, stderr);
	CHECKRESULT(result, "printmsg() failed");

	dns_message_destroy(&msg);

	printf("--- removing response\n");
	dns_dispatch_removeresponse(&resp, &ev);

	isc_app_shutdown();
}

void
got_request(isc_task_t *task, isc_event_t *ev_in) {
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	dns_dispentry_t *resp = ev->ev_sender;
	static int cnt = 0;
	dns_message_t *msg;
	isc_result_t result;

	printf("App:  Got request.  Result: %s\n",
	       isc_result_totext(ev->result));

	if (ev->result != ISC_R_SUCCESS) {
		printf("Got error, terminating application\n");
		dns_dispatch_removerequest(&resp, &ev);
		dns_dispatch_detach(&disp);
		isc_app_shutdown();
		return;
	}

	hex_dump(&ev->buffer);

	msg = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	CHECKRESULT(result, "dns_message_create() failed");

	result = dns_message_parse(msg, &ev->buffer, ISC_FALSE);
	CHECKRESULT(result, "dns_message_parse() failed");

	result = printmsg(msg, stderr);
	CHECKRESULT(result, "printmsg() failed");

	dns_message_destroy(&msg);

	sleep (1);
	printf("App:  Ready.\n");

	cnt++;
	switch (cnt) {
	case 6:
		printf("--- removing request\n");
		dns_dispatch_removerequest(&resp, &ev);
		dns_dispatch_detach(&disp);
		isc_app_shutdown();
		break;
		
	case 3:
		printf("--- removing request\n");
		dns_dispatch_removerequest(&resp, &ev);
		printf("--- adding request\n");
		RUNTIME_CHECK(dns_dispatch_addrequest(disp, task, got_request,
						      NULL, &resp)
			      == ISC_R_SUCCESS);
		break;

	default:
		dns_dispatch_freeevent(disp, resp, &ev);
		break;
	}
}

int
main(int argc, char *argv[]) {
	isc_socket_t *s0;
	isc_sockaddr_t sockaddr;

	(void)argc;
	(void)argv;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	dns_result_register();

	/*
	 * The task manager is independent (other than memory context)
	 */
	taskmgr = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 5, 0, &taskmgr) ==
		      ISC_R_SUCCESS);

	t0 = NULL;
	RUNTIME_CHECK(isc_task_create(taskmgr, 0, &t0) == ISC_R_SUCCESS);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	dispatchmgr = NULL;
	RUNTIME_CHECK(dns_dispatchmgr_create(mctx, &dispatchmgr)
		      == ISC_R_SUCCESS);

	/*
	 * Open up a random socket.  Who cares where.
	 */
	s0 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = htons(5555);
	sockaddr.length = sizeof (struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, PF_INET,
					isc_sockettype_tcp, &s0) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(s0, &sockaddr) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_listen(s0, 0) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_accept(s0, t0, my_accept, NULL)
		      == ISC_R_SUCCESS);

	isc_app_run();

	isc_socket_detach(&s0);

	fprintf(stderr, "canceling dispatcher\n");
	isc_mem_stats(mctx, stderr);
	sleep(2);
	dns_dispatch_cancel(disp);

	INSIST(disp != NULL);
	fprintf(stderr, "detaching from dispatcher\n");
	isc_mem_stats(mctx, stderr);
	sleep(2);
	dns_dispatch_detach(&disp);

	fprintf(stderr, "destroying dispatch manager\n");
	isc_mem_stats(mctx, stderr);
	sleep(2);
	dns_dispatchmgr_destroy(&dispatchmgr);

	fprintf(stderr, "Destroying socket manager\n");
	isc_mem_stats(mctx, stderr);
	sleep(2);
	isc_socketmgr_destroy(&socketmgr);

	isc_task_shutdown(t0);
	isc_task_detach(&t0);

	fprintf(stderr, "Destroying task manager\n");
	isc_mem_stats(mctx, stderr);
	sleep(2);
	isc_taskmgr_destroy(&taskmgr);

	isc_app_finish();

#if 0
	isc_log_destroy(&log);
	sleep(2);
#endif

	isc_mem_stats(mctx, stderr);
	fflush(stderr);
	isc_mem_detach(&mctx);

	isc_app_finish();

	return (0);
}
