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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>

#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/net.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>

#include <dns/dispatch.h>
#include <dns/message.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>

#include "printmsg.h"

typedef struct {
	int count;
	isc_buffer_t render;
	unsigned char render_buffer[1024];
	dns_rdataset_t rdataset;
	dns_rdatalist_t rdatalist;
	dns_dispentry_t *resp;
} clictx_t;

isc_mem_t *mctx;
isc_taskmgr_t *manager;
isc_socketmgr_t *socketmgr;
dns_dispatch_t *disp;
isc_task_t *t0, *t1, *t2;
clictx_t clients[16];  /* lots of things might want to use this */
unsigned int client_count = 0;
isc_mutex_t client_lock;

void got_request(isc_task_t *, isc_event_t *);
void got_response(isc_task_t *, isc_event_t *);
void start_response(clictx_t *, char *, isc_task_t *);
static inline void CHECKRESULT(isc_result_t, char *);
void send_done(isc_task_t *, isc_event_t *);
void hex_dump(isc_buffer_t *);

void
hex_dump(isc_buffer_t *b)
{
	unsigned int len;
	isc_region_t r;

	isc_buffer_remaining(b, &r);

	printf("Buffer %p:  used region base %p, length %d",
	       b, r.base, r.length);
	for (len = 0 ; len < r.length ; len++) {
		if (len % 16 == 0)
			printf("\n");
		printf("%02x ", r.base[len]);
	}
	printf("\n");
}

static inline void
CHECKRESULT(isc_result_t result, char *msg)
{
	if (result != DNS_R_SUCCESS) {
		printf("%s: %s\n", msg, isc_result_totext(result));

		exit(1);
	}
}

void
send_done(isc_task_t *task, isc_event_t *ev_in)
{
	isc_socketevent_t *ev = (isc_socketevent_t *)ev_in;
	clictx_t *cli = (clictx_t *)ev_in->arg;

	(void)task;

	if (ev->result == ISC_R_SUCCESS) {
		printf("Send done (SUCCESS)\n");
		isc_event_free(&ev_in);
		return;
	}

	CHECKRESULT(ev->result, "send_done got event");

	isc_event_free(&ev_in);

	printf("--- removing response (FAILURE)\n");
	dns_dispatch_removeresponse(disp, &cli->resp, NULL);
	isc_app_shutdown();
}


void
start_response(clictx_t *cli, char *query, isc_task_t *task)
{
	dns_messageid_t id;
	isc_sockaddr_t from;
	dns_message_t *msg;
	isc_result_t result;
	dns_name_t *name;
	unsigned char namebuf[255];
	isc_buffer_t target;
	isc_buffer_t source;
	isc_region_t region;

	isc_buffer_init(&source, query, strlen(query), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, strlen(query));
	isc_buffer_setactive(&source, strlen(query));
	isc_buffer_init(&target, namebuf, sizeof(namebuf),
			ISC_BUFFERTYPE_BINARY);

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

	cli->rdatalist.rdclass = dns_rdataclass_in;
	cli->rdatalist.type = dns_rdatatype_a;
	cli->rdatalist.ttl = 0;
	ISC_LIST_INIT(cli->rdatalist.rdata);

	dns_rdataset_init(&cli->rdataset);
	result = dns_rdatalist_tordataset(&cli->rdatalist, &cli->rdataset);
	CHECKRESULT(result, "dns_rdatalist_tordataset()");

	ISC_LIST_APPEND(name->list, &cli->rdataset, link);

	result = printmessage(msg);
	CHECKRESULT(result, "printmessage()");

	isc_buffer_init(&cli->render, cli->render_buffer,
			sizeof(cli->render_buffer), ISC_BUFFERTYPE_BINARY);
	result = dns_message_renderbegin(msg, &cli->render);
	CHECKRESULT(result, "dns_message_renderbegin()");

	cli->rdataset.attributes |= DNS_RDATASETATTR_QUESTION;

	result = dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0);
	CHECKRESULT(result, "dns_message_rendersection(QUESTION)");

	result = dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0);
	CHECKRESULT(result, "dns_message_rendersection(ANSWER)");

	result = dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0);
	CHECKRESULT(result, "dns_message_rendersection(ADDITIONAL)");

	result = dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0);
	CHECKRESULT(result, "dns_message_rendersection(AUTHORITY)");

	printf("--- adding response\n");
	RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
	client_count++;
	RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);
	cli->resp = NULL;
	result = dns_dispatch_addresponse(disp, &from, task, got_response,
					  cli, &id, &cli->resp);
	CHECKRESULT(result, "dns_dispatch_addresponse");

	printf("Assigned MessageID %d\n", id);

	msg->opcode = dns_opcode_query;
	msg->rcode = dns_rcode_noerror;
	msg->flags = DNS_MESSAGEFLAG_RD;
	msg->id = id;

	result = dns_message_renderend(msg);
	CHECKRESULT(result, "dns_message_renderend");

	dns_message_destroy(&msg);

	isc_buffer_used(&cli->render, &region);
	result = isc_socket_sendto(dns_dispatch_getsocket(disp), &region,
				   task, send_done, cli->resp, &from, NULL);
	CHECKRESULT(result, "isc_socket_sendto()");
}

void
got_response(isc_task_t *task, isc_event_t *ev_in)
{
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	dns_dispentry_t *resp = ev->sender;
	dns_message_t *msg;
	isc_result_t result;
	unsigned int cnt;

	(void)task;

	printf("App:  Got response (id %d).  Result: %s\n",
	       ev->id, isc_result_totext(ev->result));

	if (ev->result != ISC_R_SUCCESS) {
		printf("--- ERROR, shutting down response slot\n");
		printf("--- shutting down dispatcher\n");
		dns_dispatch_cancel(disp);
		printf("--- removing response\n");
		dns_dispatch_removeresponse(disp, &resp, &ev);
		RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
		INSIST(client_count > 0);
		client_count--;
		cnt = client_count;
		RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);
		if (cnt == 0)
			isc_app_shutdown();
		return;
	}

	msg = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	CHECKRESULT(result, "dns_message_create() failed");

	result = dns_message_parse(msg, &ev->buffer, ISC_FALSE);
	CHECKRESULT(result, "dns_message_parse() failed");

	result = printmessage(msg);
	CHECKRESULT(result, "printmessage() failed");

	dns_message_destroy(&msg);

	printf("--- shutting down dispatcher\n");
	dns_dispatch_cancel(disp);
	printf("--- removing response\n");
	dns_dispatch_removeresponse(disp, &resp, &ev);
	RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
	INSIST(client_count > 0);
	client_count--;
	cnt = client_count;
	RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);
	if (cnt == 0)
		isc_app_shutdown();
}

void
got_request(isc_task_t *task, isc_event_t *ev_in)
{
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	clictx_t *cli = (clictx_t *)ev_in->arg;
	dns_message_t *msg;
	isc_result_t result;
	unsigned int cnt;

	printf("App:  Got request.  Result: %s\n",
	       isc_result_totext(ev->result));

	if (ev->result != DNS_R_SUCCESS) {
		RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
		printf("Got error, terminating CLIENT %p resp %p\n",
		       cli, cli->resp);
		dns_dispatch_removerequest(disp, &cli->resp, &ev);
		INSIST(client_count > 0);
		client_count--;
		cnt = client_count;
		printf("CLIENT %p ENDING, %d remain\n", cli, client_count);
		RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);
		if (cnt == 0)
			isc_app_shutdown();
		return;
	}

	hex_dump(&ev->buffer);

	msg = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	CHECKRESULT(result, "dns_message_create() failed");

	result = dns_message_parse(msg, &ev->buffer, ISC_FALSE);
	CHECKRESULT(result, "dns_message_parse() failed");

	result = printmessage(msg);
	CHECKRESULT(result, "printmessage() failed");

	dns_message_destroy(&msg);

	sleep (1);
	cli->count++;
	printf("App:  Client %p ready, count == %d.\n", cli, cli->count);
	switch (cli->count) {
	case 4:
		printf("--- starting DNS lookup\n");
		dns_dispatch_freeevent(disp, cli->resp, &ev);
		start_response(&clients[3], "flame.org", task);
		start_response(&clients[4], "vix.com", task);
		start_response(&clients[5], "isc.org", task);
		break;
		
	case 2:
		printf("--- removing request\n");
		dns_dispatch_removerequest(disp, &cli->resp, &ev);
		printf("--- adding request\n");
		RUNTIME_CHECK(dns_dispatch_addrequest(disp, task, got_request,
						      cli, &cli->resp)
			      == DNS_R_SUCCESS);
		break;

	default:
		dns_dispatch_freeevent(disp, cli->resp, &ev);
		break;
	}
}

int
main(int argc, char *argv[])
{
	isc_socket_t *s0;
	isc_sockaddr_t sockaddr;
	unsigned int i;

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
	manager = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 5, 0, &manager) ==
		      ISC_R_SUCCESS);

	t0 = NULL;
	RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &t0) == ISC_R_SUCCESS);
	t1 = NULL;
	RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &t1) == ISC_R_SUCCESS);
	t2 = NULL;
	RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &t2) == ISC_R_SUCCESS);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	/*
	 * Open up a random socket.  Who cares where.
	 */
	s0 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = htons(5555);
	sockaddr.length = sizeof (struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, PF_INET,
					isc_sockettype_udp, &s0) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(s0, &sockaddr) == ISC_R_SUCCESS);

	/*
	 * Create a dispatch context
	 */
	disp = NULL;
	RUNTIME_CHECK(dns_dispatch_create(mctx, s0, t0, 512, 6, 1024,
					 17, 19, NULL, &disp)
		      == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_mutex_init(&client_lock) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
	for (i = 0 ; i < 2 ; i++) {
		clients[i].count = 0;
		clients[i].resp = NULL;
		RUNTIME_CHECK(dns_dispatch_addrequest(disp, t1, got_request,
						      &clients[i],
						      &clients[i].resp)
			      == ISC_R_SUCCESS);
		client_count++;
	}
	RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);

	isc_app_run();

	fprintf(stderr, "canceling dispatcher\n");
	dns_dispatch_cancel(disp);

	fprintf(stderr, "detaching from socket\n");
	isc_socket_detach(&s0);

	fprintf(stderr, "detaching from dispatcher\n");
	dns_dispatch_detach(&disp);

	fprintf(stderr, "Destroying socket manager\n");
	isc_socketmgr_destroy(&socketmgr);

	isc_task_shutdown(t0);
	isc_task_detach(&t0);
	isc_task_shutdown(t1);
	isc_task_detach(&t1);
	isc_task_shutdown(t2);
	isc_task_detach(&t2);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stderr);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
