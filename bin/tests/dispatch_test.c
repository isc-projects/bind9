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
#include <dns/name.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/result.h>

#define NCLIENTS	16

typedef struct {
	unsigned int client_number;
	int count;
	dns_dispentry_t *resp;
	isc_buffer_t render;
	unsigned char render_buffer[1024];
} clictx_t;

isc_mem_t *mctx;
isc_taskmgr_t *taskmgr;
isc_socketmgr_t *socketmgr;
dns_dispatchmgr_t *dispatchmgr;
dns_dispatch_t *disp;
isc_task_t *t0;
clictx_t clients[NCLIENTS];  /* Lots of things might want to use this. */
unsigned int client_count = 0;
isc_mutex_t client_lock;

/*
 * Forward declarations.
 */
void
got_response(isc_task_t *, isc_event_t *);

static isc_result_t
printmsg(dns_message_t *msg, FILE *out) {
	unsigned char text[8192];
	isc_buffer_t textbuf;
	int result;

	isc_buffer_init(&textbuf, text, sizeof text);
	result = dns_message_totext(msg, 0, &textbuf);

	if (result != ISC_R_SUCCESS)
		return (result);

	fprintf(out, "msg:\n%*s\n",
		isc_buffer_usedlength(&textbuf),
		(char *)isc_buffer_base(&textbuf));

	return (ISC_R_SUCCESS);
}

static void
hex_dump(isc_buffer_t *b) {
	unsigned int len;
	isc_region_t r;

	isc_buffer_remainingregion(b, &r);

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
CHECKRESULT(isc_result_t result, const char *msg) {
	if (result != ISC_R_SUCCESS) {
		printf("%s: %s\n", msg, isc_result_totext(result));

		exit(1);
	}
}

static void
send_done(isc_task_t *task, isc_event_t *ev_in) {
	isc_socketevent_t *ev = (isc_socketevent_t *)ev_in;
	clictx_t *cli = (clictx_t *)ev_in->ev_arg;

	(void)task;

	if (ev->result == ISC_R_SUCCESS) {
		printf("Send done (SUCCESS)\n");
		isc_event_free(&ev_in);
		return;
	}

	CHECKRESULT(ev->result, "send_done got event");

	isc_event_free(&ev_in);

	printf("--- removing response (FAILURE)\n");
	dns_dispatch_removeresponse(&cli->resp, NULL);
	isc_app_shutdown();
}

static void
start_response(clictx_t *cli, const char *query, isc_task_t *task) {
	dns_messageid_t id;
	isc_sockaddr_t from;
	dns_message_t *msg;
	isc_result_t result;
	dns_name_t *name;
	unsigned char namebuf[255];
	isc_buffer_t target;
	isc_buffer_t source;
	isc_region_t region;
	dns_rdataset_t *rdataset;
	dns_rdatalist_t *rdatalist;

	isc_buffer_init(&source, query, strlen(query));
	isc_buffer_add(&source, strlen(query));
	isc_buffer_setactive(&source, strlen(query));
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

	rdataset = NULL;
	result = dns_message_gettemprdataset(msg, &rdataset);
	CHECKRESULT(result, "dns_message_gettemprdataset()");

	rdatalist = NULL;
	result = dns_message_gettemprdatalist(msg, &rdatalist);
	CHECKRESULT(result, "dns_message_gettemprdatalist()");

	dns_rdatalist_init(rdatalist);
	rdatalist->rdclass = dns_rdataclass_in;
	rdatalist->type = dns_rdatatype_a;
	rdatalist->ttl = 0;
	ISC_LIST_INIT(rdatalist->rdata);

	dns_rdataset_init(rdataset);
	result = dns_rdatalist_tordataset(rdatalist, rdataset);
	CHECKRESULT(result, "dns_rdatalist_tordataset()");
	rdataset->attributes |= DNS_RDATASETATTR_QUESTION;

	ISC_LIST_APPEND(name->list, rdataset, link);
	rdataset = NULL;
	rdatalist = NULL;

	result = printmsg(msg, stderr);
	CHECKRESULT(result, "printmsg() failed");

	isc_buffer_init(&cli->render, cli->render_buffer,
			sizeof(cli->render_buffer));
	result = dns_message_renderbegin(msg, &cli->render);
	CHECKRESULT(result, "dns_message_renderbegin()");

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

	isc_buffer_usedregion(&cli->render, &region);
	result = isc_socket_sendto(dns_dispatch_getsocket(disp), &region,
				   task, send_done, cli->resp, &from, NULL);
	CHECKRESULT(result, "isc_socket_sendto()");
}

void
got_response(isc_task_t *task, isc_event_t *ev_in) {
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	dns_dispentry_t *resp = ev->ev_sender;
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
		dns_dispatch_removeresponse(&resp, &ev);
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

	result = printmsg(msg, stderr);
	CHECKRESULT(result, "printmsg() failed");

	dns_message_destroy(&msg);

	printf("--- shutting down dispatcher\n");
	dns_dispatch_cancel(disp);
	printf("--- removing response\n");
	dns_dispatch_removeresponse(&resp, &ev);
	RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
	INSIST(client_count > 0);
	client_count--;
	cnt = client_count;
	RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);
	if (cnt == 0)
		isc_app_shutdown();
}

static void
got_request(isc_task_t *task, isc_event_t *ev_in) {
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	clictx_t *cli = (clictx_t *)ev_in->ev_arg;
	dns_message_t *msg;
	isc_result_t result;
	unsigned int cnt;

	printf("App:  Got request.  Result: %s\n",
	       isc_result_totext(ev->result));

	if (ev->result != ISC_R_SUCCESS) {
		RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);
		printf("Got error, terminating CLIENT %p resp %p\n",
		       cli, cli->resp);
		dns_dispatch_removerequest(&cli->resp, &ev);
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

	result = printmsg(msg, stderr);
	CHECKRESULT(result, "printmsg() failed");

	dns_message_destroy(&msg);

	cli->count++;
	printf("App:  Client %p(%u) ready, count == %d.\n",
	       cli, cli->client_number, cli->count);
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
		dns_dispatch_removerequest(&cli->resp, &ev);
		printf("--- adding request\n");
		RUNTIME_CHECK(dns_dispatch_addrequest(disp, task, got_request,
						      cli, &cli->resp)
			      == ISC_R_SUCCESS);
		break;

	default:
		dns_dispatch_freeevent(disp, cli->resp, &ev);
		break;
	}
}

int
main(int argc, char *argv[]) {
	isc_sockaddr_t sa;
	unsigned int i;
	unsigned int attrs;
	isc_log_t *log;
	isc_logconfig_t *lcfg;
	isc_logdestination_t destination;
	isc_result_t result;

	UNUSED(argc);
	UNUSED(argv);

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	dns_result_register();

	log = NULL;
	lcfg = NULL;
	RUNTIME_CHECK(isc_log_create(mctx, &log, &lcfg) == ISC_R_SUCCESS);
	isc_log_setcontext(log);
	dns_log_init(log);
	dns_log_setcontext(log);
	
	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	result = isc_log_createchannel(lcfg, "_default",
				       ISC_LOG_TOFILEDESC,
				       ISC_LOG_DYNAMIC,
				       &destination, ISC_LOG_PRINTTIME);
	INSIST(result == ISC_R_SUCCESS);
	result = isc_log_usechannel(lcfg, "_default", NULL, NULL);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * The task manager is independent (other than memory context).
	 */
	taskmgr = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 5, 0, &taskmgr) ==
		      ISC_R_SUCCESS);

	isc_log_setdebuglevel(log, 99);

	t0 = NULL;
	RUNTIME_CHECK(isc_task_create(taskmgr, 0, &t0) == ISC_R_SUCCESS);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	dispatchmgr = NULL;
	RUNTIME_CHECK(dns_dispatchmgr_create(mctx, &dispatchmgr)
		      == ISC_R_SUCCESS);

	isc_sockaddr_any(&sa);
	isc_sockaddr_setport(&sa, 5356);

	/*
	 * Get or create a dispatch context.
	 */
	attrs = 0;
	attrs |= DNS_DISPATCHATTR_IPV4;
	attrs |= DNS_DISPATCHATTR_UDP;
	
	disp = NULL;
	RUNTIME_CHECK(dns_dispatch_getudp(dispatchmgr, socketmgr,
					  taskmgr, &sa, 512, 6, 1024,
					  17, 19, attrs, attrs, &disp)
		      == ISC_R_SUCCESS);
	INSIST(disp != NULL);

	RUNTIME_CHECK(isc_mutex_init(&client_lock) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_lock(&client_lock) == ISC_R_SUCCESS);

	memset(clients, 0, sizeof (clients));
	for (i = 0 ; i < NCLIENTS ; i++)
		clients[i].client_number = i;

	for (i = 0 ; i < 2 ; i++) {
		clients[i].count = 0;
		clients[i].resp = NULL;
		RUNTIME_CHECK(dns_dispatch_addrequest(disp, t0, got_request,
						      &clients[i],
						      &clients[i].resp)
			      == ISC_R_SUCCESS);
		INSIST(clients[i].resp != NULL);
		fprintf(stderr, "Started client %i via addrequest\n", i);
		client_count++;
	}
	RUNTIME_CHECK(isc_mutex_unlock(&client_lock) == ISC_R_SUCCESS);

	isc_mem_stats(mctx, stderr);

	isc_app_run();

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

	isc_log_destroy(&log);
	sleep(2);

	isc_mem_stats(mctx, stderr);
	fflush(stderr);
	isc_mem_detach(&mctx);

	return (0);
}
