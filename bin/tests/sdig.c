/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>		/* XXXRTH */
extern int h_errno;

#include <isc/types.h>
#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/socket.h>
#include <isc/task.h>

#include <dns/types.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdataset.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/result.h>

#include "printmsg.h"

static dns_message_t *message = NULL;
static isc_boolean_t have_ipv6 = ISC_FALSE;

static void
fatal(char *format, ...) {
	va_list args;

	va_start(args, format);	
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

static inline void
check_result(isc_result_t result, char *msg) {
	if (result != ISC_R_SUCCESS)
		fatal("%s: %s", msg, isc_result_totext(result));
}

static void
usage() {
	fprintf(stderr,
		"usage: sdig [@server] [-p port] [+vc] name [type] [class]\n");
	exit(1);
}

static void
add_type(dns_message_t *message, dns_name_t *name, dns_rdataclass_t rdclass,
	 dns_rdatatype_t rdtype)
{
	dns_rdataset_t *rdataset;
	isc_result_t result;

	rdataset = NULL;
	result = dns_message_gettemprdataset(message, &rdataset);
	check_result(result, "dns_message_gettemprdataset()");
	dns_rdataset_init(rdataset);
	dns_rdataset_makequestion(rdataset, rdclass, rdtype);
	ISC_LIST_APPEND(name->list, rdataset, link);
}

static void
hex_dump(isc_buffer_t *b)
{
	unsigned int len;
	isc_region_t r;

	isc_buffer_remaining(b, &r);

	for (len = 0 ; len < r.length ; len++) {
		printf("%02x ", r.base[len]);
		if (len != 0 && len % 16 == 0)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");
}

static void
get_address(char *hostname, unsigned int port, isc_sockaddr_t *sockaddr) {
	struct in_addr in4;
	struct in6_addr in6;
	struct hostent *he;

	if (have_ipv6 && inet_pton(AF_INET6, hostname, &in6) == 1)
		isc_sockaddr_fromin6(sockaddr, &in6, port);
	else if (inet_pton(AF_INET, hostname, &in4) == 1)
		isc_sockaddr_fromin(sockaddr, &in4, port);
	else {
		he = gethostbyname(hostname);
		if (he == NULL)
			fatal("gethostbyname() failed, h_errno = %d",
			      h_errno);
		INSIST(he->h_addrtype == AF_INET);
		isc_sockaddr_fromin(sockaddr,
				    (struct in_addr *)(he->h_addr_list[0]),
				    port);
	}
}

static void
recv_done(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent;
	isc_buffer_t b;
	isc_result_t result;

	REQUIRE(event->type == ISC_SOCKEVENT_RECVDONE);
	sevent = (isc_socketevent_t *)event;

	(void)task;

	if (sevent->result == ISC_R_SUCCESS) {
		isc_buffer_init(&b, sevent->region.base, sevent->n,
				ISC_BUFFERTYPE_BINARY);
		isc_buffer_add(&b, sevent->n);
		dns_message_reset(message, DNS_MESSAGE_INTENTPARSE);
		result = dns_message_parse(message, &b, ISC_FALSE);
		if (result != ISC_R_SUCCESS)
			hex_dump(&b);
		check_result(result, "dns_message_parse()");
		result = printmessage(message);
		check_result(result, "printmessage()");
	} else if (sevent->result != ISC_R_CANCELED)
		fatal("recv_done(): %s", isc_result_totext(sevent->result));
	
	isc_event_free(&event);
	isc_app_shutdown();
}

static void
send_done(isc_task_t *task, isc_event_t *event) {
	(void)task;
	isc_event_free(&event);
}

int
main(int argc, char *argv[]) {
	char *server;
	unsigned int port;
	isc_boolean_t vc, have_name, have_type;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass, nclass;
	size_t len;
	isc_buffer_t b, b2;
	isc_result_t result;
	isc_region_t r;
	isc_textregion_t tr;
	isc_mem_t *mctx;
	isc_taskmgr_t *taskmgr;
	isc_task_t *task;
	isc_socketmgr_t *socketmgr;
	isc_socket_t *sock;
	unsigned char *data[512];
	unsigned char *data2[512];
	isc_sockaddr_t sockaddr;
	int i;

	/*
	 * Initialize.
	 */

	result = isc_app_start();
	check_result(result, "isc_app_start()");

	dns_result_register();

	RUNTIME_CHECK(isc_net_probeipv4() == ISC_R_SUCCESS);
	if (isc_net_probeipv6() == ISC_R_SUCCESS)
		have_ipv6 = ISC_TRUE;

	mctx = NULL;
	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create()");
	taskmgr = NULL;
	result = isc_taskmgr_create(mctx, 1, 0, &taskmgr);
	check_result(result, "isc_taskmgr_create()");
	task = NULL;
	result = isc_task_create(taskmgr, NULL, 0, &task);
	check_result(result, "isc_task_create()");
	socketmgr = NULL;
	result = isc_socketmgr_create(mctx, &socketmgr);
	check_result(result, "isc_socketmgr_create()");
	sock = NULL;

	server = "localhost";
	port = 5544;
	vc = ISC_FALSE;
	have_name = ISC_FALSE;
	have_type = ISC_FALSE;
	rdclass = dns_rdataclass_in;

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);
	message = NULL;
	result = dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &message);
	check_result(result, "dns_message_create()");

	printf("\n; <<>> sdig <<>>");
	for (i = 1; i < argc; i++) {
		printf(" %s", argv[i]);
	}
	printf("\n");
	for (argc--, argv++; argc > 0; argc--, argv++) {
		if (strncmp(argv[0], "@", 1) == 0) {
			server = &argv[0][1];
		} else if (strcmp(argv[0], "-p") == 0) {
			if (argc < 2)
				usage();
			port = atoi(argv[1]);
			argv++;
			argc--;
		} else if (strcmp(argv[0], "+vc") == 0) {
			fatal("TCP transport not yet implemented");
		} else {
			len = strlen(argv[0]);
			tr.base = argv[0];
			tr.length = len;
			if (!have_name) {
				isc_buffer_init(&b, argv[0], len,
						ISC_BUFFERTYPE_TEXT);
				isc_buffer_add(&b, len);
				result = dns_name_fromtext(name, &b,
							   dns_rootname,
							   ISC_FALSE,
							   NULL);
				check_result(result, "dns_name_fromtext()");
				have_name = ISC_TRUE;
			} else {
				if (dns_rdatatype_fromtext(&rdtype, &tr) ==
				    ISC_R_SUCCESS) {
					add_type(message, name, rdclass,
						 rdtype);
					have_type = ISC_TRUE;
				} else {
					if (dns_rdataclass_fromtext(&nclass,
								    &tr) !=
					    ISC_R_SUCCESS)
						fatal("unknown class "
						      "or type %s", argv[0]);
					rdclass = nclass;
				}
			}
		}
	}
	if (!have_name)
		usage();
	if (!have_type)
		add_type(message, name, dns_rdataclass_in, dns_rdatatype_a);

	message->id = 1;
	message->opcode = dns_opcode_query;
	message->flags |= DNS_MESSAGEFLAG_RD;
	dns_message_addname(message, name, DNS_SECTION_QUESTION);

	isc_buffer_init(&b, data, sizeof data, ISC_BUFFERTYPE_BINARY);
	result = dns_message_renderbegin(message, &b);
	check_result(result, "dns_message_renderbegin()");
	result = dns_message_rendersection(message, DNS_SECTION_QUESTION,
					   0, 0);
	check_result(result, "dns_message_rendersection()");
	result = dns_message_renderend(message);
	check_result(result, "dns_message_renderend()");

	get_address(server, port, &sockaddr);

	result = isc_socket_create(socketmgr, isc_sockaddr_pf(&sockaddr),
				   isc_sockettype_udp, &sock);
	check_result(result, "isc_socket_create()");

	isc_buffer_init(&b2, data2, sizeof data2, ISC_BUFFERTYPE_BINARY);
	isc_buffer_available(&b2, &r);
	result = isc_socket_recv(sock, &r, 1, task, recv_done, NULL);
	check_result(result, "isc_socket_recv()");
	isc_buffer_used(&b, &r);
	result = isc_socket_sendto(sock, &r, task, send_done, NULL, &sockaddr);
	check_result(result, "isc_socket_sendto()");

	isc_app_run();

	dns_message_destroy(&message);
	isc_socket_cancel(sock, task, ISC_SOCKCANCEL_ALL);
	isc_task_detach(&task);
	isc_socket_detach(&sock);
	isc_taskmgr_destroy(&taskmgr);
	isc_socketmgr_destroy(&socketmgr);
	isc_mem_destroy(&mctx);

	isc_app_finish();
	
	return (0);
}
