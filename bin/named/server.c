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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/compress.h>
#include <dns/db.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "confparser.h"
#include "udpclient.h"
#include "tcpclient.h"

isc_mem_t *mctx = NULL;
isc_boolean_t want_stats = ISC_FALSE;
dns_db_t *db;

/*
 * For debugging only... XXX
 */
void dump_packet(unsigned char *buf, u_int len);

static void
makename(isc_mem_t *mctx, char *text, dns_name_t *name, dns_name_t *origin) {
	char b[255];
	isc_buffer_t source, target;
	size_t len;
	isc_region_t r1, r2;
	dns_result_t result;

	if (origin == NULL)
		origin = dns_rootname;
	dns_name_init(name, NULL);
	len = strlen(text);
	isc_buffer_init(&source, text, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	isc_buffer_init(&target, b, sizeof b, ISC_BUFFERTYPE_BINARY);
	result = dns_name_fromtext(name, &source, origin, ISC_FALSE, &target);
	RUNTIME_CHECK(result == DNS_R_SUCCESS);
	dns_name_toregion(name, &r1);
	r2.base = isc_mem_get(mctx, r1.length);
	RUNTIME_CHECK(r2.base != NULL);
	r2.length = r1.length;
	memcpy(r2.base, r1.base, r1.length);
	dns_name_fromregion(name, &r2);
}

/*
 * XXX This will be in a .h file soon...
 */
dns_result_t
resolve_packet(dns_db_t *db, isc_buffer_t *source, isc_buffer_t *target);

/*
 * Process the wire format message given in r, and return a new packet to
 * transmit.
 *
 * Return of DNS_R_SUCCESS means r->base is a newly allocated region of
 * memory, and r->length is its length.  The actual for-transmit packet
 * begins at (r->length + reslen) to reserve (reslen) bytes at the front
 * of the packet for transmission specific details.
 */
static dns_result_t
dispatch(isc_mem_t *mctx, isc_region_t *rxr, unsigned int reslen)
{
	char t[5000];
	isc_buffer_t source;
	isc_buffer_t target;
	dns_result_t result;
	isc_region_t txr;

	dump_packet(rxr->base, rxr->length);

	/*
	 * Set up the temporary output buffer.
	 */
	isc_buffer_init(&target, t + reslen, sizeof(t) - reslen,
			ISC_BUFFERTYPE_BINARY);

	/*
	 * Set up the input buffer from the contents of the region passed
	 * to us.
	 */
	isc_buffer_init(&source, rxr->base, rxr->length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, rxr->length);

	result = resolve_packet(db, &source, &target);
	if (result != DNS_R_SUCCESS)
		return (result);

	/*
	 * Copy the reply out, adjusting for reslen
	 */
	isc_buffer_used(&target, &txr);
	txr.base = isc_mem_get(mctx, txr.length + reslen);
	if (txr.base == NULL)
		return (DNS_R_NOMEMORY);

	memcpy(txr.base + reslen, t + reslen, txr.length);
	rxr->base = txr.base;
	rxr->length = txr.length + reslen;

	printf("Base == %p, length == %u\n", txr.base, txr.length);
	fflush(stdout);

	dump_packet(rxr->base + reslen, rxr->length - reslen);

	if (want_stats)
		isc_mem_stats(mctx, stdout);

	return (DNS_R_SUCCESS);
}


int
main(int argc, char *argv[])
{
	isc_taskmgr_t *manager = NULL;
	unsigned int workers;
	isc_socketmgr_t *socketmgr;
	isc_socket_t *so0, *so1;
	isc_sockaddr_t sockaddr;
	unsigned int addrlen;
	udp_listener_t *ludp;
	tcp_listener_t *ltcp;
	dns_name_t base, *origin;
	int ch;
	char basetext[1000];
	dns_rdatatype_t type = 2;
	dns_result_t result;

#if 0 /* brister */
	isc_cfgctx_t *configctx = NULL;
	const char *conffile = "/etc/named.conf"; /* XXX hardwired */
#endif

	/*+ XXX */
	strcpy(basetext, "");
	while ((ch = getopt(argc, argv, "z:t:s")) != -1) {
		switch (ch) {
		case 'z':
			strcpy(basetext, optarg);
			break;
		case 't':
			type = atoi(optarg);
			break;
		case 's':
			want_stats = ISC_TRUE;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "usage: named filename\n");
		exit(1);
	}

	/*- XXX */

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);

	workers = 2;
	printf("%d workers\n", workers);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

#if 0 /* brister */
	parser_init();
	RUNTIME_CHECK(parse_configuration(conffile, mctx, &configctx) ==
		      ISC_R_SUCCESS);
#endif

	/*+ XXX */
	if (strcmp(basetext, "") == 0)
		strcpy(basetext, "vix.com.");
	makename(mctx, basetext, &base, NULL);

	db = NULL;
	result = dns_db_create(mctx, "rbt", &base, ISC_FALSE, 1, 0, NULL,
			       &db);
	RUNTIME_CHECK(result == DNS_R_SUCCESS);
	
	origin = &base;
	printf("loading %s\n", argv[0]);
	result = dns_db_load(db, argv[0]);
	if (result != DNS_R_SUCCESS) {
		printf("couldn't load master file: %s\n",
		       dns_result_totext(result));
		exit(1);
	}
	/*- XXX */

	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &manager) ==
		      ISC_R_SUCCESS);

	/*
	 * Open up a database.
	 */
	

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	/*
	 * open up a UDP socket
	 */
	so0 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, isc_socket_udp, &so0) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(so0, &sockaddr,
				      (int)addrlen) == ISC_R_SUCCESS);

	ludp = udp_listener_allocate(mctx, workers);
	RUNTIME_CHECK(udp_listener_start(ludp, so0, manager,
					 workers, workers, 0,
					 dispatch) == ISC_R_SUCCESS);

	if (want_stats)
		isc_mem_stats(mctx, stdout);

	/*
	 * open up a TCP socket
	 */
	so1 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, isc_socket_tcp, &so1) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(so1, &sockaddr,
				      (int)addrlen) == ISC_R_SUCCESS);

	ltcp = tcp_listener_allocate(mctx, workers);
	RUNTIME_CHECK(tcp_listener_start(ltcp, so1, manager,
					 workers, workers, 0,
					 dispatch) == ISC_R_SUCCESS);

	if (want_stats)
		isc_mem_stats(mctx, stdout);

	/* 
	 * XXX Need to set up a condition variable here, and wait on it.
	 * For now, just semi-busy loop.
	 */
	for (;;)
		sleep(10);

	printf("Destroying socket manager\n");
	isc_socketmgr_destroy(&socketmgr);

	printf("Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	if (want_stats)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
