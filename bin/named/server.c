/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "udpclient.h"
#include "tcpclient.h"

isc_mem_t *mctx = NULL;

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
	isc_region_t txr;
	unsigned char *cp;

	/*
	 * XXX for now, just SERVFAIL everything.
	 */
	txr.length = rxr->length + reslen;
	txr.base = isc_mem_get(mctx, txr.length);
	if (txr.base == NULL)
		return (DNS_R_NOMEMORY);

	memcpy(txr.base + reslen, rxr->base, rxr->length);

	cp = txr.base + reslen;
	cp += 2;
	*cp |= 0x80;  /* set QR to response */
	*cp++ &= 0xf9; /* clear AA, TC */
	*cp++ = 2;  /* SERVFAIL */

	rxr->base = txr.base;
	rxr->length = txr.length;

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

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &manager) ==
		      ISC_R_SUCCESS);

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

	isc_mem_stats(mctx, stdout);

	for (;;)
		sleep(10);

	printf("Destroying socket manager\n");
	isc_socketmgr_destroy(&socketmgr);

	printf("Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
