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

#include <dns/dispatch.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

isc_mem_t *mctx;
isc_taskmgr_t *manager;
isc_socketmgr_t *socketmgr;
dns_dispatch_t *disp;

void got_packet(isc_task_t *, isc_event_t *);

void
got_packet(isc_task_t *task, isc_event_t *ev_in)
{
	dns_dispatchevent_t *ev = (dns_dispatchevent_t *)ev_in;
	dns_dispentry_t *resp = ev->sender;

	(void)task;

	dns_dispatch_freeevent(disp, resp, &ev);
}

int
main(int argc, char *argv[])
{
	isc_task_t *t0;
	isc_socket_t *s0;
	isc_sockaddr_t sockaddr;
	dns_dispentry_t *resp;

	(void)argc;
	(void)argv;

	/*
	 * EVERYTHING needs a memory context.
	 */
	mctx = NULL;
	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	/*
	 * The task manager is independent (other than memory context)
	 */
	manager = NULL;
	RUNTIME_CHECK(isc_taskmgr_create(mctx, 1, 0, &manager) ==
		      ISC_R_SUCCESS);

	t0 = NULL;
	RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &t0) == ISC_R_SUCCESS);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	/*
	 * Open up a random socket.  Who cares where.
	 */
	s0 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = 0;
	sockaddr.length = sizeof (struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, isc_socket_udp, &s0) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(s0, &sockaddr) == ISC_R_SUCCESS);

	/*
	 * Create a dispatch context
	 */
	disp = NULL;
	RUNTIME_CHECK(dns_dispatch_create(mctx, s0, t0, 512, 1024, 1024,
					 16, &disp) == ISC_R_SUCCESS);

	resp = NULL;
	RUNTIME_CHECK(dns_dispatch_addrequest(disp, t0, got_packet, NULL,
					      &resp) == ISC_R_SUCCESS);

	fprintf(stderr, "Destroying socket manager\n");
	isc_socketmgr_destroy(&socketmgr);

	fprintf(stderr, "Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
