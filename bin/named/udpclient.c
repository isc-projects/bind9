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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>

#include <dns/result.h>

#define LOCK(lp) \
	RUNTIME_CHECK(isc_mutex_lock((lp)) == ISC_R_SUCCESS)
#define UNLOCK(lp) \
	RUNTIME_CHECK(isc_mutex_unlock((lp)) == ISC_R_SUCCESS)

#include "udpclient.h"

static udp_cctx_t *udp_cctx_allocate(isc_mem_t *mctx);
static void udp_cctx_free(udp_cctx_t *ctx);

static void udp_send(isc_task_t *task, isc_event_t *event);
static void udp_recv(isc_task_t *task, isc_event_t *event);
static void udp_listener_free(udp_listener_t **lp);


static udp_cctx_t *
udp_cctx_allocate(isc_mem_t *mctx)
{
	udp_cctx_t *ctx;

	ctx = isc_mem_get(mctx, sizeof(udp_cctx_t));
	if (ctx == NULL)
		return (NULL);

	ctx->buf = isc_mem_get(mctx, UDP_INPUT_BUFFER_SIZE);
	if (ctx->buf == NULL) {
		isc_mem_put(mctx, ctx, sizeof(udp_cctx_t));
		return (NULL);
	}

	ctx->slot = 0;
	ctx->mctx = mctx;

	return (ctx);
}

static void
udp_cctx_free(udp_cctx_t *ctx)
{
	isc_mem_put(ctx->mctx, ctx->buf, UDP_INPUT_BUFFER_SIZE);
	isc_mem_put(ctx->mctx, ctx, sizeof(udp_cctx_t));
}

/*
 * A worker task is shutting down, presumably because the
 * socket has been shut down.
 */
static void
udp_shutdown(isc_task_t *task, isc_event_t *event)
{
	udp_cctx_t *ctx;
	udp_listener_t *l;
	isc_boolean_t free_listener = ISC_FALSE;

	ctx = (udp_cctx_t *)(event->arg);
	l = ctx->parent;

	LOCK(&l->lock);

	REQUIRE(l->nwactive > 0);

	/*
	 * Remove our task from the list of tasks that the listener
	 * maintains by setting things to NULL, then freeing the
	 * pointers we maintain.
	 */
	INSIST(l->tasks[ctx->slot] == task);
	l->tasks[ctx->slot] = NULL;
	INSIST(l->ctxs[ctx->slot] == ctx);	
	l->ctxs[ctx->slot] = NULL;

	l->nwactive--;

	if (l->nwactive == 0)
		free_listener = ISC_TRUE;

	UNLOCK(&l->lock);

#ifdef NOISY
	printf("Final shutdown slot %u\n", ctx->slot);
#endif

	/* This is where the pointers are freed. */
	udp_cctx_free(ctx);
	isc_task_detach(&task);

	isc_event_free(&event);

	if (free_listener)
		udp_listener_free(&l);
}

/*
 * We got the data we were waiting to receive, or 
 * a socket shutdown request.
 */
static void
udp_recv(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	udp_cctx_t *ctx;
	dns_result_t result;
	isc_region_t region;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (udp_cctx_t *)(event->arg);

#ifdef NOISY
	printf("Task %u (sock %p, base %p, length %d, n %d, result %d)\n",
	       ctx->slot, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n",
	       inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));
#endif

	if (dev->result != ISC_R_SUCCESS) {
		isc_task_shutdown(task);

		isc_event_free(&event);

		return;
	}

	region.base = ctx->buf;
	region.length = dev->n;
	result = ctx->parent->dispatch(ctx->mctx, &region, 0);

	if (result == DNS_R_SUCCESS) {
		/* Send a reply as soon as the socket is ready to do so. */
		isc_socket_sendto(sock, &region, task, udp_send, ctx,
				  &dev->address, dev->addrlength);
	} else {
		/* Send no reply, just wait for the next request. */
		isc_socket_recv(sock, &region, ISC_FALSE, task, udp_recv, ctx);
	}

	isc_event_free(&event);
}

/*
 * The data we were waiting to send was sent, or we got a socket
 * shutdown request.
 */
static void
udp_send(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	udp_cctx_t *ctx;
	isc_region_t region;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (udp_cctx_t *)(event->arg);

#ifdef NOISY
	printf("udp_send: task %u\n\t(base %p, length %d, n %d, result %d)\n",
	       ctx->slot, dev->region.base, dev->region.length,
	       dev->n, dev->result);
#endif

	if (ctx->buf != dev->region.base)
		isc_mem_put(ctx->mctx, dev->region.base, dev->region.length);

	if (dev->result != ISC_R_SUCCESS) {
		isc_task_shutdown(task);

		isc_event_free(&event);

		return;
	}

	region.base = ctx->buf;
	region.length = UDP_INPUT_BUFFER_SIZE;
	isc_socket_recv(sock, &region, ISC_FALSE, task, udp_recv, ctx);

	isc_event_free(&event);
}

udp_listener_t *
udp_listener_allocate(isc_mem_t *mctx, u_int nwmax)
{
	udp_listener_t *l;

	l = isc_mem_get(mctx, sizeof(udp_listener_t));
	if (l == NULL)
		return (NULL);

	if (isc_mutex_init(&l->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, l, sizeof(udp_listener_t));

		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");

		return (NULL);
	}

	l->tasks = isc_mem_get(mctx, sizeof(isc_task_t *) * nwmax);
	RUNTIME_CHECK(l->tasks != NULL); /* XXX should be non-fatal? */
	l->ctxs = isc_mem_get(mctx, sizeof(udp_cctx_t *) * nwmax);
	RUNTIME_CHECK(l->ctxs != NULL);  /* XXX should be non-fatal? */

	l->sock = NULL;
	l->nwstart = 0;
	l->nwkeep = 0;
	l->nwmax = nwmax;
	l->mctx = mctx;
	l->dispatch = NULL;
	l->nwactive = 0;

	return (l);
}

static void 
udp_listener_free(udp_listener_t **lp)
{
	udp_listener_t *l = *lp;
	isc_mem_put(l->mctx, l->ctxs, sizeof(udp_cctx_t *) * l->nwmax);	
	l->ctxs = NULL;
	isc_mem_put(l->mctx, l->tasks, sizeof(isc_task_t *) * l->nwmax);
	l->tasks = NULL;	
	isc_mutex_destroy(&l->lock);
	isc_mem_put(l->mctx, l, sizeof(udp_listener_t));
	*lp = NULL;
}

isc_result_t
udp_listener_start(udp_listener_t *l,
		   isc_socket_t *sock, isc_taskmgr_t *tmgr,
		   u_int nwstart, u_int nwkeep, u_int nwtimeout,
		   dns_result_t (*dispatch)(isc_mem_t *, isc_region_t *,
					    unsigned int))
{
	u_int i;
	isc_region_t region;

	(void)nwkeep;		/* Make compiler happy. */
	(void)nwtimeout;	/* Make compiler happy. */

	LOCK(&l->lock);
	INSIST(l->nwactive == 0);
	INSIST(dispatch != NULL);

	l->dispatch = dispatch;
	l->sock = sock;

	for (i = 0 ; i < nwstart ; i++) {
		l->tasks[i] = NULL;
		RUNTIME_CHECK(isc_task_create(tmgr, NULL, 0, &l->tasks[i])
			      == ISC_R_SUCCESS);

		l->ctxs[i] = udp_cctx_allocate(l->mctx);
		RUNTIME_CHECK(l->ctxs[i] != NULL);

		l->ctxs[i]->parent = l;
		l->ctxs[i]->slot = i;

		RUNTIME_CHECK(isc_task_onshutdown(l->tasks[i], udp_shutdown,
						  l->ctxs[i])
			      == ISC_R_SUCCESS);

		region.length = UDP_INPUT_BUFFER_SIZE;
		region.base = l->ctxs[i]->buf;

		RUNTIME_CHECK(isc_socket_recv(sock, &region,
					      ISC_FALSE, l->tasks[i],
					      udp_recv, l->ctxs[i])
			      == ISC_R_SUCCESS);

		l->nwactive++;
	}

	UNLOCK(&l->lock);

	return (ISC_R_SUCCESS);
}
