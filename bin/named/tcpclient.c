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

#define LOCK(lp) \
	RUNTIME_CHECK(isc_mutex_lock((lp)) == ISC_R_SUCCESS)
#define UNLOCK(lp) \
	RUNTIME_CHECK(isc_mutex_unlock((lp)) == ISC_R_SUCCESS)

#include "tcpclient.h"

/*
 * For debugging only... XXX
 */
void dump_packet(char *buf, u_int len);

static tcp_cctx_t *tcp_cctx_allocate(isc_mem_t *mctx);
static void tcp_cctx_free(tcp_cctx_t *ctx);

static void tcp_send(isc_task_t *task, isc_event_t *event);
static void tcp_recv_len(isc_task_t *task, isc_event_t *event);
static void tcp_recv_req(isc_task_t *task, isc_event_t *event);
static void tcp_accept(isc_task_t *task, isc_event_t *event);

static tcp_cctx_t *
tcp_cctx_allocate(isc_mem_t *mctx)
{
	tcp_cctx_t *ctx;

	ctx = isc_mem_get(mctx, sizeof(tcp_cctx_t));
	if (ctx == NULL)
		return (NULL);

	ctx->buf = NULL;
	ctx->buflen = 0;
	ctx->slot = 0;
	ctx->mctx = mctx;
	ctx->csock = NULL;

	ctx->count = 0; /* XXX */

	return (ctx);
}

static void
tcp_cctx_free(tcp_cctx_t *ctx)
{
	if (ctx->buf != NULL)
		isc_mem_put(ctx->mctx, ctx->buf, ctx->buflen);
	ctx->buf = NULL;
	isc_mem_put(ctx->mctx, ctx, sizeof(tcp_cctx_t));
}

static void
tcp_restart(isc_task_t *task, tcp_cctx_t *ctx)
{
	printf("Restarting listen on %u\n", ctx->slot);

	if (ctx->buf != NULL)
		isc_mem_put(ctx->mctx, ctx->buf, ctx->buflen);
	ctx->buf = NULL;
	ctx->buflen = 0;

	if (ctx->csock != NULL)
		isc_socket_detach(&ctx->csock);

	RUNTIME_CHECK(isc_socket_accept(ctx->parent->sock, task,
					tcp_accept, ctx)
		      == ISC_R_SUCCESS);

	isc_mem_stats(ctx->mctx, stdout);
}

static void
tcp_shutdown(isc_task_t *task, isc_event_t *event)
{
	tcp_cctx_t *ctx;
	tcp_listener_t *l;

	ctx = (tcp_cctx_t *)(event->arg);
	l = ctx->parent;

	printf("Parent: %p\n", l);

	LOCK(&l->lock);

	if (ctx->csock != NULL)
		isc_socket_detach(&ctx->csock);

	REQUIRE(l->nwactive > 0);

	/*
	 * remove our task from the list of tasks that the listener
	 * maintains by setting things to NULL, then freeing the
	 * pointers we maintain.
	 */
	INSIST(l->tasks[ctx->slot] == task);
	l->tasks[ctx->slot] = NULL;
	l->ctxs[ctx->slot] = NULL;

	l->nwactive--;

	UNLOCK(&l->lock);

	printf("Final shutdown slot %u\n", ctx->slot);
	tcp_cctx_free(ctx);

	isc_event_free(&event);
}

static void
tcp_recv_len(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	tcp_cctx_t *ctx;
	isc_region_t region;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (tcp_cctx_t *)(event->arg);

	printf("len Task %u (sock %p, base %p, length %d, n %d, result %d)\n",
	       ctx->slot, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n",
	       inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));

	if (dev->result == ISC_R_CANCELED) {
		isc_task_shutdown(task);

		isc_event_free(&event);

		return;
	}
	if (dev->result != ISC_R_SUCCESS) {
		tcp_restart(task, ctx);

		isc_event_free(&event);

		return;
	}

	/*
	 * Allocate the space needed to complete this request.
	 */
	ctx->buflen = ntohs(ctx->buflen);
	ctx->buf = isc_mem_get(ctx->mctx, ctx->buflen);
	if (ctx->buf == NULL) {
		printf("Out of memory!\n");
		tcp_restart(task, ctx);

		isc_event_free(&event);

		return;
	}

	printf("Length of buffer: %u\n", ctx->buflen);

	region.base = ctx->buf;
	region.length = ctx->buflen;

	isc_socket_recv(sock, &region, ISC_FALSE,
			task, tcp_recv_req, event->arg);

	isc_event_free(&event);
}

static void
tcp_recv_req(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	tcp_cctx_t *ctx;
	isc_region_t region;
	unsigned char *cp;
	isc_uint16_t len;
	dns_result_t result;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (tcp_cctx_t *)(event->arg);

	printf("req Task %u (sock %p, base %p, length %d, n %d, result %d)\n",
	       ctx->slot, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n",
	       inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));

	if (dev->result == ISC_R_CANCELED) {
		isc_task_shutdown(task);

		isc_event_free(&event);

		return;
	}
	if (dev->result != ISC_R_SUCCESS) {
		tcp_restart(task, ctx);

		isc_event_free(&event);

		return;
	}

	/*
	 * Call the dump routine to print this baby out
	 */
	dump_packet(ctx->buf, dev->n);

	/*
	 * Call the dispatch() function to actually process this packet.
	 * If it returns ISC_R_SUCCESS, we have a packet to transmit.
	 * do so.  If it returns anything else, drop this connection.
	 */
	region.base = ctx->buf;
	region.length = dev->n;
	result = ctx->parent->dispatch(ctx->mctx, &region, 2);
	isc_mem_put(ctx->mctx, ctx->buf, ctx->buflen); /* clean up request */
	ctx->buf = NULL;

	/*
	 * Failure.  Close TCP client.
	 */
	if (result != DNS_R_SUCCESS) {
		tcp_restart(task, ctx);

		isc_event_free(&event);

		return;
	}

	/*
	 * Success.  Send the packet, after filling in the length at the
	 * front of the packet.
	 */
	len = region.length - 2;
	cp = region.base;
	*cp++ = (len & 0xff00) >> 8;
	*cp++ = (len & 0x00ff);

	isc_socket_send(sock, &region, task, tcp_send, ctx);

	isc_event_free(&event);
}

static void
tcp_accept(isc_task_t *task, isc_event_t *event)
{
	isc_region_t region;
	isc_socket_newconnev_t *dev;
	isc_socket_t *sock;
	tcp_cctx_t *ctx;

	sock = event->sender;
	dev = (isc_socket_newconnev_t *)event;
	ctx = (tcp_cctx_t *)(event->arg);

	printf("tcp_accept: task %u\n", ctx->slot);

	/*
	 * If we get an error, close the socket.  This routine will actually
	 * close the socket and restart a listen on the parent socket for
	 * this task.  If, however, the result is that the I/O was canceled,
	 * we are being asked to shut down.  Do so.
	 */
	if (dev->result == ISC_R_CANCELED) {
		isc_task_shutdown(task);

		isc_event_free(&event);

		return;
	}
	if (dev->result != ISC_R_SUCCESS) {
		tcp_restart(task, ctx);

		isc_event_free(&event);

		return;
	}

	ctx->csock = dev->newsocket;

	/*
	 * New connection.  Start the read.  In this case, the first read
	 * goes into the length field.
	 */
	region.length = 2;
	region.base = (unsigned char *)&ctx->buflen;

	RUNTIME_CHECK(isc_socket_recv(ctx->csock, &region, ISC_FALSE, task,
				      tcp_recv_len, ctx)
		      == ISC_R_SUCCESS);

	isc_event_free(&event);
}

static void
tcp_send(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	tcp_cctx_t *ctx;
	isc_region_t region;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (tcp_cctx_t *)(event->arg);

	printf("tcp_send: task %u\n\t(base %p, length %d, n %d, result %d)\n",
	       ctx->slot, dev->region.base, dev->region.length,
	       dev->n, dev->result);

	/*
	 * release memory regardless of outcome.
	 */
	isc_mem_put(ctx->mctx, dev->region.base, dev->region.length);

	if (dev->result == ISC_R_CANCELED) {
		isc_task_shutdown(task);

		isc_event_free(&event);

		return;
	}
	if (dev->result != ISC_R_SUCCESS) {
		tcp_restart(task, ctx);

		isc_event_free(&event);

		return;
	}

	/*
	 * Queue up another receive.
	 */
	region.base = (unsigned char *)&ctx->buflen;
	region.length = 2;
	isc_socket_recv(sock, &region, ISC_FALSE, task, tcp_recv_len, ctx);

	isc_event_free(&event);
}

tcp_listener_t *
tcp_listener_allocate(isc_mem_t *mctx, u_int nwmax)
{
	tcp_listener_t *l;

	l = isc_mem_get(mctx, sizeof(tcp_listener_t));
	if (l == NULL)
		return (NULL);

	if (isc_mutex_init(&l->lock) != ISC_R_SUCCESS) {
		isc_mem_put(mctx, l, sizeof(tcp_listener_t));

		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");

		return (NULL);
	}

	l->tasks = isc_mem_get(mctx, sizeof(isc_task_t *) * nwmax);
	RUNTIME_CHECK(l->tasks != NULL); /* XXX should be non-fatal? */
	l->ctxs = isc_mem_get(mctx, sizeof(tcp_cctx_t *) * nwmax);
	RUNTIME_CHECK(l->ctxs != NULL);  /* XXX should be non-fatal? */

	l->mctx = mctx;

	return (l);
}

isc_result_t
tcp_listener_start(tcp_listener_t *l,
		   isc_socket_t *sock, isc_taskmgr_t *tmgr,
		   u_int nwstart, u_int nwkeep, u_int nwtimeout,
		   dns_result_t (*dispatch)(isc_mem_t *, isc_region_t *,
					    unsigned int))
{
	u_int i;

	LOCK(&l->lock);
	INSIST(l->nwactive == 0);
	INSIST(dispatch != NULL);

	l->dispatch = dispatch;
	l->sock = sock;
	RUNTIME_CHECK(isc_socket_listen(sock, 0) == ISC_R_SUCCESS);

	for (i = 0 ; i < nwstart ; i++) {
		l->tasks[i] = NULL;
		RUNTIME_CHECK(isc_task_create(tmgr, NULL, 0, &l->tasks[i])
			      == ISC_R_SUCCESS);

		l->ctxs[i] = tcp_cctx_allocate(l->mctx);
		RUNTIME_CHECK(l->ctxs[i] != NULL);

		l->ctxs[i]->parent = l;
		l->ctxs[i]->slot = i;

		RUNTIME_CHECK(isc_task_onshutdown(l->tasks[i], tcp_shutdown,
						  l->ctxs[i])
			      == ISC_R_SUCCESS);

		RUNTIME_CHECK(isc_socket_accept(sock, l->tasks[i],
						tcp_accept, l->ctxs[i])
			      == ISC_R_SUCCESS);

		l->nwactive++;
	}

	UNLOCK(&l->lock);

	printf("Parent: %p\n", l);

	return (ISC_R_SUCCESS);
}
