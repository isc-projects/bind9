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

#define LOCK(lp) \
	RUNTIME_CHECK(isc_mutex_lock((lp)) == ISC_R_SUCCESS)
#define UNLOCK(lp) \
	RUNTIME_CHECK(isc_mutex_unlock((lp)) == ISC_R_SUCCESS)

#include "udpclient.h"

/*
 * For debugging only... XXX
 */
void dump_packet(char *buf, u_int len);

static udp_cctx_t *udp_cctx_allocate(isc_mem_t *mctx);
static void udp_cctx_free(udp_cctx_t *ctx);

static void udp_send(isc_task_t *task, isc_event_t *event);
static void udp_recv(isc_task_t *task, isc_event_t *event);



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

static void
udp_shutdown(isc_task_t *task, isc_event_t *event)
{
	udp_cctx_t *ctx;
	udp_listener_t *l;

	ctx = (udp_cctx_t *)(event->arg);
	l = ctx->parent;

	LOCK(&l->lock);

	REQUIRE(l->nwactive > 0);

	/*
	 * remove our task from the list of tasks that the listener
	 * maintains by setting things to NULL, then freeing the
	 * pointers we maintain.
	 */
	INSIST(l->tasks[ctx->slot] == task);
	l->tasks[ctx->slot] = NULL;
	l->ctxs[ctx->slot] = NULL;

	isc_socket_cancel(l->sock, task, ISC_SOCKCANCEL_ALL);

	l->nwactive--;

	UNLOCK(&l->lock);

	printf("Final shutdown slot %u\n", ctx->slot);
	udp_cctx_free(ctx);

	isc_event_free(&event);
}

static void
udp_recv(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	udp_cctx_t *ctx;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (udp_cctx_t *)(event->arg);

	printf("Task %u (sock %p, base %p, length %d, n %d, result %d)\n",
	       ctx->slot, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n",
	       inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));

	if (dev->result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);

		udp_cctx_free(ctx);

		isc_event_free(&event);

		isc_task_shutdown(task);

		return;
	}

	/*
	 * Call the dump routine to print this baby out
	 */
	dump_packet(ctx->buf, dev->n);

	isc_socket_recv(sock, &dev->region, ISC_FALSE,
			task, udp_recv, event->arg);

	isc_event_free(&event);
}

static void
udp_send(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;

	printf("my_send: %s task %p\n\t(sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), task, sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);

	isc_mem_put(event->mctx, dev->region.base, dev->region.length);

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

	l->mctx = mctx;

	return (l);
}

isc_result_t
udp_listener_start(udp_listener_t *l,
		   isc_socket_t *sock, isc_taskmgr_t *tmgr,
		   u_int nwstart, u_int nwkeep, u_int nwtimeout)
{
	u_int i;
	isc_region_t region;

	LOCK(&l->lock);
	INSIST(l->nwactive == 0);

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
