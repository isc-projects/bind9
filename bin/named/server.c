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

isc_mem_t *mctx = NULL;

#define INPUT_BUFFER_SIZE (64 * 1024)	/* 64k */

typedef struct {
	char name[16];		/* socket human-printable name */
	char *buf;		/* input buffer */
	isc_mem_t *mctx;	/* memory context used to allocate */
} client_ctx_t;

static client_ctx_t *client_ctx_allocate(isc_mem_t *mctx);
static void client_ctx_free(client_ctx_t *ctx);

static void my_send(isc_task_t *task, isc_event_t *event);
static void udp_recv(isc_task_t *task, isc_event_t *event);

static client_ctx_t *
client_ctx_allocate(isc_mem_t *mctx)
{
	client_ctx_t *ctx;

	ctx = isc_mem_get(mctx, sizeof(client_ctx_t));
	if (ctx == NULL)
		return (NULL);

	ctx->buf = isc_mem_get(mctx, INPUT_BUFFER_SIZE);
	if (ctx->buf == NULL) {
		isc_mem_put(mctx, ctx, sizeof(client_ctx_t));
		return (NULL);
	}

	ctx->name[0] = '\0';
	ctx->mctx = mctx;

	return (ctx);
}

static void
client_ctx_free(client_ctx_t *ctx)
{
	isc_mem_put(ctx->mctx, ctx->buf, INPUT_BUFFER_SIZE);
	isc_mem_put(ctx->mctx, ctx, sizeof(client_ctx_t));
}

typedef struct dns_message {
	unsigned int		id;
	unsigned int		flags;
	unsigned int		qcount;
	unsigned int		ancount;
	unsigned int		aucount;
	unsigned int		adcount;
	dns_namelist_t		question;
	dns_namelist_t		answer;
	dns_namelist_t		authority;
	dns_namelist_t		additional;
} dns_message_t; /* XXX Should be common? */

/*
 * XXX These is in wire_test.c right now.
 */
void getmessage(dns_message_t *message, isc_buffer_t *source,
		isc_buffer_t *target);
dns_result_t printmessage(dns_message_t *message);

static void
dump_packet(char *buf, u_int len)
{
	extern dns_decompress_t dctx;
	char t[5000]; /* XXX */
	dns_message_t message;
	dns_result_t result;
	isc_buffer_t source, target;

	dctx.allowed = DNS_COMPRESS_GLOBAL14;
	dns_name_init(&dctx.owner_name, NULL);

	isc_buffer_init(&source, buf, len, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, len);
	isc_buffer_init(&target, t, sizeof(t), ISC_BUFFERTYPE_BINARY);

	getmessage(&message, &source, &target);
	result = printmessage(&message);
	if (result != DNS_R_SUCCESS)
		printf("printmessage() failed: %s\n",
		       dns_result_totext(result));
}

static void
udp_recv(isc_task_t *task, isc_event_t *event)
{
	isc_socket_t *sock;
	isc_socketevent_t *dev;
	client_ctx_t *ctx;

	sock = event->sender;
	dev = (isc_socketevent_t *)event;
	ctx = (client_ctx_t *)(event->arg);

	printf("Task %s (sock %p, base %p, length %d, n %d, result %d)\n",
	       (char *)(event->arg), sock,
	       dev->region.base, dev->region.length,
	       dev->n, dev->result);
	printf("\tFrom: %s port %d\n",
	       inet_ntoa(dev->address.type.sin.sin_addr),
	       ntohs(dev->address.type.sin.sin_port));

	if (dev->result != ISC_R_SUCCESS) {
		isc_socket_detach(&sock);

		client_ctx_free(ctx);

		isc_event_free(&event);

		/* destroy task */

		return;
	}

	/*
	 * Call the dump routine to print this baby out
	 */
	dump_packet(ctx->buf, dev->n);

	isc_socket_recv(sock, &dev->region, ISC_FALSE,
			task, udp_recv, event->arg);

	isc_mem_stats(ctx->mctx, stdout);

	isc_event_free(&event);
}

static void
my_send(isc_task_t *task, isc_event_t *event)
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

int
main(int argc, char *argv[])
{
	isc_taskmgr_t *manager = NULL;
	isc_task_t **tasks;
	unsigned int workers;
	isc_socketmgr_t *socketmgr;
	isc_socket_t *so1;
	isc_sockaddr_t sockaddr;
	unsigned int addrlen;
	client_ctx_t **ctxs;
	unsigned int i;
	isc_region_t region;

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	tasks = isc_mem_get(mctx, sizeof(isc_task_t *) * workers);
	RUNTIME_CHECK(tasks != NULL);
	ctxs = isc_mem_get(mctx, sizeof(client_ctx_t *) * workers);
	RUNTIME_CHECK(ctxs != NULL);

	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &manager) ==
		      ISC_R_SUCCESS);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	/*
	 * open up a UDP socket
	 */
	so1 = NULL;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_family = AF_INET;
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);
	RUNTIME_CHECK(isc_socket_create(socketmgr, isc_socket_udp, &so1) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socket_bind(so1, &sockaddr,
				      (int)addrlen) == ISC_R_SUCCESS);

	/*
	 * Create all the listening tasks and set up the initial read.
	 */
	for (i = 0 ; i < workers ; i++) {
		tasks[i] = NULL;
		RUNTIME_CHECK(isc_task_create(manager, NULL, 0, &tasks[i])
			      == ISC_R_SUCCESS);

		/*
		 * Allocate client context and set its name.
		 */
		ctxs[i] = client_ctx_allocate(mctx);
		RUNTIME_CHECK(ctxs[i] != NULL);
		region.length = INPUT_BUFFER_SIZE;
		region.base = ctxs[i]->buf;

		sprintf(ctxs[i]->name, "%u", i);

		printf("recv started for task %s\n", ctxs[i]->name);
		RUNTIME_CHECK(isc_socket_recv(so1, &region,
					      ISC_FALSE, tasks[i],
					      udp_recv, ctxs[i])
			      == ISC_R_SUCCESS);
	}

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
