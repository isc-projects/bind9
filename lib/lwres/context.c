/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <lwres/context.h>
#include <lwres/lwres.h>
#include <lwres/result.h>

#include "context_p.h"
#include "assert_p.h"

static void *lwres_malloc(void *, size_t);
static void lwres_free(void *, void *, size_t);
static lwres_result_t context_connect(lwres_context_t *);

lwres_result_t
lwres_context_create(lwres_context_t **contextp, void *arg,
		     lwres_malloc_t malloc_function,
		     lwres_free_t free_function)
{
	lwres_context_t *ctx;

	REQUIRE(contextp != NULL && *contextp == NULL);

	/*
	 * If we were not given anything special to use, use our own
	 * functions.  These are just wrappers around malloc() and free().
	 */
	if (malloc_function == NULL || free_function == NULL) {
		REQUIRE(malloc_function == NULL);
		REQUIRE(free_function == NULL);
		malloc_function = lwres_malloc;
		free_function = lwres_free;
	}

	ctx = malloc_function(arg, sizeof(lwres_context_t));
	if (ctx == NULL)
		return (LWRES_R_NOMEMORY);

	/*
	 * Set up the context.
	 */
	ctx->malloc = malloc_function;
	ctx->free = free_function;
	ctx->arg = arg;
	ctx->sock = -1;

	ctx->timeout = LWRES_DEFAULT_TIMEOUT;
	ctx->serial = (lwres_uint32_t)ctx; /* XXXMLG */

	(void)context_connect(ctx); /* XXXMLG */

	/*
	 * Init resolv.conf bits.
	 */
	lwres_conf_init(ctx);

	*contextp = ctx;
	return (LWRES_R_SUCCESS);
}

void
lwres_context_destroy(lwres_context_t **contextp)
{
	lwres_context_t *ctx;

	REQUIRE(contextp != NULL && *contextp != NULL);

	ctx = *contextp;
	*contextp = NULL;

	if (ctx->sock != -1) {
		close(ctx->sock);
		ctx->sock = -1;
	}

	CTXFREE(ctx, sizeof(lwres_context_t));
}

lwres_uint32_t
lwres_context_nextserial(lwres_context_t *ctx)
{
	REQUIRE(ctx != NULL);

	return (ctx->serial++);
}

void
lwres_context_initserial(lwres_context_t *ctx, lwres_uint32_t serial)
{
	REQUIRE(ctx != NULL);

	ctx->serial = serial;
}

void
lwres_context_freemem(lwres_context_t *ctx, void *mem, size_t len)
{
	REQUIRE(mem != NULL);
	REQUIRE(len != 0);

	CTXFREE(mem, len);
}

void *
lwres_context_allocmem(lwres_context_t *ctx, size_t len)
{
	REQUIRE(len != 0);

	return (CTXMALLOC(len));
}

static void *
lwres_malloc(void *arg, size_t len)
{
	void *mem;

	(void)arg;

	mem = malloc(len);
	if (mem == NULL)
		return (NULL);

	memset(mem, 0xe5, len);

	return (mem);
}

static void
lwres_free(void *arg, void *mem, size_t len)
{
	(void)arg;

	memset(mem, 0xa9, len);
	free(mem);
}

static lwres_result_t
context_connect(lwres_context_t *ctx)
{
	int s;
	int ret;
	struct sockaddr_in localhost;

	memset(&localhost, 0, sizeof(localhost));
	localhost.sin_family = AF_INET;
	localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	localhost.sin_port = htons(LWRES_UDP_PORT);

	s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return (LWRES_R_IOERROR);

	ret = connect(s, (struct sockaddr *)&localhost, sizeof(localhost));
	if (ret != 0) {
		close(s);
		return (LWRES_R_IOERROR);
	}

	ctx->sock = s;

	return (LWRES_R_SUCCESS);
}

lwres_result_t
lwres_context_sendrecv(lwres_context_t *ctx,
		       void *sendbase, int sendlen,
		       void *recvbase, int recvlen,
		       int *recvd_len)
{
	int ret;
	int ret2;
	int flags;
	struct sockaddr_in sin;
	int fromlen;
	fd_set readfds;
	struct timeval timeout;

	timeout.tv_sec = ctx->timeout;
	timeout.tv_usec = 0;

	ret = sendto(ctx->sock, sendbase, sendlen, 0, NULL, 0);
	if (ret < 0)
		return (LWRES_R_IOERROR);
	if (ret != sendlen)
		return (LWRES_R_IOERROR);

 again:
	flags = fcntl(ctx->sock, F_GETFL, 0);
	flags |= O_NONBLOCK;
	ret = fcntl(ctx->sock, F_SETFL, flags);
	if (ret < 0)
		return (LWRES_R_IOERROR);

	FD_ZERO(&readfds);
	FD_SET(ctx->sock, &readfds);
	ret2 = select(ctx->sock + 1, &readfds, NULL, NULL, &timeout);

	flags = fcntl(ctx->sock, F_GETFL, 0);
	flags &= ~O_NONBLOCK;
	ret = fcntl(ctx->sock, F_SETFL, flags);
	if (ret < 0)
		return (LWRES_R_IOERROR);

	/*
	 * What happened with select?
	 */
	if (ret2 < 0)
		return (LWRES_R_IOERROR);
	if (ret2 == 0)
		return (LWRES_R_TIMEOUT);

	fromlen = sizeof(sin);
	ret = recvfrom(ctx->sock, recvbase, recvlen, 0,
		       (struct sockaddr *)&sin, &fromlen);

	if (ret < 0)
		return (LWRES_R_IOERROR);

	/*
	 * If we got something other than what we expect, re-issue our
	 * recvfrom() call.  This can happen if an old result comes in,
	 * or if someone is sending us random stuff.
	 */
	if (sin.sin_addr.s_addr != htonl(INADDR_LOOPBACK)
	    || sin.sin_port != htons(LWRES_UDP_PORT))
		goto again;

	if (recvd_len != NULL)
		*recvd_len = ret;

	return (LWRES_R_SUCCESS);
}
