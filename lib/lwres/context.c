
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <lwres/context.h>

#include "context_p.h"
#include "assert_p.h"

static void *lwres_malloc(void *, size_t);
static void lwres_free(void *, void *, size_t);

int
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
	if (ctx == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	/*
	 * Set up the context.
	 */
	ctx->malloc = malloc_function;
	ctx->free = free_function;
	ctx->arg = arg;

	ctx->timeout = LWRES_DEFAULT_TIMEOUT;
	ctx->serial = (isc_uint32_t)ctx; /* XXXMLG */

	*contextp = ctx;
	return (0);
}

void
lwres_context_free(lwres_context_t **contextp)
{
	lwres_context_t *ctx;

	REQUIRE(contextp != NULL && *contextp != NULL);

	ctx = *contextp;
	*contextp = NULL;

	CTXFREE(ctx, sizeof(lwres_context_t));
}

isc_uint32_t
lwres_context_nextserial(lwres_context_t *ctx)
{
	REQUIRE(ctx != NULL);

	return (ctx->serial++);
}

void
lwres_context_initserial(lwres_context_t *ctx, isc_uint32_t serial)
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
