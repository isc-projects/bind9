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

/* XXXMLG */
#define REQUIRE(x)

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <lwres/lwbuffer.h>
#include <lwres/lwpacket.h>
#include <lwres/lwres.h>

static void *lwres_malloc(void *, size_t);
static void lwres_free(void *, size_t, void *);

#define LWRES_DEFAULT_TIMEOUT	30	/* 30 seconds for a reply */

/*
 * Not all the attributes here are actually settable by the application at
 * this time.
 */
struct lwres_context {
	unsigned int		timeout;	/* time to wait for reply */

	/*
	 * Function pointers for allocating memory.
	 */
	lwres_malloc_t		malloc;
	lwres_free_t		free;
	void		       *arg;
};

int
lwres_contextcreate(lwres_context_t **contextp, void *arg,
		    lwres_malloc_t malloc_function,
		    lwres_free_t free_function)
{
	lwres_context_t *context;

	/*
	 * If we were not given anything special to use, use our own
	 * functions.  These are just wrappers around malloc() and free().
	 */
	if (malloc_function == NULL || free_function == NULL) {
		malloc_function = lwres_malloc;
		free_function = lwres_free;
	}

	context = malloc_function(arg, sizeof(lwres_context_t));
	if (context == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	/*
	 * Set up the context.
	 */
	context->malloc = malloc_function;
	context->free = free_function;
	context->arg = arg;

	context->timeout = LWRES_DEFAULT_TIMEOUT;

	*contextp = context;
	return (0);
}

void
lwres_contextfree(lwres_context_t **contextp)
{
	lwres_context_t *context;

	context = *contextp;
	*contextp = NULL;

	/* This is always allocated via malloc() for now... */
	context->free(context->arg, sizeof(lwres_context_t), context);
}

int
lwres_getaddrsbyname(lwres_context_t *contextp,
		     char *name, isc_uint32_t addrtypes,
		     lwres_getaddrsbyname_t **structp)
{
	lwres_lwpacket_t pkt;
	unsigned char *buf;
	unsigned char buflen;

	buflen = sizeof(lwres_lwpacket_t) + strlen(name) + 1 + 1 + 4;
}

void
lwres_freegetaddrsbyname(lwres_context_t *contextp,
			 lwres_getaddrsbyname_t **structp)
{
}

int
lwres_noop(lwres_context_t *context, isc_uint16_t datalength, void *data,
	   lwres_noop_t **structp)
{
}

void
lwres_freenoop(lwres_context_t *context, lwres_noop_t **structp)
{
}

int
lwres_getnamebyaddr(lwres_context_t *contextp, isc_uint32_t addrtype,
		    isc_uint16_t addrlen, unsigned char *addr,
		    lwres_getnamebyaddr_t **structp)
{
}

void
lwres_freegetnamebyaddr(lwres_context_t *contextp,
			lwres_getnamebyaddr_t **structp)
{
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
lwres_free(void *arg, size_t len, void *mem)
{
	(void)arg;

	memset(mem, 0xa9, len);
	free(mem);
}
