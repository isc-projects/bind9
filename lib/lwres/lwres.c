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

/*
 * Not all the attributes here are actually settable by the application at
 * this time.
 */
struct lwres_context {
	/*
	 * Function pointers for allocating memory.
	 */
	lwres_malloc_t		malloc;
	lwres_free_t		free;
	void		       *arg;
};

unsigned int
lwres_contextcreate(lwres_context_t **contextp, void *arg,
		    lwres_malloc_t malloc_function,
		    lwres_free_t free_function)
{
	lwres_context_t *context;

	if (malloc_function == NULL) {
		malloc_function = lwres_malloc;
		free_function = lwres_free;
	}

	context = malloc_function(arg, sizeof(lwres_context_t));
	if (context == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	context->free = lwres_free;
	context->malloc = lwres_malloc;
	context->arg = arg;

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

unsigned int
lwres_getaddrsbyname(lwres_context_t *contextp,
		     char *name, unsigned int addrtypes,
		     lwres_getaddrsbyname_t **structp)
{
}

void
lwres_freegetaddrsbyname(lwres_context_t *contextp,
			 lwres_getaddrsbyname_t **structp)
{
}

unsigned int
lwres_getnamebyaddr(lwres_context_t *contextp, unsigned int addrtype,
		    unsigned int addrlen, unsigned char *addr,
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
	(void)arg;

	return (malloc(len));
}

static void
lwres_free(void *arg, size_t len, void *mem)
{
	(void)arg;
	(void)len;

	free(mem);
}
