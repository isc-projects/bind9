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

#include <lwres/lwbuffer.h>
#include <lwres/lwpacket.h>
#include <lwres/lwres.h>

#include "context_p.h"
#include "assert_p.h"

int
lwres_gnbarequest_render(lwres_context_t *ctx,
			 lwres_gnbarequest_t *req,
			 isc_uint32_t maxrecv, lwres_buffer_t *b)
{
}

int
lwres_gnbaresponse_render(lwres_context_t *ctx,
			  lwres_gnbaresponse_t *req,
			  isc_uint32_t maxrecv, lwres_buffer_t *b)
{
}

int
lwres_gnbarequest_parse(lwres_context_t *ctx, lwres_gnbarequest_t **structp)
{
}

int
lwres_gnbaresponse_parse(lwres_context_t *ctx, lwres_gnbaresponse_t **structp)
{
}

void
lwres_gnbarequest_free(lwres_context_t *ctx, lwres_gnbarequest_t **structp)
{
}

void
lwres_gnbaresponse_free(lwres_context_t *ctx, lwres_gnbaresponse_t **structp)
{
}
