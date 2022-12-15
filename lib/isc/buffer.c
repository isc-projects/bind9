/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */
/*! \file */

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/string.h>
#include <isc/util.h>

void
isc_buffer_reinit(isc_buffer_t *b, void *base, unsigned int length) {
	/*
	 * Re-initialize the buffer enough to reconfigure the base of the
	 * buffer.  We will swap in the new buffer, after copying any
	 * data we contain into the new buffer and adjusting all of our
	 * internal pointers.
	 *
	 * The buffer must not be smaller than the length of the original
	 * buffer.
	 */
	REQUIRE(b->length <= length);
	REQUIRE(base != NULL);
	REQUIRE(b->mctx == NULL);

	if (b->length > 0U) {
		(void)memmove(base, b->base, b->length);
	}

	b->base = base;
	b->length = length;
}

void
isc_buffer_compact(isc_buffer_t *b) {
	unsigned int length;
	void *src;

	/*
	 * Compact the used region by moving the remaining region so it occurs
	 * at the start of the buffer.  The used region is shrunk by the size
	 * of the consumed region, and the consumed region is then made empty.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));

	src = isc_buffer_current(b);
	length = isc_buffer_remaininglength(b);
	if (length > 0U) {
		(void)memmove(b->base, src, (size_t)length);
	}

	if (b->active > b->current) {
		b->active -= b->current;
	} else {
		b->active = 0;
	}
	b->current = 0;
	b->used = length;
}

isc_result_t
isc_buffer_dup(isc_mem_t *mctx, isc_buffer_t **dstp, const isc_buffer_t *src) {
	isc_buffer_t *dst = NULL;
	isc_region_t region;
	isc_result_t result;

	REQUIRE(dstp != NULL && *dstp == NULL);
	REQUIRE(ISC_BUFFER_VALID(src));

	isc_buffer_usedregion(src, &region);

	isc_buffer_allocate(mctx, &dst, region.length);

	result = isc_buffer_copyregion(dst, &region);
	RUNTIME_CHECK(result == ISC_R_SUCCESS); /* NOSPACE is impossible */
	*dstp = dst;
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_buffer_copyregion(isc_buffer_t *b, const isc_region_t *r) {
	isc_result_t result;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	if (b->mctx) {
		result = isc_buffer_reserve(b, r->length);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	if (r->length > isc_buffer_availablelength(b)) {
		return (ISC_R_NOSPACE);
	}

	if (r->length > 0U) {
		memmove(isc_buffer_used(b), r->base, r->length);
		b->used += r->length;
	}

	return (ISC_R_SUCCESS);
}

void
isc_buffer_allocate(isc_mem_t *mctx, isc_buffer_t **dynbuffer,
		    unsigned int length) {
	REQUIRE(dynbuffer != NULL && *dynbuffer == NULL);

	isc_buffer_t *dbuf = isc_mem_get(mctx, sizeof(isc_buffer_t));
	unsigned char *bdata = isc_mem_get(mctx, length);

	isc_buffer_init(dbuf, bdata, length);

	dbuf->mctx = mctx;

	*dynbuffer = dbuf;
}

isc_result_t
isc_buffer_reserve(isc_buffer_t *dynbuffer, unsigned int size) {
	size_t len;

	REQUIRE(ISC_BUFFER_VALID(dynbuffer));

	len = dynbuffer->length;
	if ((len - dynbuffer->used) >= size) {
		return (ISC_R_SUCCESS);
	}

	if (dynbuffer->mctx == NULL) {
		return (ISC_R_NOSPACE);
	}

	/* Round to nearest buffer size increment */
	len = size + dynbuffer->used;
	len = (len + ISC_BUFFER_INCR - 1 - ((len - 1) % ISC_BUFFER_INCR));

	/* Cap at UINT_MAX */
	if (len > UINT_MAX) {
		len = UINT_MAX;
	}

	if ((len - dynbuffer->used) < size) {
		return (ISC_R_NOMEMORY);
	}

	dynbuffer->base = isc_mem_reget(dynbuffer->mctx, dynbuffer->base,
					dynbuffer->length, len);
	dynbuffer->length = (unsigned int)len;

	return (ISC_R_SUCCESS);
}

void
isc_buffer_free(isc_buffer_t **dynbuffer) {
	isc_buffer_t *dbuf;
	isc_mem_t *mctx;

	REQUIRE(dynbuffer != NULL);
	REQUIRE(ISC_BUFFER_VALID(*dynbuffer));
	REQUIRE((*dynbuffer)->mctx != NULL);

	dbuf = *dynbuffer;
	*dynbuffer = NULL; /* destroy external reference */
	mctx = dbuf->mctx;
	dbuf->mctx = NULL;

	isc_mem_put(mctx, dbuf->base, dbuf->length);
	isc_buffer_invalidate(dbuf);
	isc_mem_put(mctx, dbuf, sizeof(isc_buffer_t));
}

isc_result_t
isc_buffer_printf(isc_buffer_t *b, const char *format, ...) {
	va_list ap;
	int n;
	isc_result_t result;

	REQUIRE(ISC_BUFFER_VALID(b));

	va_start(ap, format);
	n = vsnprintf(NULL, 0, format, ap);
	va_end(ap);

	if (n < 0) {
		return (ISC_R_FAILURE);
	}

	if (b->mctx) {
		result = isc_buffer_reserve(b, n + 1);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	if (isc_buffer_availablelength(b) < (unsigned int)n + 1) {
		return (ISC_R_NOSPACE);
	}

	va_start(ap, format);
	n = vsnprintf(isc_buffer_used(b), n + 1, format, ap);
	va_end(ap);

	if (n < 0) {
		return (ISC_R_FAILURE);
	}

	b->used += n;

	return (ISC_R_SUCCESS);
}
