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
isc_buffer_allocate(isc_mem_t *mctx, isc_buffer_t **dbufp,
		    unsigned int length) {
	REQUIRE(dbufp != NULL && *dbufp == NULL);

	isc_buffer_t *dbuf = isc_mem_get(mctx, sizeof(*dbuf) + length);
	uint8_t *bdata = (uint8_t *)dbuf + sizeof(*dbuf);

	isc_buffer_init(dbuf, bdata, length);
	dbuf->extra = length;
	dbuf->mctx = mctx;

	*dbufp = dbuf;
}

isc_result_t
isc_buffer_reserve(isc_buffer_t *dbuf, unsigned int size) {
	REQUIRE(ISC_BUFFER_VALID(dbuf));

	size_t len;
	uint8_t *bdata = (uint8_t *)dbuf + sizeof(*dbuf);

	len = dbuf->length;
	if ((len - dbuf->used) >= size) {
		return (ISC_R_SUCCESS);
	}

	if (dbuf->mctx == NULL) {
		return (ISC_R_NOSPACE);
	}

	/* Round to nearest buffer size increment */
	len = size + dbuf->used;
	len = ISC_ALIGN(len, ISC_BUFFER_INCR);

	/* Cap at UINT_MAX */
	if (len > UINT_MAX) {
		len = UINT_MAX;
	}

	if ((len - dbuf->used) < size) {
		return (ISC_R_NOMEMORY);
	}

	if (dbuf->base == bdata) {
		dbuf->base = isc_mem_get(dbuf->mctx, len);
		memmove(dbuf->base, bdata, dbuf->used);
	} else {
		dbuf->base = isc_mem_reget(dbuf->mctx, dbuf->base, dbuf->length,
					   len);
	}
	dbuf->length = (unsigned int)len;

	return (ISC_R_SUCCESS);
}

void
isc_buffer_free(isc_buffer_t **dbufp) {
	REQUIRE(dbufp != NULL && ISC_BUFFER_VALID(*dbufp));
	REQUIRE((*dbufp)->mctx != NULL);

	isc_buffer_t *dbuf = *dbufp;
	isc_mem_t *mctx = dbuf->mctx;
	uint8_t *bdata = (uint8_t *)dbuf + sizeof(*dbuf);
	unsigned int extra = dbuf->extra;

	*dbufp = NULL; /* destroy external reference */
	dbuf->mctx = NULL;

	if (dbuf->base != bdata) {
		isc_mem_put(mctx, dbuf->base, dbuf->length);
	}

	isc_buffer_invalidate(dbuf);
	isc_mem_put(mctx, dbuf, sizeof(*dbuf) + extra);
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
