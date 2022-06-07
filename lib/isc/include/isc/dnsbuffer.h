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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/util.h>

#define ISC_DNSBUFFER_STATIC_BUFFER_SIZE	  (512)
#define ISC_DNSBUFFER_INITIAL_DYNAMIC_BUFFER_SIZE (ISC_BUFFER_INCR * 2)

typedef struct isc_dnsbuffer {
	isc_buffer_t *current; /* pointer to the currently used buffer */
	isc_buffer_t  stbuf;   /* static memory buffer */
	uint8_t buf[ISC_DNSBUFFER_STATIC_BUFFER_SIZE]; /* storage for the static
							  buffer */
	isc_buffer_t *dynbuf; /* resizeable dynamic memory buffer */
	isc_mem_t    *mctx;
} isc_dnsbuffer_t;
/*
 * The 'isc_dnsbuffer_t' object implementation is a thin wrapper on
 * top of 'isc_buffer_t' which has the following characteristics:
 *
 * - provides interface specifically atuned for handling/generating
 *   DNS messages, especially in the format used for DNS messages over
 *   TCP;
 *
 * - avoids allocating dynamic memory when handling small DNS
 *   messages, while transparently switching to using dynamic memory
 *   when handling larger messages. This approach significantly
 *   reduces pressure on the memory allocator, as most of the DNS
 *   messages are small.
 */

static inline void
isc_dnsbuffer_init(isc_dnsbuffer_t *restrict dnsbuf, isc_mem_t *memctx);
/*!<
 *  \brief Initialise the 'isc_dnsbuffer_t' object, keep a reference to
 * 'memctx' inside the object.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL;
 *\li	'memctx' is not NULL.
 */

static inline void
isc_dnsbuffer_uninit(isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Un-initialise the 'isc_dnsbuffer_t' object, de-allocate any
 *dynamically allocated memory, detach from an internal memory context
 * reference.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline isc_dnsbuffer_t *
isc_dnsbuffer_new(isc_mem_t *memctx);
/*!<
 * \brief Allocate and initialise a new 'isc_dnsbuffer_t' object, keep a
 * reference to 'memctx' inside the object.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL;
 *\li	'memctx' is not NULL.
 */

static inline void
isc_dnsbuffer_free(isc_dnsbuffer_t **restrict pdnsbuf);
/*!<
 * \brief Un-initialise and de-allocate the given 'isc_dnsbuffer_t' object.
 *
 * Requires:
 *\li	'pdnsbuf' is not NULL;
 *\li	'pdnsbuf' does not point to NULL.
 */

static inline void
isc_dnsbuffer_clear(isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Clear the given 'isc_dnsbuffer_t' object (make it empty).
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline unsigned int
isc_dnsbuffer_length(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Return the total length of the internal memory buffer of
 * the given 'isc_dnsbuffer_t' object.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline unsigned int
isc_dnsbuffer_usedlength(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Return the total number of used bytes from the internal
 * memory buffer of the given 'isc_dnsbuffer_t' object.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline unsigned int
isc_dnsbuffer_remaininglength(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Return the total number of remaining (unprocessed data)
 * bytes from the internal memory buffer of the given
 * 'isc_dnsbuffer_t' object.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline void
isc_dnsbuffer_remainingregion(const isc_dnsbuffer_t *restrict dnsbuf,
			      isc_region_t *region);
/*!<
 * \brief Make the given 'isc_region_t' object reference remaining
 * (unprocessed) data from the internal memory buffer of the given
 * 'isc_dnsbuffer_t' object.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline void
isc_dnsbuffer_compact(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Compact the internal used memory region of the internal
 * memory buffer of the given 'isc_dnsbuffer_t' object so that it
 * occurs at the start of the memory buffer. Then used region is
 * shrunk by the size of the processed (consumed) region, and the
 * consumed region is then made empty. This way the previously
 * processed (consumed) amount of memory can be used again without
 * resizing/reallocating the buffer.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline bool
isc_dnsbuffer_trycompact(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Compact the internal used memory region of the internal
 * memory buffer of the given 'isc_dnsbuffer_t' object in the case
 * when the processed (consumed) region is larger or equal in size to
 * the unprocessed one.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline void
isc_dnsbuffer_consume(isc_dnsbuffer_t *restrict dnsbuf, const unsigned int n);
/*!<
 * \brief Consume the given number of bytes from the beginning of
 * the unprocessed data region of the given 'isc_dnsbuffer_t' object.
 * The call moves the 'current' unprocessed data region pointer by the
 * given number of bytes.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline void
isc_dnsbuffer_putmem(isc_dnsbuffer_t *restrict dnsbuf, void *buf,
		     const unsigned int buf_size);
/*!<
 * \brief Copy 'buf_size' bytes from the location pointed to by
 * 'buf' pointer to the end of the unprocessed data region of the
 * given 'isc_dnsbuffer_t' object. Resize/reallocate the internal
 * memory buffer if it is too small.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL;
 *\li	'buf' is not NULL;
 *\li	'buf_size' is greater than '0'.
 */

static inline uint8_t *
isc_dnsbuffer_current(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Return the pointer to the beginning of unprocessed data
 * region of the given 'isc_dnsbuffer_t' object ("current pointer").
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline uint16_t
isc_dnsbuffer_peek_uint16be(const isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Lookup an unsigned short (16-bit) value in
 * big-endian/network byte order at the beginning of unprocessed data
 * region of the given 'isc_dnsbuffer_t' object.
 *
 * If there is not enough data available in the region, '0' will be
 * returned.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline uint16_t
isc_dnsbuffer_consume_uint16be(isc_dnsbuffer_t *restrict dnsbuf);
/*!<
 * \brief Read an unsigned short (16-bit) value in
 * big-endian/network byte order at the beginning of unprocessed data
 * region of the given 'isc_dnsbuffer_t' object.
 *
 * If there is not enough data available in the region, '0' will be
 * returned.
 *
 * In the case, when the data has been read successfully, the start of
 * the unprocessed data region is advanced by two bytes.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline void
isc_dnsbuffer_putmem_uint16be(isc_dnsbuffer_t *restrict dnsbuf,
			      const uint16_t v);
/*!<
 * \brief Append a given unsigned short (16-bit) value 'v' converted
 * into big-endian/network byte order at the end of unprocessed data
 * region of the given 'isc_dnsbuffer_t' object. Resize/reallocate the
 * internal memory buffer if it is too small to hold the appended data.
 *
 * Requires:
 *\li	'dnsbuf' is not NULL.
 */

static inline void
isc_dnsbuffer_init(isc_dnsbuffer_t *restrict dnsbuf, isc_mem_t *memctx) {
	REQUIRE(dnsbuf != NULL);
	REQUIRE(memctx != NULL);
	*dnsbuf = (isc_dnsbuffer_t){ .current = &dnsbuf->stbuf };
	isc_buffer_init(&dnsbuf->stbuf, &dnsbuf->buf[0], sizeof(dnsbuf->buf));
	isc_mem_attach(memctx, &dnsbuf->mctx);
}

static inline void
isc_dnsbuffer_uninit(isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	isc_buffer_clear(&dnsbuf->stbuf);
	if (dnsbuf->dynbuf != NULL) {
		isc_buffer_free(&dnsbuf->dynbuf);
	}

	if (dnsbuf->mctx != NULL) {
		isc_mem_detach(&dnsbuf->mctx);
	}
}

static inline isc_dnsbuffer_t *
isc_dnsbuffer_new(isc_mem_t *memctx) {
	isc_dnsbuffer_t *newbuf;

	REQUIRE(memctx != NULL);

	newbuf = isc_mem_get(memctx, sizeof(*newbuf));
	isc_dnsbuffer_init(newbuf, memctx);

	return (newbuf);
}

static inline void
isc_dnsbuffer_free(isc_dnsbuffer_t **restrict pdnsbuf) {
	isc_dnsbuffer_t *restrict buf = NULL;
	isc_mem_t *memctx = NULL;
	REQUIRE(pdnsbuf != NULL && *pdnsbuf != NULL);

	buf = *pdnsbuf;

	isc_mem_attach(buf->mctx, &memctx);
	isc_dnsbuffer_uninit(buf);
	isc_mem_putanddetach(&memctx, buf, sizeof(*buf));

	*pdnsbuf = NULL;
}

static inline void
isc_dnsbuffer_clear(isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	isc_buffer_clear(dnsbuf->current);
}

static inline unsigned int
isc_dnsbuffer_length(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	return (isc_buffer_length(dnsbuf->current));
}

static inline unsigned int
isc_dnsbuffer_usedlength(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	return (isc_buffer_usedlength(dnsbuf->current));
}

static inline unsigned int
isc_dnsbuffer_remaininglength(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	return (isc_buffer_remaininglength(dnsbuf->current));
}

static inline void
isc_dnsbuffer_remainingregion(const isc_dnsbuffer_t *restrict dnsbuf,
			      isc_region_t *region) {
	REQUIRE(dnsbuf != NULL);
	REQUIRE(region != NULL);
	isc_buffer_remainingregion(dnsbuf->current, region);
}

static inline void
isc_dnsbuffer_compact(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	isc_buffer_compact(dnsbuf->current);
}

static inline bool
isc_dnsbuffer_trycompact(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	if (isc_buffer_consumedlength(dnsbuf->current) >=
	    isc_dnsbuffer_remaininglength(dnsbuf))
	{
		isc_dnsbuffer_compact(dnsbuf);
		return (true);
	}

	return (false);
}

static inline void
isc_dnsbuffer_consume(isc_dnsbuffer_t *restrict dnsbuf, const unsigned int n) {
	REQUIRE(dnsbuf != NULL);
	isc_buffer_forward(dnsbuf->current, n);
}

static inline void
isc_dnsbuffer_putmem(isc_dnsbuffer_t *restrict dnsbuf, void *buf,
		     const unsigned int buf_size) {
	REQUIRE(dnsbuf != NULL);
	REQUIRE(buf != NULL);
	REQUIRE(buf_size > 0);
	if (!(dnsbuf->current == &dnsbuf->stbuf &&
	      isc_buffer_availablelength(dnsbuf->current) >= buf_size) &&
	    dnsbuf->dynbuf == NULL)
	{
		isc_region_t remaining = { 0 };
		unsigned int total_size = 0;

		isc_buffer_remainingregion(&dnsbuf->stbuf, &remaining);
		total_size = remaining.length + buf_size;
		if (total_size < ISC_DNSBUFFER_INITIAL_DYNAMIC_BUFFER_SIZE) {
			total_size = ISC_DNSBUFFER_INITIAL_DYNAMIC_BUFFER_SIZE;
		}
		isc_buffer_allocate(dnsbuf->mctx, &dnsbuf->dynbuf, total_size);
		isc_buffer_setautorealloc(dnsbuf->dynbuf, true);
		if (remaining.length > 0) {
			isc_buffer_putmem(dnsbuf->dynbuf, remaining.base,
					  remaining.length);
		}

		dnsbuf->current = dnsbuf->dynbuf;
	}

	isc_buffer_putmem(dnsbuf->current, buf, buf_size);
}

static inline uint8_t *
isc_dnsbuffer_current(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	return (isc_buffer_current(dnsbuf->current));
}

static inline uint16_t
isc__dnsbuffer_peek_uint16be(const isc_dnsbuffer_t *restrict dnsbuf) {
	uint16_t v;
	uint8_t *p = (uint8_t *)isc_dnsbuffer_current(dnsbuf);

	v = p[0] << 8;
	v |= p[1] & 0xFF;

	return (v);
}

static inline uint16_t
isc_dnsbuffer_peek_uint16be(const isc_dnsbuffer_t *restrict dnsbuf) {
	REQUIRE(dnsbuf != NULL);
	if (isc_dnsbuffer_remaininglength(dnsbuf) < sizeof(uint16_t)) {
		return (0);
	}

	return (isc__dnsbuffer_peek_uint16be(dnsbuf));
}

static inline uint16_t
isc_dnsbuffer_consume_uint16be(isc_dnsbuffer_t *restrict dnsbuf) {
	uint16_t v;

	REQUIRE(dnsbuf != NULL);

	if (isc_dnsbuffer_remaininglength(dnsbuf) < sizeof(uint16_t)) {
		return (0);
	}

	v = isc__dnsbuffer_peek_uint16be(dnsbuf);

	isc_dnsbuffer_consume(dnsbuf, sizeof(uint16_t));

	return (v);
}

static inline void
isc_dnsbuffer_putmem_uint16be(isc_dnsbuffer_t *restrict dnsbuf,
			      const uint16_t v) {
	uint8_t b[2] = { 0 };

	REQUIRE(dnsbuf != NULL);

	b[0] = v >> 8;
	b[1] = v & 0xFF;

	isc_dnsbuffer_putmem(dnsbuf, b, sizeof(b));
}
