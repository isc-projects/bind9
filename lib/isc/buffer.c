/*
 * Copyright (C) 1998  Internet Software Consortium.
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

#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>

#define VALID_BUFFER(b)			((b) != NULL)

void
isc_buffer_init(isc_buffer_t *b, unsigned char *base, unsigned int length) {
	/*
	 * Make 'b' refer to the 'length'-byte region starting at base.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(length > 0);

	b->base = base;
	b->length = length;
	b->used = 0;
	b->current = base;
}

void
isc_buffer_region(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the region of 'b'.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(r != NULL);

	r->base = b->base;
	r->length = b->length;
}

void
isc_buffer_used(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the used region of 'b'.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(r != NULL);

	r->base = b->base;
	r->length = b->used;
}

void
isc_buffer_available(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the available region of 'b'.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(r != NULL);

	r->base = b->base + b->used;
	r->length = b->length - b->used;
}


void
isc_buffer_add(isc_buffer_t *b, unsigned int n) {
	/*
	 * Increase the 'used' region of 'b' by 'n' bytes.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(b->used + n <= b->length);

	b->used += n;
}

void
isc_buffer_subtract(isc_buffer_t *b, unsigned int n) {
	/*
	 * Decrease the 'used' region of 'b' by 'n' bytes.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(b->used >= n);

	b->used -= n;
}

void
isc_buffer_clear(isc_buffer_t *b) {
	/*
	 * Make the used region empty.
	 */

	REQUIRE(VALID_BUFFER(b));
	b->used = 0;
}

void
isc_buffer_consumed(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the consumed region of 'b'.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(r != NULL);

	r->base = b->base;
	r->length = (unsigned int)(b->current - b->base);
}

void
isc_buffer_remaining(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the remaining region of 'b'.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(r != NULL);

	r->base = b->current;
	r->length = (unsigned int)((b->base + b->used) - b->current);
}

void
isc_buffer_first(isc_buffer_t *b) {
	/*
	 * Make the consumed region empty.
	 */

	REQUIRE(VALID_BUFFER(b));

	b->current = b->base;
}

void
isc_buffer_forward(isc_buffer_t *b, unsigned int n) {
	/*
	 * Decrease the 'used' region of 'b' by 'n' bytes.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(b->current + n <= b->base + b->used);

	b->current += n;
}

void
isc_buffer_back(isc_buffer_t *b, unsigned int n) {
	/*
	 * Decrease the 'consumed' region of 'b' by 'n' bytes.
	 */

	REQUIRE(VALID_BUFFER(b));
	REQUIRE(b->base + n <= b->current);

	b->current -= n;
}

void
isc_buffer_compact(isc_buffer_t *b) {
	unsigned int length;

	/*
	 * Compact the used region by moving the remaining region so it occurs
	 * at the start of the buffer.  The used region is shrunk by the size
	 * of the consumed region, and the consumed region is then made empty.
	 */

	REQUIRE(VALID_BUFFER(b));

	length = (unsigned int)((b->base + b->used) - b->current);

	(void)memmove(b->base, b->current, length);

	b->current = b->base;
	b->used = length;
}
