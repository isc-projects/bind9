/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

void
isc_buffer_init(isc_buffer_t *b, void *base, unsigned int length,
		unsigned int type)
{
	/*
	 * Make 'b' refer to the 'length'-byte region starting at base.
	 */

	REQUIRE(b != NULL);

	b->magic = ISC_BUFFER_MAGIC;
	b->type = type;
	b->base = base;
	b->length = length;
	b->used = 0;
	b->current = 0;
	b->active = 0;
	b->mctx = NULL;
	ISC_LINK_INIT(b, link);
}

void
isc_buffer_invalidate(isc_buffer_t *b) {
	/*
	 * Make 'b' an invalid buffer.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(!ISC_LINK_LINKED(b, link));
	REQUIRE(b->mctx == NULL);
	
	b->magic = 0;
	b->type = 0;
	b->base = NULL;
	b->length = 0;
	b->used = 0;
	b->current = 0;
	b->active = 0;
}

unsigned int
isc_buffer_type(isc_buffer_t *b) {
	/*
	 * The type of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));

	return (b->type);
}

void
isc_buffer_region(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the region of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	r->base = b->base;
	r->length = b->length;
}

void
isc_buffer_used(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the used region of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	r->base = b->base;
	r->length = b->used;
}

void
isc_buffer_available(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the available region of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	r->base = (unsigned char *)b->base + b->used;
	r->length = b->length - b->used;
}

void
isc_buffer_add(isc_buffer_t *b, unsigned int n) {
	/*
	 * Increase the 'used' region of 'b' by 'n' bytes.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used + n <= b->length);

	b->used += n;
}

void
isc_buffer_subtract(isc_buffer_t *b, unsigned int n) {
	/*
	 * Decrease the 'used' region of 'b' by 'n' bytes.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used >= n);

	b->used -= n;
	if (b->current > b->used)
		b->current = b->used;
	if (b->active > b->used)
		b->active = b->used;
}

void
isc_buffer_clear(isc_buffer_t *b) {
	/*
	 * Make the used region empty.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));

	b->used = 0;
	b->current = 0;
	b->active = 0;
}

void
isc_buffer_consumed(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the consumed region of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	r->base = b->base;
	r->length = b->current;
}

void
isc_buffer_remaining(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the remaining region of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	r->base = (unsigned char *)b->base + b->current;
	r->length = b->used - b->current;
}

void
isc_buffer_active(isc_buffer_t *b, isc_region_t *r) {
	/*
	 * Make 'r' refer to the active region of 'b'.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	if (b->current < b->active) {
		r->base = (unsigned char *)b->base + b->current;
		r->length = b->active - b->current;
	} else {
		r->base = NULL;
		r->length = 0;
	}
}

void
isc_buffer_setactive(isc_buffer_t *b, unsigned int n) {
	unsigned int active;

	/*
	 * Sets the end of the active region 'n' bytes after current.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	active = b->current + n;
	REQUIRE(active <= b->used);

	b->active = active;
}

void
isc_buffer_first(isc_buffer_t *b) {
	/*
	 * Make the consumed region empty.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));

	b->current = 0;
}

void
isc_buffer_forward(isc_buffer_t *b, unsigned int n) {
	/*
	 * Increase the 'consumed' region of 'b' by 'n' bytes.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->current + n <= b->used);

	b->current += n;
}

void
isc_buffer_back(isc_buffer_t *b, unsigned int n) {
	/*
	 * Decrease the 'consumed' region of 'b' by 'n' bytes.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(n <= b->current);

	b->current -= n;
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

	src = (unsigned char *)b->base + b->current;
	length = b->used - b->current;
	(void)memmove(b->base, src, (size_t)length);

	if (b->active > b->current)
		b->active -= b->current;
	else
		b->active = 0;
	b->current = 0;
	b->used = length;
}

isc_uint8_t
isc_buffer_getuint8(isc_buffer_t *b) {
	unsigned char *cp;
	isc_uint8_t result;

	/*
	 * Read an unsigned 8-bit integer from 'b' and return it.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used - b->current >= 1);

	cp = b->base;
	cp += b->current;
	b->current += 1;
	result = ((unsigned int)(cp[0]));

	return (result);
}

void
isc_buffer_putuint8(isc_buffer_t *b, isc_uint8_t val)
{
	unsigned char *cp;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used + 1 <= b->length);

	cp = b->base;
	cp += b->used;
	b->used += 1;
	cp[0] = (val & 0x00ff);
}

isc_uint16_t
isc_buffer_getuint16(isc_buffer_t *b) {
	unsigned char *cp;
	isc_uint16_t result;

	/*
	 * Read an unsigned 16-bit integer in network byte order from 'b',
	 * convert it to host byte order, and return it.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used - b->current >= 2);

	cp = b->base;
	cp += b->current;
	b->current += 2;
	result = ((unsigned int)(cp[0])) << 8;
	result |= ((unsigned int)(cp[1]));

	return (result);
}

void
isc_buffer_putuint16(isc_buffer_t *b, isc_uint16_t val)
{
	unsigned char *cp;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used + 2 <= b->length);

	cp = b->base;
	cp += b->used;
	b->used += 2;
	cp[0] = (val & 0xff00) >> 8;
	cp[1] = (val & 0x00ff);
}

isc_uint32_t
isc_buffer_getuint32(isc_buffer_t *b) {
	unsigned char *cp;
	isc_uint32_t result;

	/*
	 * Read an unsigned 32-bit integer in network byte order from 'b',
	 * convert it to host byte order, and return it.
	 */

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used - b->current >= 4);

	cp = b->base;
	cp += b->current;
	b->current += 4;
	result = ((unsigned int)(cp[0])) << 24;
	result |= ((unsigned int)(cp[1])) << 16;
	result |= ((unsigned int)(cp[2])) << 8;
	result |= ((unsigned int)(cp[3]));

	return (result);
}

void
isc_buffer_putuint32(isc_buffer_t *b, isc_uint32_t val)
{
	unsigned char *cp;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used + 4 <= b->length);

	cp = b->base;
	cp += b->used;
	b->used += 4;
	cp[0] = (unsigned char)((val & 0xff000000) >> 24);
	cp[1] = (unsigned char)((val & 0x00ff0000) >> 16);
	cp[2] = (unsigned char)((val & 0x0000ff00) >> 8);
	cp[3] = (unsigned char)(val & 0x000000ff);
}

void
isc_buffer_putmem(isc_buffer_t *b, unsigned char *base, unsigned int length)
{
	unsigned char *cp;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(b->used + length <= b->length);

	cp = (unsigned char *)b->base + b->used;
	memcpy(cp, base, length);
	b->used += length;
}	

isc_result_t
isc_buffer_putstr(isc_buffer_t *b, const char *source) {
        unsigned int l;
	unsigned char *cp;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(source != NULL);

	l = strlen(source);
	if (l > (b->length - b->used))
		return (ISC_R_NOSPACE);

	cp = (unsigned char *)b->base + b->used;
	memcpy(cp, source, l);
	b->used += l;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_buffer_copyregion(isc_buffer_t *b, isc_region_t *r) {
	unsigned char *base;
	unsigned int available;

	REQUIRE(ISC_BUFFER_VALID(b));
	REQUIRE(r != NULL);

	base = (unsigned char *)b->base + b->used;
	available = b->length - b->used;
        if (r->length > available)
		return (ISC_R_NOSPACE);
	memcpy(base, r->base, r->length);
	b->used += r->length;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_buffer_allocate(isc_mem_t *mctx, isc_buffer_t **dynbuffer,
		    unsigned int length, unsigned int type)
{
	isc_buffer_t *dbuf;

	REQUIRE(dynbuffer != NULL);
	REQUIRE(*dynbuffer == NULL);

	dbuf = isc_mem_get(mctx, length + sizeof(isc_buffer_t));
	if (dbuf == NULL)
		return (ISC_R_NOMEMORY);

	isc_buffer_init(dbuf, ((unsigned char *)dbuf) + sizeof(isc_buffer_t),
			length, type);
	dbuf->mctx = mctx;

	*dynbuffer = dbuf;

	return (ISC_R_SUCCESS);
}

void
isc_buffer_free(isc_buffer_t **dynbuffer)
{
	unsigned int real_length;
	isc_buffer_t *dbuf;
	isc_mem_t *mctx;

	REQUIRE(dynbuffer != NULL);
	REQUIRE(ISC_BUFFER_VALID(*dynbuffer));
	REQUIRE((*dynbuffer)->mctx != NULL);

	dbuf = *dynbuffer;
	*dynbuffer = NULL;	/* destroy external reference */

	real_length = dbuf->length + sizeof(isc_buffer_t);
	mctx = dbuf->mctx;
	dbuf->mctx = NULL;
	isc_buffer_invalidate(dbuf);

	isc_mem_put(mctx, dbuf, real_length);
}
