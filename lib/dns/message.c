/*
 * Copyright (C) 1999  Internet Software Consortium.
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

/***
 *** Imports
 ***/

#include <config.h>

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>

#include <dns/message.h>
#include <dns/rdataset.h>

#define MESSAGE_MAGIC		0x4d534740U	/* MSG@ */
#define VALID_MESSAGE_MAGIC(magic)  ((magic) == MESSAGE_MAGIC)

static inline void
dns_msgblock_free(isc_mem_t *, dns_msgblock_t *);
#define dns_msgblock_get(block, type) \
	((type *)dns_msgblock__get(block, sizeof(type)))

static inline void *
dns_msgblock__get(dns_msgblock_t *, unsigned int);

static inline dns_msgblock_t *
dns_msgblock_allocate(isc_mem_t *, unsigned int, unsigned int);

/*
 * Allocate a new dns_msgblock_t, and return a pointer to it.  If no memory
 * is free, return NULL.
 */
static inline dns_msgblock_t *
dns_msgblock_allocate(isc_mem_t *mctx, unsigned int sizeof_type,
		      unsigned int count)
{
	dns_msgblock_t *block;
	unsigned int length;

	length = sizeof(dns_msgblock_t) + (sizeof_type * count);

	block = isc_mem_get(mctx, length);
	if (block == NULL)
		return NULL;

	block->length = length;
	block->remaining = count;

	ISC_LINK_INIT(block, link);

	return (block);
}

/*
 * Return an element from the msgblock.  If no more are available, return
 * NULL.
 */
static inline void *
dns_msgblock__get(dns_msgblock_t *block, unsigned int sizeof_type)
{
	void *ptr;

	if (block->remaining == 0)
		return (NULL);

	block->remaining--;

	ptr = (((unsigned char *)block)
	       + sizeof(dns_msgblock_t)
	       + (sizeof_type * block->remaining));

	return (ptr);
}

/*
 * Release memory associated with a message block.
 */
static inline void
dns_msgblock_free(isc_mem_t *mctx, dns_msgblock_t *block)
{
	isc_mem_put(mctx, block, block->length);
}
