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

#ifndef ISC_BUFFER_H
#define ISC_BUFFER_H 1

/*****
 ***** Module Info
 *****/

/*
 * Buffers
 *
 * A buffer is a region of memory, together with a set of related subregions.
 * Buffers are used for parsing and I/O operations.
 *
 * The 'used region' and the 'available' region are disjoint, and their
 * union is the buffer's region.  The used region extends from the beginning
 * of the buffer region to the last used byte.  The available region
 * extends from one byte greater than the last used byte to the end of the
 * buffer's region.  The size of the used region can be changed using various
 * buffer commands.  Initially, the used region is empty.
 *
 * The used region is further subdivided into two disjoint regions: the
 * 'consumed region' and the 'remaining region'.  The union of these two
 * regions is the used region.  The consumed region extends from the beginning
 * of the used region to the byte before the 'current' offset (if any).  The
 * 'remaining' region the current pointer to the end of the used
 * region.  The size of the consumed region can be changed using various
 * buffer commands.  Initially, the consumed region is empty.
 *
 * The 'active region' is an (optional) subregion of the remaining region.
 * It extends from the current offset to an offset in the remaining region
 * that is selected with isc_buffer_setactive().  Initially, the active region
 * is empty.  If the current offset advances beyond the chosen offset, the
 * active region will also be empty.
 *
 * The following invariants are maintained by all routines:
 *
 *	length > 0
 *
 *	base is a valid pointer to length bytes of memory
 *
 *	0 <= used <= length
 *
 *	0 <= current <= used
 *
 *	0 <= active <= used
 *
 * MP:
 *	Buffers have no synchronization.  Clients must ensure exclusive
 *	access.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	Memory: 2 pointers + 2 unsigned integers per buffer.
 *
 * Security:
 *	No anticipated impact.
 *
 * Standards:
 *	None.
 */

/***
 *** Imports
 ***/

#include <isc/region.h>
#include <isc/int.h>

/***
 *** Types
 ***/

#define ISC_BUFFERTYPE_GENERIC			0
#define ISC_BUFFERTYPE_BINARY			1
#define ISC_BUFFERTYPE_TEXT			2

/* Types >= 1024 are reserved for application use. */

/*
 * Note that the buffer structure is public.  This is principally so buffer
 * operations can be implemented using macros.  Applications are strongly
 * discouraged from directly manipulating the structure.
 */

typedef struct isc_buffer {
	unsigned int	magic;
	unsigned int	type;
	void *		base;
	/* The following integers are byte offsets from 'base'. */
	unsigned int	length;
	unsigned int	used;
	unsigned int 	current;
	unsigned int 	active;
} isc_buffer_t;


/***
 *** Functions
 ***/


void
isc_buffer_init(isc_buffer_t *b, void *base, unsigned int length,
		unsigned int type);
/*
 * Make 'b' refer to the 'length'-byte region starting at base.
 *
 * Requires:
 *
 *	'length' > 0
 *
 *	'base' is a pointer to a sequence of 'length' bytes.
 *
 */

void
isc_buffer_invalidate(isc_buffer_t *b);
/*
 * Make 'b' an invalid buffer.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 * Ensures:
 *	If assertion checking is enabled, future attempts to use 'b' without
 *	calling isc_buffer_init() on it will cause an assertion failure.
 */
		
unsigned int
isc_buffer_type(isc_buffer_t *b);
/*
 * The type of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 * Returns:
 *
 *	The type of 'b'.
 */
			
void
isc_buffer_region(isc_buffer_t *b, isc_region_t *r);
/*
 * Make 'r' refer to the region of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	'r' points to a region structure.
 */

void
isc_buffer_used(isc_buffer_t *b, isc_region_t *r);
/*
 * Make 'r' refer to the used region of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	'r' points to a region structure.
 */

void
isc_buffer_available(isc_buffer_t *b, isc_region_t *r);
/*
 * Make 'r' refer to the available region of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	'r' points to a region structure.
 */

void
isc_buffer_add(isc_buffer_t *b, unsigned int n);
/*
 * Increase the 'used' region of 'b' by 'n' bytes.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 *	used + n <= length
 *
 */

void
isc_buffer_subtract(isc_buffer_t *b, unsigned int n);
/*
 * Decrease the 'used' region of 'b' by 'n' bytes.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 *	used >= n
 *
 */

void
isc_buffer_clear(isc_buffer_t *b);
/*
 * Make the used region empty.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 * Ensures:
 *
 *	used = 0
 *
 */

void
isc_buffer_consumed(isc_buffer_t *b, isc_region_t *r);
/*
 * Make 'r' refer to the consumed region of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	'r' points to a region structure.
 */

void
isc_buffer_remaining(isc_buffer_t *b, isc_region_t *r);
/*
 * Make 'r' refer to the remaining region of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	'r' points to a region structure.
 */

void
isc_buffer_active(isc_buffer_t *b, isc_region_t *r);
/*
 * Make 'r' refer to the active region of 'b'.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	'r' points to a region structure.
 */

void
isc_buffer_setactive(isc_buffer_t *b, unsigned int n);
/*
 * Sets the end of the active region 'n' bytes after current.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	current + n <= used
 */

void
isc_buffer_first(isc_buffer_t *b);
/*
 * Make the consumed region empty.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 * Ensures:
 *
 *	current == 0
 *
 */

void
isc_buffer_forward(isc_buffer_t *b, unsigned int n);
/*
 * Increase the 'consumed' region of 'b' by 'n' bytes.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 *	current + n <= used
 *
 */

void
isc_buffer_back(isc_buffer_t *b, unsigned int n);
/*
 * Decrease the 'consumed' region of 'b' by 'n' bytes.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 *	n <= current
 *
 */

void
isc_buffer_compact(isc_buffer_t *b);
/*
 * Compact the used region by moving the remaining region so it occurs
 * at the start of the buffer.  The used region is shrunk by the size of
 * the consumed region, and the consumed region is then made empty.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 * Ensures:
 *
 *	current == 0
 *
 *	The size of the used region is now equal to the size of the remaining
 *	region (as it was before the call).  The contents of the used region
 *	are those of the remaining region (as it was before the call).
 */

isc_uint16_t
isc_buffer_getuint16(isc_buffer_t *b);
/*
 * Read an unsigned 16-bit integer in network byte order from 'b', convert
 * it to host byte order, and return it.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	The length of the available region of 'b' is at least 2.
 *
 * Ensures:
 *
 *	The current pointer in 'b' is advanced by 2.
 *
 * Returns:
 *
 *	A 16-bit unsigned integer.
 */

isc_uint32_t
isc_buffer_getuint32(isc_buffer_t *b);
/*
 * Read an unsigned 32-bit integer in network byte order from 'b', convert
 * it to host byte order, and return it.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	The length of the available region of 'b' is at least 2.
 *
 * Ensures:
 *
 *	The current pointer in 'b' is advanced by 2.
 *
 * Returns:
 *
 *	A 32-bit unsigned integer.
 */

#endif /* ISC_BUFFER_H */
