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
 * of the used region to the 'current' pointer.  The 'remaining' region
 * extends from one byte beyond the current pointer to the end of the used
 * region.  The size of the consumed region can be changed using various
 * buffer commands.  Initially, the consumed region is empty.
 *
 * The following invariants are maintained by all routines:
 *
 *	length > 0
 *
 *	base is a valid pointer to length bytes of memory
 *
 *	0 <= used <= length
 *
 *	base <= current <= base + used
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


/***
 *** Types
 ***/

/*
 * Note that the buffer structure is public.  This is principally so buffer
 * operations can be implemented using macros.  Applications are strongly
 * discouraged from directly manipulating the structure.
 */

typedef struct isc_buffer {
	unsigned char *	base;
	unsigned char *	current;
	unsigned int	length;
	unsigned int	used;
} isc_buffer_t;


/***
 *** Functions
 ***/


void
isc_buffer_init(isc_buffer_t *b, unsigned char *base, unsigned int length);
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
 *	current = base
 *
 */

void
isc_buffer_forward(isc_buffer_t *b, unsigned int n);
/*
 * Decrease the 'used' region of 'b' by 'n' bytes.
 *
 * Requires:
 *
 *	'b' is a valid buffer
 *
 *	current + n <= base + used
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
 *	base + n <= current
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
 *	current = base
 *
 *	The size of the used region is now equal to the size of the remaining
 *	region (as it was before the call).  The contents of the used region
 *	are those of the remaining region (as it was before the call).
 */

#endif /* ISC_BUFFER_H */
