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
 *  /----- used region -----\/-- available --\
 *  +----------------------------------------+
 *  | consumed  | remaining |                |
 *  +----------------------------------------+
 *  a           b     c     d                e
 *
 * a == base of buffer.
 * b == current pointer.  Can be anywhere between a and d.
 * c == active pointer.  Meaningful between b and d.
 * d == used pointer.
 * e == length of buffer.
 *
 * a-e == entire (length) of buffer.
 * a-d == used region.
 * a-b == consumed region.
 * b-d == remaining region.
 * b-c == optional active region.
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
 *	(although active < current implies empty active region)
 *
 * MP:
 *	Buffers have no synchronization.  Clients must ensure exclusive
 *	access.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	Memory: 1 pointer + 6 unsigned integers per buffer.
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

#include <isc/lang.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/int.h>

ISC_LANG_BEGINDECLS

/***
 *** Magic numbers
 ***/
#define ISC_BUFFER_MAGIC		0x42756621U	/* Buf!. */

#define ISC_BUFFER_VALID(b)		((b) != NULL && \
					 (b)->magic == ISC_BUFFER_MAGIC)

/*
 * The following macros MUST be used only on valid buffers.  It is the
 * caller's responsibility to ensure this by using the ISC_BUFFER_VALID
 * check above, or by calling another isc_buffer_*() function (rather than
 * another macro.)
 */

/*
 * Get the length of the used region of buffer "b"
 */
#define ISC_BUFFER_USEDCOUNT(b)		((b)->used)

/*
 * Get the length of the available region of buffer "b"
 */
#define ISC_BUFFER_AVAILABLECOUNT(b)	((b)->length - (b)->used)

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

typedef struct isc_buffer isc_buffer_t;
struct isc_buffer {
	unsigned int		magic;
	unsigned int		type;
	void		       *base;
	/* The following integers are byte offsets from 'base'. */
	unsigned int		length;
	unsigned int		used;
	unsigned int 		current;
	unsigned int 		active;
	/* linkable */
	ISC_LINK(isc_buffer_t)	link;
	/* private internal elements */
	isc_mem_t	       *mctx;
};

/***
 *** Functions
 ***/

isc_result_t
isc_buffer_allocate(isc_mem_t *mctx, isc_buffer_t **dynbuffer,
		    unsigned int length, unsigned int type);
/*
 * Allocate a dynamic linkable buffer which has "length" bytes in the
 * data region.
 *
 * Requires:
 *	"mctx" is valid.
 *
 *	"dynbuffer" is non-NULL, and "*dynbuffer" is NULL.
 *
 * Returns:
 *	ISC_R_SUCCESS		- success
 *	ISC_R_NOMEMORY		- no memory available
 *
 * Note:
 *	Changing the buffer's length field is not permitted.
 */

void
isc_buffer_free(isc_buffer_t **dynbuffer);
/*
 * Release resources allocated for a dynamic buffer.
 *
 * Requires:
 *	"dynbuffer" is not NULL.
 *
 *	"*dynbuffer" is a valid dynamic buffer.
 *
 * Ensures:
 *	"*dynbuffer" will be NULL on return, and all memory associated with
 *	the dynamic buffer is returned to the memory context used in
 *	isc_buffer_allocate().
 */

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

isc_uint8_t
isc_buffer_getuint8(isc_buffer_t *b);
/*
 * Read an unsigned 8-bit integer from 'b' and return it.
 *
 * Requires:
 *
 *	'b' is a valid buffer.
 *
 *	The length of the available region of 'b' is at least 1.
 *
 * Ensures:
 *
 *	The current pointer in 'b' is advanced by 1.
 *
 * Returns:
 *
 *	A 8-bit unsigned integer.
 */

void
isc_buffer_putuint8(isc_buffer_t *b, isc_uint8_t val);
/*
 * Store an unsigned 8-bit integer from 'val' into 'b'.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 *	The length of the unused region of 'b' is at least 1.
 *
 * Ensures:
 *	The used pointer in 'b' is advanced by 1.
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

void
isc_buffer_putuint16(isc_buffer_t *b, isc_uint16_t val);
/*
 * Store an unsigned 16-bit integer in host byte order from 'val'
 * into 'b' in network byte order.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 *	The length of the unused region of 'b' is at least 2.
 *
 * Ensures:
 *	The used pointer in 'b' is advanced by 2.
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

void
isc_buffer_putuint32(isc_buffer_t *b, isc_uint32_t val);
/*
 * Store an unsigned 32-bit integer in host byte order from 'val'
 * into 'b' in network byte order.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 *	The length of the unused region of 'b' is at least 4.
 *
 * Ensures:
 *	The used pointer in 'b' is advanced by 4.
 */

void
isc_buffer_putmem(isc_buffer_t *b, unsigned char *base, unsigned int length);
/*
 * Copy 'length' bytes of memory at 'base' into 'b'.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 *	'base' points to 'length' bytes of valid memory.
 *
 */

isc_result_t
isc_buffer_putstr(isc_buffer_t *b, const char *source);
/*
 * Copy 'length' bytes of memory at 'base' into 'b'.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 *	'source' to be a valid NULL terminated string.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOSPACE			The available region of 'b' is not
 *					big enough.
 */

isc_result_t
isc_buffer_copyregion(isc_buffer_t *b, isc_region_t *r);
/*
 * Copy the contents of 'r' into 'b'.
 *
 * Requires:
 *	'b' is a valid buffer.
 *
 *	'r' is a valid region.
 *
 * Returns:
 *
 *	ISC_R_SUCCESS
 *	ISC_R_NOSPACE			The available region of 'b' is not
 *					big enough.
 */


ISC_LANG_ENDDECLS

#endif /* ISC_BUFFER_H */
