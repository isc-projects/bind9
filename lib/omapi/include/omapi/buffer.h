/*
 * Copyright (C) 1996, 1997, 1998, 1999  Internet Software Consortium.
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

/*****
 ***** Definitions for the object management API protocol buffering.
 *****/

/*
 * OMAPI buffers are ring buffers, which means that the beginning of the
 * buffer and the end of the buffer chase each other around.   As long as
 * the tail never catches up to the head, there's room in the buffer for
 * data.
 *
 *	- If the tail and the head are equal, the buffer is empty.
 *
 *	- If the tail is less than the head, the contents of the buffer
 *	  are the bytes from the head to the end of buffer, and in addition,
 *	  the bytes between the beginning of the buffer and the tail, not
 *	  including the byte addressed by the tail.
 *
 *	- If the tail is greater than the head, then the buffer contains
 *	  valid bytes starting with the byte addressed by the head, and
 *	  ending with the byte before the byte addressed by the tail.
 *
 * There will always be at least one byte of waste, because the tail can't
 * increase so that it's equal to the head (that would represent an empty
 * buffer.
 */

#ifndef OMAPI_BUFFER_H
#define OMAPI_BUFFER_H 1

#include <isc/lang.h>

#include <omapi/omapip.h>

ISC_LANG_BEGINDECLS

#define OMAPI_BUFFER_SIZE 4048

typedef struct omapi_buffer {
	struct omapi_buffer *next;	/* Buffers can be chained. */
	isc_uint32_t refcnt;		/* Buffers are reference counted. */
	isc_uint16_t head, tail;	/* Buffers are organized in a ring. */
	char data[OMAPI_BUFFER_SIZE];	/* The actual buffer is included in
					   the buffer data structure. */
} omapi_buffer_t;	

#define BUFFER_BYTES_FREE(x)	\
	((x)->tail > (x)->head \
	  ? sizeof ((x)->data) - ((x)->tail - (x)->head) \
	  : (x)->head - (x)->tail)

#define BYTES_IN_BUFFER(x)	\
	((x)->tail > (x)->head \
	 ? (x)->tail - (x)->head - 1 \
	 : sizeof ((x)->data) - ((x)->head - (x)->tail) - 1)

isc_result_t
omapi_connection_require(omapi_object_t *connection, unsigned int bytes);

isc_result_t
omapi_connection_copyout(unsigned char *data, omapi_object_t *connection,
			 unsigned int length);

isc_result_t
omapi_connection_copyin(omapi_object_t *connection, unsigned char *data,
			 unsigned int length);

isc_result_t
omapi_connection_get_uint32(omapi_object_t *connection, isc_uint32_t *value);

isc_result_t
omapi_connection_put_uint32(omapi_object_t *connection, isc_uint32_t value);

isc_result_t
omapi_connection_get_uint16(omapi_object_t *connection, isc_uint16_t *value);

isc_result_t
omapi_connection_put_uint16(omapi_object_t *connection, isc_uint32_t value);

ISC_LANG_ENDDECLS

#endif /* OMAPI_BUFFER_H */
