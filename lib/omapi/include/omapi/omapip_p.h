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
 ***** Private master include file for the OMAPI library.
 *****/

#ifndef OMAPI_OMAPIP_P_H
#define OMAPI_OMAPIP_P_H

#include <isc/lang.h>
#include <isc/net.h>
#include <isc/result.h>

#include <omapi/omapip.h>
#include <omapi/buffer.h>
#include <omapi/alloc.h>

ISC_LANG_BEGINDECLS

#define OMAPI_OP_OPEN		1
#define OMAPI_OP_REFRESH	2
#define	OMAPI_OP_UPDATE		3
#define OMAPI_OP_NOTIFY		4
#define OMAPI_OP_STATUS		5
#define OMAPI_OP_DELETE		6

typedef enum {
	omapi_connection_unconnected,
	omapi_connection_connecting,
	omapi_connection_connected,
	omapi_connection_disconnecting,
	omapi_connection_closed
} omapi_connection_state_t;

typedef struct omapi_message_object {
	OMAPI_OBJECT_PREAMBLE;
	struct omapi_message_object *	next;
	struct omapi_message_object *	prev;
	omapi_object_t *		object;
	omapi_object_t *		notify_object;
	unsigned int			authlen;
	omapi_typed_data_t *		authenticator;
	unsigned int 			authid;
	omapi_object_t *		id_object;
	unsigned int			op;
	omapi_handle_t			h;
	unsigned int			id;
	unsigned int			rid;
} omapi_message_object_t;

typedef struct omapi_connection_object {
	OMAPI_OBJECT_PREAMBLE;
	int				socket; /* Connection socket. */
	omapi_connection_state_t	state;
	struct sockaddr_in		remote_addr;
	struct sockaddr_in		local_addr;
	/*
	 * Bytes of input needed before wakeup.
	 */
	isc_uint32_t			bytes_needed;
	/*
	 * Bytes of input already buffered.
	 */
	isc_uint32_t			in_bytes;
	omapi_buffer_t *		inbufs;
	/*
	 * Bytes of output in buffers.
	 */
	isc_uint32_t			out_bytes;
	omapi_buffer_t *		outbufs;
	/*
	 * Listener that accepted this connection.
	 */
	omapi_object_t *		listener;
} omapi_connection_object_t;

typedef struct omapi_generic_object {
	OMAPI_OBJECT_PREAMBLE;
	omapi_value_t **	values;
	int			nvalues;
	int			va_max;
} omapi_generic_object_t;

ISC_LANG_ENDDECLS

#endif /* OMAPIP_OMAPIP_P_H */
