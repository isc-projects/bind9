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

#define ISC_MEM_DEBUG 1

#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>

#include <omapi/omapip.h>
#include <omapi/result.h>

ISC_LANG_BEGINDECLS

#define OMAPI_OP_OPEN		1
#define OMAPI_OP_REFRESH	2
#define	OMAPI_OP_UPDATE		3
#define OMAPI_OP_NOTIFY		4
#define OMAPI_OP_STATUS		5
#define OMAPI_OP_DELETE		6

#define OMAPI_BUFFER_SIZE 4096

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
	isc_socket_t			*socket; /* Connection socket. */
	isc_task_t			*task;
	unsigned int			events_pending;
	omapi_connection_state_t	state;
	isc_sockaddr_t			remote_addr;
	isc_sockaddr_t			local_addr;
	/*
	 * Bytes of input needed before wakeup.
	 */
	isc_uint32_t			bytes_needed;
	/*
	 * Bytes of input already buffered.
	 * XXXDCL isc_bufferlist_available() instead?
	 */
	isc_uint32_t			in_bytes;
	/*
	 * Input buffers.
	 */
	isc_bufferlist_t		input_buffers;
	/*
	 * Bytes of output in buffers.
	 */
	isc_uint32_t			out_bytes;
	isc_bufferlist_t		output_buffers;
	/*
	 * Listener that accepted this connection.
	 * XXXDCL This appears to not be needed.
	 */
	omapi_object_t *		listener;
} omapi_connection_object_t;

typedef struct omapi_generic_object {
	OMAPI_OBJECT_PREAMBLE;
	omapi_value_t **	values;
	int			nvalues;
	int			va_max;
} omapi_generic_object_t;

/*
 * Everything needs a memory context.  This will likely be made a parameter
 * where needed rather than a single global context. XXXDCL
 */
extern isc_mem_t *omapi_mctx;

/*
 * XXXDCL comment, localize?
 */
extern isc_taskmgr_t *omapi_taskmgr;

/*
 * XXXDCL comment, localize?
 */
extern isc_timermgr_t *omapi_timermgr;

/*
 * XXXDCL comment, localize?
 */
extern isc_socketmgr_t *omapi_socketmgr;

extern isc_boolean_t omapi_ipv6;

void
connection_send(omapi_connection_object_t *connection);

#define OBJECT_REF(objectp, object, where) \
	omapi_object_reference((omapi_object_t **)objectp, \
			       (omapi_object_t *)object, where)

#define OBJECT_DEREF(objectp, where) \
	omapi_object_dereference((omapi_object_t **)objectp, where)

#define PASS_CHECK(object, function) \
	(object->inner != NULL && object->inner->type->function != NULL)

#define PASS_GETVALUE(object) \
     do { \
	if (PASS_CHECK(object, get_value)) \
		return (*(object->inner->type->get_value))(object->inner, \
							   id, name, value); \
	else \
		return (ISC_R_NOTFOUND); \
     } while (0)

#define PASS_SETVALUE(object) \
     do { \
	if (PASS_CHECK(object, set_value)) \
		return (*(object->inner->type->set_value))(object->inner, \
							   id, name, value); \
	else \
		return (ISC_R_NOTFOUND); \
     } while (0)

#define PASS_SIGNAL(object) \
     do { \
	if (PASS_CHECK(object, signal_handler)) \
		return (*(object->inner->type->signal_handler))(object->inner,\
								name, ap); \
	else \
		return (ISC_R_NOTFOUND); \
     } while (0)

#define PASS_STUFFVALUES(object) \
     do { \
	if (PASS_CHECK(object, stuff_values)) \
		return (*(object->inner->type->stuff_values))(connection, id, \
							      object->inner); \
	else \
		return (ISC_R_SUCCESS); \
     } while (0)

ISC_LANG_ENDDECLS

#endif /* OMAPIP_OMAPIP_P_H */
