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

#ifndef OMAPI_PRIVATE_H
#define OMAPI_PRIVATE_H

#include <config.h>

#include <isc/condition.h>
#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/net.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/timer.h>

#include <omapi/omapi.h>
#include <omapi/result.h>

ISC_LANG_BEGINDECLS

#define OMAPI_BUFFER_SIZE 4096

/*
 * Types shared among multiple library files.
 */
typedef struct omapi_generic	omapi_generic_t;
typedef struct omapi_message	omapi_message_t;
typedef struct omapi_connection	omapi_connection_t;
typedef struct omapi_protocol	omapi_protocol_t;

typedef enum {
	omapi_connection_unconnected,
	omapi_connection_connecting,
	omapi_connection_connected,
	omapi_connection_disconnecting,
	omapi_connection_closed
} omapi_connection_state_t;

typedef enum {
	omapi_protocol_intro_wait,
	omapi_protocol_header_wait,
	omapi_protocol_signature_wait,
	omapi_protocol_name_wait,
	omapi_protocol_name_length_wait,
	omapi_protocol_value_wait,
	omapi_protocol_value_length_wait
} omapi_protocol_state_t;

/*
 * OMAPI data types.
 */

struct omapi_data {
#define OMAPI_DATA_HEADER_LEN (sizeof(int) + sizeof(omapi_datatype_t))
	int 			refcnt;
	omapi_datatype_t 	type;

	union {
		/*
		 * OMAPI_DATA_NOBUFFER_LEN purposefully does not
		 * include the 'value' byte, which only serves as a
		 * handle to memory allocated for (usually) more than
		 * one byte that begins at the 'value' location.
		 */
#define OMAPI_DATA_NOBUFFER_LEN (OMAPI_DATA_HEADER_LEN + sizeof(int))
		struct {
			unsigned int	len;
			unsigned char	value[1];
		} buffer;

#define OMAPI_DATA_OBJECT_LEN \
			(OMAPI_DATA_HEADER_LEN + sizeof(omapi_object_t *))
		omapi_object_t		*object;

#define OMAPI_DATA_INT_LEN (OMAPI_DATA_HEADER_LEN + sizeof(int))
		int 			integer;
	} u;
};

struct omapi_string {
	/*
	 * OMAPI_STRING_EMPTY_SIZE purposefully does not
	 * include the 'value' byte, which only serves as a
	 * handle to memory allocated for (usually) more than
	 * one byte that begins at the 'value' location.
	 */
#define OMAPI_STRING_EMPTY_SIZE (2 * sizeof(int))
	int 		refcnt;
	unsigned int	len;
	unsigned char	value[1];
};

struct omapi_value {
	int 			refcnt;
	omapi_string_t *	name;
	omapi_data_t *		value;
};

struct omapi_generic {
	OMAPI_OBJECT_PREAMBLE;
	omapi_value_t **		values;
	unsigned int			nvalues;
	unsigned int			va_max;
};

struct omapi_message {
	OMAPI_OBJECT_PREAMBLE;
	omapi_message_t *		next;
	omapi_message_t *		prev;
	omapi_object_t *		object;
	omapi_object_t *		notify_object;
	isc_uint32_t			authlen;
	omapi_data_t *			authenticator;
	isc_uint32_t 			authid;
	isc_uint32_t			op;
	omapi_handle_t			h;
	isc_uint32_t			id;
	isc_uint32_t			rid;
};

struct omapi_connection {
	OMAPI_OBJECT_PREAMBLE;
	isc_mutex_t			mutex;
	isc_mutex_t			recv_lock;
	isc_socket_t			*socket; /* Connection socket. */
	isc_task_t			*task;
	unsigned int			events_pending;	/* socket events */
	unsigned int			messages_expected;
	isc_boolean_t			waiting;
	isc_condition_t			waiter;	/* connection_wait() */
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
	isc_boolean_t			is_client;
};

struct omapi_protocol {
	OMAPI_OBJECT_PREAMBLE;
	isc_uint32_t			header_size;		
	isc_uint32_t			protocol_version;
	isc_uint32_t			next_xid;
	omapi_object_t *		authinfo;	/* Default authinfo. */
	omapi_protocol_state_t		state;		/* Input state. */
	isc_boolean_t			reading_message_values;
	omapi_message_t *		message;	/* Incoming message. */
	omapi_string_t *		name;		/* Incoming name. */
	omapi_data_t *			value;		/* Incoming value. */
};

/*****
 ***** Private Global Library Variables.
 *****/
extern omapi_objecttype_t *omapi_type_connection;
extern omapi_objecttype_t *omapi_type_listener;
extern omapi_objecttype_t *omapi_type_generic;
extern omapi_objecttype_t *omapi_type_protocol;
extern omapi_objecttype_t *omapi_type_message;
extern omapi_objecttype_t *omapi_object_types;

/*
 * Everything needs a memory context. 
 */
extern isc_mem_t *omapi_mctx;

/*
 * XXXDCL comment, localize?
 */
extern isc_taskmgr_t *omapi_taskmgr;

/*
 * XXXDCL comment, localize?
 */
extern isc_socketmgr_t *omapi_socketmgr;

/*
 * Is IPv6 in use?  Need to know when making connections to servers.
 */
extern isc_boolean_t omapi_ipv6;

/*****
 ***** Convenience macros.
 *****/
#define OBJECT_REF(objectp, object) \
	omapi_object_reference((omapi_object_t **)objectp, \
			       (omapi_object_t *)object)

#define OBJECT_DEREF(objectp) \
	omapi_object_dereference((omapi_object_t **)objectp)

#define PASS_CHECK(object, function) \
	(object->inner != NULL && object->inner->type->function != NULL)

/*
 * Private library functions defined in connection.c.
 */
isc_result_t
connection_init(void);

isc_result_t
connect_toserver(omapi_object_t *connection, const char *server, int port);

void
connection_send(omapi_connection_t *connection);

isc_result_t
connection_wait(omapi_object_t *connection_handle, isc_time_t *timeout);

isc_result_t
connection_require(omapi_connection_t *connection, unsigned int bytes);

void
connection_copyout(unsigned char *data, omapi_connection_t *connection,
		   unsigned int length);

void
connection_getuint32(omapi_connection_t *c, isc_uint32_t *value);

void
connection_getuint16(omapi_connection_t *c, isc_uint16_t *value);

/*
 * Private library functions defined in generic.c.
 */
isc_result_t
generic_init(void);

/*
 * Private functions defined in handle.c.
 */
isc_result_t
object_gethandle(omapi_handle_t *handle, omapi_object_t *object);

isc_result_t
handle_lookup(omapi_object_t **object, omapi_handle_t handle);

/*
 * Private library functions defined in listener.c.
 */
isc_result_t
listener_init(void);

/*
 * Private library functions defined in message.c.
 */
isc_result_t
message_init(void);

isc_result_t
message_process(omapi_object_t *message, omapi_object_t *protocol);

/*
 * Private library functions defined in object.c.
 */
isc_result_t
object_signal(omapi_object_t *handle, const char *name, ...);

isc_result_t
object_vsignal(omapi_object_t *handle, const char *name, va_list ap);

isc_result_t
object_stuffvalues(omapi_object_t *handle, omapi_object_t *object);

isc_result_t
object_update(omapi_object_t *object, omapi_object_t *source,
	      omapi_handle_t handle);

omapi_objecttype_t *
object_findtype(omapi_value_t *tv);

isc_result_t
object_methodlookup(omapi_objecttype_t *type, omapi_object_t **object,
		    omapi_object_t *key);

isc_result_t
object_methodcreate(omapi_objecttype_t *type, omapi_object_t **object);

isc_result_t
object_methodremove(omapi_objecttype_t *type, omapi_object_t *object);

void
object_destroytypes(void);

/*
 * Private library functions defined in protocol.c.
 */
isc_result_t
protocol_init(void);

isc_result_t
send_intro(omapi_object_t *object, unsigned int version);

isc_result_t
send_status(omapi_object_t *protcol, isc_result_t waitstatus,
	    unsigned int response_id, const char *message);

isc_result_t
send_update(omapi_object_t *protocol, unsigned int response_id,
	    omapi_object_t *object);

ISC_LANG_ENDDECLS

#endif /* OMAPIP_PRIVATE_H */
