/*
 * Copyright (C) 1996-2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: private.h,v 1.25 2000/08/26 01:56:46 bwelling Exp $ */

/*****
 ***** Private master include file for the OMAPI library.
 *****/

#ifndef OMAPI_PRIVATE_H
#define OMAPI_PRIVATE_H 1

#include <isc/condition.h>
#include <isc/lang.h>
#include <isc/mutex.h>
#include <isc/socket.h>

#include <dst/dst.h>

#include <omapi/omapi.h>

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
	/*
	 * The wait lock is necessary to ensure that connection_wait is
	 * blocking for the signal before any event is received that might
	 * potentially free the connection.  This ensures that end_connection
	 * will unblock connection_wait so that connection_wait can free
	 * the connection.
	 *
	 * Consider, for example, the problem that send_intro has without
	 * this lock.  It first needs to call connection_require to start
	 * a recv task to get the server's intro.  Then it needs to send
	 * the intro itself.  One sample problem that can then arise from
	 * this is that the recv task completes before the wait is established
	 * and it triggers an error, such as an premature EOF or an unsupported
	 * version number in the header.  The client would have no way of
	 * knowing an error occurred.
	 *
	 * Fortunately, there is no such problem in the server.  Since all
	 * uses of the connection object happen from the socket thread,
	 * no function will continue to use a connection object after there
	 * has been an error on it, no other event can be posted until the
	 * current event handler is done, and all events subsequent to
	 * abandoning the connection will be ISC_R_CANCELED, so the event
	 * handlers will not try to use the connection object.
	 *
	 * XXXDCL the above comments are somewhat out of date.
	 */
	isc_mutex_t			wait_lock;
	isc_socket_t			*socket;
	isc_task_t			*task;
	/*
	 * The error that caused the connection to be freed.
	 */
	isc_result_t			result;
	/*
	 * Number of socket events outstanding.  This should always be
	 * either 0 or 1 under the current model; having any more than
	 * one event pending at any given time complicates the thread
	 * locking issues.
	 */
	unsigned int			events_pending;
	/*
	 * Blocks connection_wait until the outstanding event completes.
	 */
	isc_condition_t			waiter;
	/*
	 * True if connection_wait is blocking on the water condition variable.
	 */
	isc_boolean_t			waiting;
	omapi_connection_state_t	state;
	/*
	 * These are set when a connection is made, but not currently used.
	 */
	isc_sockaddr_t			remote_addr;
	isc_sockaddr_t			local_addr;
	/*
	 * Bytes of input needed before wakeup.
	 */
	isc_uint32_t			bytes_needed;
	/*
	 * Bytes of input already buffered.
	 * XXXDCL use isc_bufferlist_available() instead?
	 */
	isc_uint32_t			in_bytes;
	isc_bufferlist_t		input_buffers;
	/*
	 * Bytes of output in output buffers.
	 */
	isc_uint32_t			out_bytes;
	isc_bufferlist_t		output_buffers;
	/*
	 * True if the connection was created by omapi_protocol_connect.
	 */
	isc_boolean_t			is_client;
	/*
	 * The listener that accepted the connection.
	 * XXXDCL (Means is_client is false, making is_client is somewhat
	 * redundant.)
	 */
	omapi_object_t *		listener;
	/*
	 * The server links known connections in a list at the connections
	 * member of the omapi_listener_t struct.
	 */
	ISC_LINK(omapi_connection_t)	link;
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
	/*
	 * Authentication information.
	 */
	char *				authname;
	unsigned int			algorithm;
	isc_boolean_t			dst_update;
	dst_key_t			*key;
	dst_context_t			*dstctx;
	isc_region_t			signature_in;
	isc_buffer_t			*signature_out;
	isc_result_t			verify_result;
	/*
	 * A callback to find out whether a requested key is valid on
	 * the connection, and the arg the caller wants to help it decide.
	 * Only gets set on the server side.
	 */
	isc_boolean_t	 ((*verify_key)(const char *name,
					unsigned int algorithm,
					void *key_arg));
	void *				verify_key_arg;
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
 * Task to keep the omapi_taskmgr alive until omapi_lib_destroy is called.
 */
extern isc_task_t *omapi_task;

/*
 * XXXDCL comment, localize?
 */
extern isc_taskmgr_t *omapi_taskmgr;

/*
 * XXXDCL comment, localize?
 */
extern isc_socketmgr_t *omapi_socketmgr;

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

ISC_LANG_BEGINDECLS

/*
 * Private library functions defined in auth.c.
 */
#define auth_destroy omapi__auth_destroy
void
auth_destroy(void);

#define auth_makekey omapi__auth_makekey
isc_result_t
auth_makekey(const char *name, unsigned int algorithm, dst_key_t **key);

/*
 * Private library functions defined in connection.c.
 */
#define connection_init omapi__connection_init
isc_result_t
connection_init(void);

#define connect_toserver omapi__connect_toserver
isc_result_t
connect_toserver(omapi_object_t *connection, const char *server,
		 in_port_t port);

#define connection_send omapi__connection_send
isc_result_t
connection_send(omapi_connection_t *connection);

#define connection_require omapi__connection_require
isc_result_t
connection_require(omapi_connection_t *connection, unsigned int bytes);

#define connection_copyout omapi__connection_copyout
void
connection_copyout(unsigned char *data, omapi_connection_t *connection,
		   unsigned int length);

#define connection_getuint32 omapi__connection_getuint32
void
connection_getuint32(omapi_connection_t *c, isc_uint32_t *value);

#define connection_getuint16 omapi__connection_getuint16
void
connection_getuint16(omapi_connection_t *c, isc_uint16_t *value);

/*
 * Private library functions defined in generic.c.
 */
#define generic_init omapi__generic_init
isc_result_t
generic_init(void);

/*
 * Private functions defined in handle.c.
 */
#define object_gethandle omapi__object_gethandle
isc_result_t
object_gethandle(omapi_handle_t *handle, omapi_object_t *object);

#define handle_lookup omapi__handle_lookup
isc_result_t
handle_lookup(omapi_object_t **object, omapi_handle_t handle);

#define handle_destroy omapi__handle_destroy
void
handle_destroy(void);

/*
 * Private library functions defined in listener.c.
 */
#define listener_init omapi__listener_init
isc_result_t
listener_init(void);

/*
 * Private library functions defined in message.c.
 */
#define message_init omapi__message_init
isc_result_t
message_init(void);

#define message_process omapi__message_process
isc_result_t
message_process(omapi_object_t *message, omapi_object_t *protocol);

/*
 * Private library functions defined in object.c.
 */
#define object_signal omapi__object_signal
isc_result_t
object_signal(omapi_object_t *handle, const char *name, ...);

#define object_vsignal omapi__object_vsignal
isc_result_t
object_vsignal(omapi_object_t *handle, const char *name, va_list ap);

#define object_stuffvalues omapi__object_stuffvalues
isc_result_t
object_stuffvalues(omapi_object_t *handle, omapi_object_t *object);

#define object_update omapi__object_update
isc_result_t
object_update(omapi_object_t *object, omapi_object_t *source,
	      omapi_handle_t handle);

#define object_findtype omapi__object_findtype
omapi_objecttype_t *
object_findtype(omapi_value_t *tv);

#define object_methodlookup omapi__object_methodlookup
isc_result_t
object_methodlookup(omapi_objecttype_t *type, omapi_object_t **object,
		    omapi_object_t *key);

#define object_methodcreate omapi__object_methodcreate
isc_result_t
object_methodcreate(omapi_objecttype_t *type, omapi_object_t **object);

#define object_methodexpunge omapi__object_methodexpunge
isc_result_t
object_methodexpunge(omapi_objecttype_t *type, omapi_object_t *object);

#define object_destroytypes omapi__object_destroytypes
void
object_destroytypes(void);

/*
 * Private library functions defined in protocol.c.
 */
#define protocol_init omapi__protocol_init
isc_result_t
protocol_init(void);

#define send_intro omapi__send_intro
isc_result_t
send_intro(omapi_object_t *object, unsigned int version);

#define send_status omapi__send_status
isc_result_t
send_status(omapi_object_t *protcol, isc_result_t waitstatus,
	    unsigned int response_id, const char *message);

#define send_update omapi__send_update
isc_result_t
send_update(omapi_object_t *protocol, unsigned int response_id,
	    omapi_object_t *object);

ISC_LANG_ENDDECLS

#endif /* OMAPI_PRIVATE_H */
