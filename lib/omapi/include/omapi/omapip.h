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

/*
 * Definitions for the object management API and protocol.
 */

#ifndef _OMAPI_OMAPIP_H_
#define _OMAPI_OMAPIP_H_

#include <stdarg.h>
#include <time.h>		/* struct timeval */

#include <isc/boolean.h>
#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

#define OMAPI_PROTOCOL_VERSION	100

/*****
 ***** Type definitions.
 *****/

typedef unsigned int			omapi_handle_t;
typedef struct omapi_object		omapi_object_t;
typedef struct omapi_object_type 	omapi_object_type_t;
typedef struct omapi_typed_data		omapi_typed_data_t;
typedef struct omapi_data_string	omapi_data_string_t;
typedef struct omapi_value		omapi_value_t;

#define OMAPI_OBJECT_PREAMBLE \
	omapi_object_type_t *	type; \
	size_t			object_size; \
	int 			refcnt; \
	omapi_handle_t 		handle; \
	omapi_object_t 		*outer, *inner

/*
 * The OMAPI handle structure.
 */
struct omapi_object {
	OMAPI_OBJECT_PREAMBLE;
};

/*
 * OMAPI data types.
 */
typedef enum {
	omapi_datatype_int,
	omapi_datatype_string,
	omapi_datatype_data,
	omapi_datatype_object
} omapi_datatype_t;

struct omapi_typed_data {
#define OMAPI_TYPED_DATA_HEADER_LEN (sizeof(int) + \
				     sizeof(omapi_datatype_t))
	int 			refcnt;
	omapi_datatype_t 	type;

	union {
		/*
		 * OMAPI_TYPED_DATA_NOBUFFER_LEN purposefully does not
		 * include the 'value' byte, which only serves as a
		 * handle to memory allocated for (usually) more than
		 * one byte that begins at the 'value' location.
		 */
#define OMAPI_TYPED_DATA_NOBUFFER_LEN (OMAPI_TYPED_DATA_HEADER_LEN + \
				       sizeof(int))
		struct {
			unsigned int	len;
			unsigned char	value[1];
		} buffer;

#define OMAPI_TYPED_DATA_OBJECT_LEN (OMAPI_TYPED_DATA_HEADER_LEN + \
				     sizeof(omapi_object_t *))
		omapi_object_t		*object;

#define OMAPI_TYPED_DATA_INT_LEN (OMAPI_TYPED_DATA_HEADER_LEN + \
				  sizeof(int))
		int 			integer;
	} u;
};

struct omapi_data_string {
	/*
	 * OMAPI_DATA_STRING_EMPTY_SIZE purposefully does not
	 * include the 'value' byte, which only serves as a
	 * handle to memory allocated for (usually) more than
	 * one byte that begins at the 'value' location.
	 */
#define OMAPI_DATA_STRING_EMPTY_SIZE (2 * sizeof(int))
	int 		refcnt;
	unsigned int	len;
	unsigned char	value[1];
};

struct omapi_value {
	int 			refcnt;
	omapi_data_string_t *	name;
	omapi_typed_data_t *	value;
};

struct omapi_object_type {
	const char *		name;
	omapi_object_type_t *	next;
	
	isc_result_t		(*set_value)(omapi_object_t *object,
					     omapi_object_t *id,
					     omapi_data_string_t *name,
					     omapi_typed_data_t *value);

	isc_result_t		(*get_value)(omapi_object_t *object,
					     omapi_object_t *id,
					     omapi_data_string_t *name,
					     omapi_value_t **value);

	void			(*destroy)(omapi_object_t *object,
					   const char *name);

	isc_result_t		(*signal_handler)(omapi_object_t *object,
						  const char *name,
						  va_list args);

	isc_result_t		(*stuff_values)(omapi_object_t *connection,
						omapi_object_t *id,
						omapi_object_t *object);

	isc_result_t		(*lookup)(omapi_object_t **object,
					  omapi_object_t *id,
					  omapi_object_t *reference);

	isc_result_t		(*create)(omapi_object_t **object,
					  omapi_object_t *id);

	isc_result_t		(*remove)(omapi_object_t *object,
					  omapi_object_t *id);
};

/*
 * The port on which applications should listen for OMAPI connections.
 */
#define OMAPI_PROTOCOL_PORT	7911

/*
 * For use with omapi_connection_disconnect().
 */
#define OMAPI_FORCE_DISCONNECT	ISC_TRUE
#define OMAPI_CLEAN_DISCONNECT	ISC_FALSE

/*****
 ***** Global Variables.
 *****/
extern omapi_object_type_t *omapi_type_connection;
extern omapi_object_type_t *omapi_type_listener;
extern omapi_object_type_t *omapi_type_io_object;
extern omapi_object_type_t *omapi_type_generic;
extern omapi_object_type_t *omapi_type_protocol;
extern omapi_object_type_t *omapi_type_protocol_listener;
extern omapi_object_type_t *omapi_type_waiter;
extern omapi_object_type_t *omapi_type_remote;
extern omapi_object_type_t *omapi_type_message;

extern omapi_object_type_t *omapi_object_types;

/*****
 ***** Function Prototypes.
 *****/

/*
 * protocol.c
 */
isc_result_t
omapi_protocol_connect(omapi_object_t *object, const char *server, int port,
		       omapi_object_t *authinfo);

void
omapi_protocol_disconnect(omapi_object_t *handle, isc_boolean_t force);

isc_result_t
omapi_protocol_listen(omapi_object_t *object, int port, int backlog);

isc_result_t
omapi_protocol_send_intro(omapi_object_t *object, unsigned int version,
			  unsigned int object_size);

isc_result_t
omapi_protocol_set_value(omapi_object_t *object, omapi_object_t *id,
			 omapi_data_string_t *name, omapi_typed_data_t *value);

isc_result_t
omapi_protocol_get_value(omapi_object_t *object, omapi_object_t *id,
			 omapi_data_string_t *name, omapi_value_t **value); 

isc_result_t
omapi_protocol_stuff_values(omapi_object_t *connection, omapi_object_t *id,
			    omapi_object_t *object);

void
omapi_protocol_destroy(omapi_object_t *object, const char *name);

isc_result_t
omapi_protocol_send_message(omapi_object_t *protocol,
			    omapi_object_t *id,
			    omapi_object_t *message,
			    omapi_object_t *original_message);

isc_result_t
omapi_protocol_signal_handler(omapi_object_t *protocol, const char *name,
			      va_list args);

isc_result_t
omapi_protocol_listener_set_value(omapi_object_t *object, omapi_object_t *id,
				  omapi_data_string_t *name,
				  omapi_typed_data_t *value);
isc_result_t
omapi_protocol_listener_get_value(omapi_object_t *object, omapi_object_t *id,
				  omapi_data_string_t *name,
				  omapi_value_t **value); 

void
omapi_protocol_listener_destroy(omapi_object_t *object, const char *name);

isc_result_t
omapi_protocol_listener_signal(omapi_object_t *protocol_listener,
			       const char *names, va_list args);

isc_result_t
omapi_protocol_listener_stuff(omapi_object_t *connection, omapi_object_t *id,
			      omapi_object_t *object);

isc_result_t
omapi_protocol_send_status(omapi_object_t *protcol, omapi_object_t *id,
			   isc_result_t waitstatus, unsigned int response_id,
			   const char *message);

isc_result_t
omapi_protocol_send_update(omapi_object_t *protocl, omapi_object_t *id,
			   unsigned int response_id, omapi_object_t *object);

/*
 * connection.c (XXX and buffer.c)
 */
isc_result_t
omapi_connect(omapi_object_t *connection, const char *server, int port);

isc_result_t
omapi_connection_toserver(omapi_object_t *connection, const char *server,
			  int port);

void
omapi_connection_disconnect(omapi_object_t *connection, isc_boolean_t force);

int
omapi_connection_readfd(omapi_object_t *connection);

int
omapi_connection_writefd(omapi_object_t *connection);

void
omapi_connection_read(isc_task_t *task, isc_event_t *event);

isc_result_t
omapi_connection_reader(omapi_object_t *connection);

isc_result_t
omapi_connection_writer(omapi_object_t *connection);

isc_result_t
omapi_connection_reaper(omapi_object_t *connection);

isc_result_t
omapi_connection_setvalue(omapi_object_t *connection, omapi_object_t *id,
			   omapi_data_string_t *name,
			   omapi_typed_data_t *value);

isc_result_t
omapi_connection_getvalue(omapi_object_t *connection, omapi_object_t *id,
			   omapi_data_string_t *name, omapi_value_t **value); 

void
omapi_connection_destroy(omapi_object_t *connection, const char *name);

isc_result_t
omapi_connection_signalhandler(omapi_object_t *connection, const char *name,
				va_list args);

isc_result_t
omapi_connection_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
			      omapi_object_t *object);

isc_result_t
omapi_connection_require(omapi_object_t *connection, unsigned int bytes);

isc_result_t
omapi_connection_copyout(unsigned char *data, omapi_object_t *connection,
			 unsigned int length);

isc_result_t
omapi_connection_copyin(omapi_object_t *connection, unsigned char *data,
			 unsigned int length);

isc_result_t
omapi_connection_getuint32(omapi_object_t *c, isc_uint32_t *value);

isc_result_t
omapi_connection_putuint32(omapi_object_t *c, isc_uint32_t value);

isc_result_t
omapi_connection_getuint16(omapi_object_t *c, isc_uint16_t *value);

isc_result_t
omapi_connection_putuint16(omapi_object_t *c, isc_uint32_t value);

isc_result_t
omapi_connection_puttypeddata(omapi_object_t *connection,
				  omapi_typed_data_t *data);

isc_result_t
omapi_connection_putname(omapi_object_t *connection, const char *name);

isc_result_t
omapi_connection_putstring(omapi_object_t *connection, const char *string);

isc_result_t
omapi_connection_puthandle(omapi_object_t *connection,
			    omapi_object_t *object);

/*
 * listen.c
 */
isc_result_t
omapi_listener_listen(omapi_object_t *listener, int port, int backlog);

isc_result_t
omapi_listener_setvalue(omapi_object_t *listener, omapi_object_t *id,
			omapi_data_string_t *name, omapi_typed_data_t *value);

isc_result_t
omapi_listener_getvalue(omapi_object_t *listener, omapi_object_t *id,
			omapi_data_string_t *name, omapi_value_t **value); 

void
omapi_listener_destroy(omapi_object_t *listener, const char *name);

isc_result_t
omapi_listener_signalhandler(omapi_object_t *listener, const char *name,
			     va_list args);

isc_result_t
omapi_listener_stuffvalues(omapi_object_t *listener, omapi_object_t *id,
			   omapi_object_t *object);

/*
 * dispatch.c
 */
isc_result_t
omapi_register_io_object(omapi_object_t *object,
			 int (*readfd)(omapi_object_t *),
			 int (*writefd)(omapi_object_t *),
			 isc_result_t (*reader)(omapi_object_t *),
			 isc_result_t (*writer)(omapi_object_t *),
			 isc_result_t (*reaper)(omapi_object_t *));

isc_result_t
omapi_dispatch(struct timeval *timeout);

isc_result_t
omapi_wait_for_completion(omapi_object_t *io, struct timeval *timeout);

isc_result_t
omapi_one_dispatch(omapi_object_t *waiter, struct timeval *timeout);

isc_result_t
omapi_io_setvalue(omapi_object_t *io, omapi_object_t *id,
		   omapi_data_string_t *name, omapi_typed_data_t *value);

isc_result_t
omapi_io_getvalue(omapi_object_t *io, omapi_object_t *id,
		   omapi_data_string_t *name, omapi_value_t **value); 

void
omapi_io_destroy(omapi_object_t *io, const char *name);

isc_result_t
omapi_io_signalhandler(omapi_object_t *io, const char *name, va_list args);

isc_result_t
omapi_io_stuffvalues(omapi_object_t *io, omapi_object_t *id,
		      omapi_object_t *object);
isc_result_t
omapi_waiter_signal_handler(omapi_object_t *waiter, const char *name,
			    va_list args);

/*
 * generic.c
 */
isc_result_t
omapi_generic_new(omapi_object_t **generic, const char *name);

isc_result_t
omapi_generic_set_value(omapi_object_t *generic, omapi_object_t *id,
			omapi_data_string_t *name, omapi_typed_data_t *value);

isc_result_t
omapi_generic_get_value(omapi_object_t *generic, omapi_object_t *id,
			omapi_data_string_t *name, omapi_value_t **value); 

void
omapi_generic_destroy(omapi_object_t *generic, const char *name);

isc_result_t
omapi_generic_signal_handler(omapi_object_t *generic, const char *name,
			     va_list args);

isc_result_t
omapi_generic_stuff_values(omapi_object_t *generic, omapi_object_t *id,
			   omapi_object_t *object);

/*
 * message.c
 */
isc_result_t
omapi_message_new(omapi_object_t **message, const char *name);

isc_result_t
omapi_message_setvalue(omapi_object_t *message, omapi_object_t *id,
			omapi_data_string_t *name, omapi_typed_data_t *value);
isc_result_t
omapi_message_getvalue(omapi_object_t *message, omapi_object_t *id,
			omapi_data_string_t *name, omapi_value_t **value); 
void
omapi_message_destroy(omapi_object_t *message, const char *name);

isc_result_t
omapi_message_signalhandler(omapi_object_t *message, const char *name,
			     va_list args);

isc_result_t
omapi_message_stuffvalues(omapi_object_t *message, omapi_object_t *id,
			   omapi_object_t *object);
isc_result_t
omapi_message_register(omapi_object_t *message);

isc_result_t
omapi_message_unregister(omapi_object_t *message);

isc_result_t
omapi_message_process(omapi_object_t *message, omapi_object_t *protocol);

/*
 * support.c
 */
isc_result_t
omapi_init(isc_mem_t *mctx);

isc_result_t
omapi_object_type_register(omapi_object_type_t **type,
			   const char *name,
			   isc_result_t ((*set_value)
					 (omapi_object_t *,
					  omapi_object_t *,
					  omapi_data_string_t *,
					  omapi_typed_data_t *)),

			   isc_result_t ((*get_value)
					 (omapi_object_t *,
					  omapi_object_t *,
					  omapi_data_string_t *,
					  omapi_value_t **)),

			   void		((*destroy)
					 (omapi_object_t *,
					  const char *)),

			   isc_result_t ((*signal_handler)
					 (omapi_object_t *,
					  const char *,
					  va_list)),

			   isc_result_t ((*stuff_values)
					 (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *)),

			   isc_result_t ((*lookup)
					 (omapi_object_t **,
					  omapi_object_t *,
					  omapi_object_t *)),

			   isc_result_t ((*create)
					 (omapi_object_t **,
					  omapi_object_t *)),

			   isc_result_t  ((*remove)
					  (omapi_object_t *,
					   omapi_object_t *)));

isc_result_t
omapi_signal(omapi_object_t *handle, const char *name, ...);

isc_result_t
omapi_signal_in(omapi_object_t *handle, const char *name, ...);

isc_result_t
omapi_set_value(omapi_object_t *handle, omapi_object_t *id,
		omapi_data_string_t *name, omapi_typed_data_t *value);

isc_result_t
omapi_set_value_str(omapi_object_t *handle, omapi_object_t *id,
		    const char *name, omapi_typed_data_t *value);

isc_result_t
omapi_set_boolean_value(omapi_object_t *handle, omapi_object_t *id,
			const char *name, int value);

isc_result_t
omapi_set_int_value(omapi_object_t *handle, omapi_object_t *id,
		    const char *name, int value);

isc_result_t
omapi_set_object_value(omapi_object_t *handle, omapi_object_t *id,
		       const char *name, omapi_object_t *value);

isc_result_t
omapi_set_string_value(omapi_object_t *handle, omapi_object_t *id,
		       const char *name, const char *value);

isc_result_t
omapi_get_value(omapi_object_t *handle, omapi_object_t *id,
		omapi_data_string_t *name, omapi_value_t **value); 

isc_result_t
omapi_get_value_str(omapi_object_t *handle, omapi_object_t *id,
		    const char *name, omapi_value_t **value); 

isc_result_t
omapi_stuff_values(omapi_object_t *handle, omapi_object_t *id,
		   omapi_object_t *object);

isc_result_t
omapi_object_create(omapi_object_t **object, omapi_object_t *id,
		    omapi_object_type_t *type);

isc_result_t
omapi_object_update(omapi_object_t *object, omapi_object_t *id,
		    omapi_object_t *source, omapi_handle_t handle);

int
omapi_data_string_cmp(omapi_data_string_t *data_string1,
		      omapi_data_string_t *data_string2);

int
omapi_ds_strcmp(omapi_data_string_t *data_string, const char *string);

int
omapi_td_strcmp(omapi_typed_data_t *string_type, const char *string);

isc_result_t
omapi_make_value(omapi_value_t **valuep, omapi_data_string_t *name,
		 omapi_typed_data_t *value, const char *caller);

isc_result_t
omapi_make_const_value(omapi_value_t **valuep, omapi_data_string_t *name,
		       const unsigned char *value, unsigned int length,
		       const char *caller);

isc_result_t
omapi_make_int_value(omapi_value_t **valuep, omapi_data_string_t *name,
		     int value, const char *caller);

isc_result_t
omapi_make_handle_value(omapi_value_t **valuep, omapi_data_string_t *name,
			omapi_object_t *handle, const char *caller);

isc_result_t
omapi_make_string_value(omapi_value_t **valuep, omapi_data_string_t *name,
			char *string, const char *caller);

isc_result_t
omapi_get_int_value(unsigned long *value, omapi_typed_data_t *data_object);

/*
 * handle.c
 */
isc_result_t
omapi_object_handle(omapi_handle_t *handle, omapi_object_t *object);

isc_result_t
omapi_handle_lookup(omapi_object_t **object, omapi_handle_t handle);

isc_result_t
omapi_handle_td_lookup(omapi_object_t **object, omapi_typed_data_t *data);

/*
 * object.c
 */
isc_result_t
omapi_object_new(omapi_object_t **object, omapi_object_type_t *type,
		    size_t size);

void
omapi_object_reference(omapi_object_t **reference, omapi_object_t *object,
		       const char *name);

void
omapi_object_dereference(omapi_object_t **reference, const char *name);

/*
 * data.c
 */

isc_result_t
omapi_data_new(omapi_typed_data_t **data, omapi_datatype_t type, ...);

void
omapi_data_reference(omapi_typed_data_t **reference, omapi_typed_data_t *data,
		     const char *name);

void
omapi_data_dereference(omapi_typed_data_t **reference, const char *name);

isc_result_t
omapi_data_newstring(omapi_data_string_t **string, unsigned int length,
		     const char *name);

void
omapi_data_stringreference(omapi_data_string_t **reference,
			   omapi_data_string_t *string,
			   const char *name);

void
omapi_data_stringdereference(omapi_data_string_t **, const char *);
isc_result_t

omapi_data_newvalue(omapi_value_t **value, const char *name);

void
omapi_data_valuereference(omapi_value_t **reference, omapi_value_t *value,
			  const char *name);

void
omapi_data_valuedereference(omapi_value_t **reference, const char *name);

ISC_LANG_ENDDECLS

#endif /* _OMAPI_OMAPIP_H_ */
