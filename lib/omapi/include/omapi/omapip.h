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
#include <isc/time.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

#define OMAPI_PROTOCOL_VERSION	100

#define OMAPI_OP_OPEN		1
#define OMAPI_OP_REFRESH	2
#define	OMAPI_OP_UPDATE		3
#define OMAPI_OP_NOTIFY		4
#define OMAPI_OP_STATUS		5
#define OMAPI_OP_DELETE		6

/*****
 ***** Type definitions.
 *****/

typedef unsigned int			omapi_handle_t;
typedef struct omapi_object		omapi_object_t;
typedef struct omapi_object_type 	omapi_object_type_t;
typedef struct omapi_typed_data		omapi_typed_data_t;
typedef struct omapi_data_string	omapi_data_string_t;
typedef struct omapi_value		omapi_value_t;

/*
 * This preamble is common to all objects manipulated by libomapi.a,
 * including specials objects created by external users of the library.
 * It needs to be at the start of every struct that gets used as an object.
 */
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
 * XXXDCL rename
 */
#define OMAPI_FORCE_DISCONNECT	ISC_TRUE
#define OMAPI_CLEAN_DISCONNECT	ISC_FALSE

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
omapi_protocol_destroy(omapi_object_t *object);

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
omapi_protocol_listener_destroy(omapi_object_t *object);

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

isc_result_t
omapi_connection_require(omapi_object_t *connection, unsigned int bytes);

isc_result_t
omapi_connection_wait(omapi_object_t *object,
		      omapi_object_t *connection_handle,
		      isc_time_t *timeout);

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

/*
 * dispatch.c
 */

isc_result_t
omapi_dispatch(struct timeval *timeout);

/*
 * message.c
 */
isc_result_t
omapi_message_new(omapi_object_t **message);

void
omapi_message_register(omapi_object_t *message);

isc_result_t
omapi_message_process(omapi_object_t *message, omapi_object_t *protocol);

/*
 * support.c
 */
isc_result_t
omapi_init(isc_mem_t *mctx);

void
omapi_destroy(void);

isc_result_t
omapi_object_register(omapi_object_type_t **type, const char *name,
		      isc_result_t	((*set_value)
					 (omapi_object_t *,
					  omapi_object_t *,
					  omapi_data_string_t *,
					  omapi_typed_data_t *)),

		      isc_result_t 	((*get_value)
					 (omapi_object_t *,
					  omapi_object_t *,
					  omapi_data_string_t *,
					  omapi_value_t **)),

		      void		((*destroy)
					 (omapi_object_t *)),

		      isc_result_t	((*signal_handler)
					 (omapi_object_t *,
					  const char *,
					  va_list)),

		      isc_result_t	((*stuff_values)
					 (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *)),

		      isc_result_t	((*lookup)
					 (omapi_object_t **,
					  omapi_object_t *,
					  omapi_object_t *)),

		      isc_result_t	((*create)
					 (omapi_object_t **,
					  omapi_object_t *)),

		      isc_result_t	((*remove)
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
omapi_object_create(omapi_object_t **object, omapi_object_type_t *type,
		    size_t size);

void
omapi_object_reference(omapi_object_t **reference, omapi_object_t *object);

void
omapi_object_dereference(omapi_object_t **reference);

/*
 * data.c
 */

isc_result_t
omapi_data_new(omapi_typed_data_t **data, omapi_datatype_t type, ...);

void
omapi_data_reference(omapi_typed_data_t **reference, omapi_typed_data_t *data,
		     const char *name);

void
omapi_data_dereference(omapi_typed_data_t **reference);

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
