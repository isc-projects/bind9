/* omapip.h

   Definitions for the object management API and protocol... */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#ifndef _OMAPIP_H_
#define _OMAPIP_H_
#include <isc/result.h>

typedef unsigned int omapi_handle_t;

struct __omapi_object;
typedef struct __omapi_object omapi_object_t;

typedef enum {
	omapi_datatype_int,
	omapi_datatype_string,
	omapi_datatype_data,
	omapi_datatype_object
} omapi_datatype_t;

typedef struct {
	int refcnt;
	omapi_datatype_t type;
	union {
		struct {
			unsigned len;
#define OMAPI_TYPED_DATA_NOBUFFER_LEN (sizeof (int) + \
				       sizeof (omapi_datatype_t) + \
				       sizeof (int))
			unsigned char value [1];
		} buffer;
#define OMAPI_TYPED_DATA_OBJECT_LEN (sizeof (int) + \
				     sizeof (omapi_datatype_t) + \
				     sizeof (omapi_object_t *))
		omapi_object_t *object;
#define OMAPI_TYPED_DATA_REF_LEN (sizeof (int) + \
				  sizeof (omapi_datatype_t) + \
				  3 * sizeof (void *))
		struct {
			void *ptr;
			isc_result_t (*reference) (void *,
						   void *, char *);
			isc_result_t (*dereference) (void *, char *);
		} ref;
#define OMAPI_TYPED_DATA_INT_LEN (sizeof (int) + \
				  sizeof (omapi_datatype_t) + \
				  sizeof (int))
		int integer;
	} u;
} omapi_typed_data_t;

typedef struct {
	int refcnt;
	unsigned len;
#define OMAPI_DATA_STRING_EMPTY_SIZE (2 * sizeof (int))
	unsigned char value [1];
} omapi_data_string_t;

typedef struct {
	int refcnt;
	omapi_data_string_t *name;
	omapi_typed_data_t *value;
} omapi_value_t;

typedef struct __omapi_object_type_t {
	const char *name;
	struct __omapi_object_type_t *next;
	
	isc_result_t (*set_value) (omapi_object_t *, omapi_object_t *,
				   omapi_data_string_t *,
				   omapi_typed_data_t *);
	isc_result_t (*get_value) (omapi_object_t *,
				   omapi_object_t *,
				   omapi_data_string_t *, omapi_value_t **);
	isc_result_t (*destroy) (omapi_object_t *, const char *);
	isc_result_t (*signal_handler) (omapi_object_t *,
					const char *, va_list);
	isc_result_t (*stuff_values) (omapi_object_t *,
				      omapi_object_t *, omapi_object_t *);
	isc_result_t (*lookup) (omapi_object_t **, omapi_object_t *,
				omapi_object_t *);
	isc_result_t (*create) (omapi_object_t **, omapi_object_t *);
	isc_result_t (*remove) (omapi_object_t *, omapi_object_t *);
} omapi_object_type_t;

#define OMAPI_OBJECT_PREAMBLE \
	omapi_object_type_t *type; \
	int refcnt; \
	omapi_handle_t handle; \
	omapi_object_t *outer, *inner

/* The omapi handle structure. */
struct __omapi_object {
	OMAPI_OBJECT_PREAMBLE;
};

/* The port on which applications should listen for OMAPI connections. */
#define OMAPI_PROTOCOL_PORT	7911

isc_result_t omapi_protocol_connect (omapi_object_t *,
				     const char *, int, omapi_object_t *);
isc_result_t omapi_protocol_listen (omapi_object_t *, int, int);
isc_result_t omapi_protocol_accept (omapi_object_t *);
isc_result_t omapi_protocol_send_intro (omapi_object_t *, unsigned, unsigned);
isc_result_t omapi_protocol_ready (omapi_object_t *);
isc_result_t omapi_protocol_set_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_protocol_get_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_value_t **); 
isc_result_t omapi_protocol_stuff_values (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);

isc_result_t omapi_protocol_destroy (omapi_object_t *, const char *);
isc_result_t omapi_protocol_send_message (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);
isc_result_t omapi_protocol_signal_handler (omapi_object_t *,
					    const char *, va_list);
isc_result_t omapi_protocol_listener_set_value (omapi_object_t *,
						omapi_object_t *,
						omapi_data_string_t *,
						omapi_typed_data_t *);
isc_result_t omapi_protocol_listener_get_value (omapi_object_t *,
						omapi_object_t *,
						omapi_data_string_t *,
						omapi_value_t **); 
isc_result_t omapi_protocol_listener_destroy (omapi_object_t *, const char *);
isc_result_t omapi_protocol_listener_signal (omapi_object_t *,
					     const char *, va_list);
isc_result_t omapi_protocol_listener_stuff (omapi_object_t *,
					    omapi_object_t *,
					    omapi_object_t *);
isc_result_t omapi_protocol_send_status (omapi_object_t *, omapi_object_t *,
					 isc_result_t, unsigned, const char *);
isc_result_t omapi_protocol_send_update (omapi_object_t *, omapi_object_t *,
					 unsigned, omapi_object_t *);

isc_result_t omapi_connect (omapi_object_t *, const char *, int);
isc_result_t omapi_disconnect (omapi_object_t *, int);
int omapi_connection_readfd (omapi_object_t *);
int omapi_connection_writefd (omapi_object_t *);
isc_result_t omapi_connection_reader (omapi_object_t *);
isc_result_t omapi_connection_writer (omapi_object_t *);
isc_result_t omapi_connection_reaper (omapi_object_t *);
isc_result_t omapi_connection_set_value (omapi_object_t *, omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_typed_data_t *);
isc_result_t omapi_connection_get_value (omapi_object_t *, omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_value_t **); 
isc_result_t omapi_connection_destroy (omapi_object_t *, const char *);
isc_result_t omapi_connection_signal_handler (omapi_object_t *,
					      const char *, va_list);
isc_result_t omapi_connection_stuff_values (omapi_object_t *,
					    omapi_object_t *,
					    omapi_object_t *);
isc_result_t omapi_connection_write_typed_data (omapi_object_t *,
						omapi_typed_data_t *);
isc_result_t omapi_connection_put_name (omapi_object_t *, const char *);
isc_result_t omapi_connection_put_string (omapi_object_t *, const char *);
isc_result_t omapi_connection_put_handle (omapi_object_t *c,
					  omapi_object_t *h);


isc_result_t omapi_listen (omapi_object_t *, int, int);
isc_result_t omapi_listener_accept (omapi_object_t *);
int omapi_listener_readfd (omapi_object_t *);
isc_result_t omapi_accept (omapi_object_t *);
isc_result_t omapi_listener_set_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_listener_get_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_value_t **); 
isc_result_t omapi_listener_destroy (omapi_object_t *, const char *);
isc_result_t omapi_listener_signal_handler (omapi_object_t *,
					    const char *, va_list);
isc_result_t omapi_listener_stuff_values (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);

isc_result_t omapi_register_io_object (omapi_object_t *,
				       int (*)(omapi_object_t *),
				       int (*)(omapi_object_t *),
				       isc_result_t (*)(omapi_object_t *),
				       isc_result_t (*)(omapi_object_t *),
				       isc_result_t (*)(omapi_object_t *));
isc_result_t omapi_dispatch (struct timeval *);
isc_result_t omapi_wait_for_completion (omapi_object_t *, struct timeval *);
isc_result_t omapi_one_dispatch (omapi_object_t *, struct timeval *);
isc_result_t omapi_io_set_value (omapi_object_t *, omapi_object_t *,
				 omapi_data_string_t *,
				 omapi_typed_data_t *);
isc_result_t omapi_io_get_value (omapi_object_t *, omapi_object_t *,
				 omapi_data_string_t *, omapi_value_t **); 
isc_result_t omapi_io_destroy (omapi_object_t *, const char *);
isc_result_t omapi_io_signal_handler (omapi_object_t *, const char *, va_list);
isc_result_t omapi_io_stuff_values (omapi_object_t *,
				    omapi_object_t *,
				    omapi_object_t *);
isc_result_t omapi_waiter_signal_handler (omapi_object_t *,
					  const char *, va_list);

isc_result_t omapi_generic_new (omapi_object_t **, const char *);
isc_result_t omapi_generic_set_value  (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_generic_get_value (omapi_object_t *, omapi_object_t *,
				      omapi_data_string_t *,
				      omapi_value_t **); 
isc_result_t omapi_generic_destroy (omapi_object_t *, const char *);
isc_result_t omapi_generic_signal_handler (omapi_object_t *,
					   const char *, va_list);
isc_result_t omapi_generic_stuff_values (omapi_object_t *,
					 omapi_object_t *,
					 omapi_object_t *);

isc_result_t omapi_message_new (omapi_object_t **, const char *);
isc_result_t omapi_message_set_value  (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_message_get_value (omapi_object_t *, omapi_object_t *,
				      omapi_data_string_t *,
				      omapi_value_t **); 
isc_result_t omapi_message_destroy (omapi_object_t *, const char *);
isc_result_t omapi_message_signal_handler (omapi_object_t *,
					   const char *, va_list);
isc_result_t omapi_message_stuff_values (omapi_object_t *,
					 omapi_object_t *,
					 omapi_object_t *);
isc_result_t omapi_message_register (omapi_object_t *);
isc_result_t omapi_message_unregister (omapi_object_t *);
isc_result_t omapi_message_process (omapi_object_t *, omapi_object_t *);

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

isc_result_t omapi_init (void);
isc_result_t omapi_object_type_register (omapi_object_type_t **,
					 const char *,
					 isc_result_t (*)
						(omapi_object_t *,
						 omapi_object_t *,
						 omapi_data_string_t *,
						 omapi_typed_data_t *),
					 isc_result_t (*)
						(omapi_object_t *,
						 omapi_object_t *,
						 omapi_data_string_t *,
						 omapi_value_t **),
					 isc_result_t (*) (omapi_object_t *,
							   const char *),
					 isc_result_t (*) (omapi_object_t *,
							   const char *,
							   va_list),
					 isc_result_t (*) (omapi_object_t *,
							   omapi_object_t *,
							   omapi_object_t *),
					 isc_result_t (*) (omapi_object_t **,
							   omapi_object_t *,
							   omapi_object_t *),
					 isc_result_t (*) (omapi_object_t **,
							   omapi_object_t *),
					 isc_result_t (*) (omapi_object_t *,
							   omapi_object_t *));
isc_result_t omapi_signal (omapi_object_t *, const char *, ...);
isc_result_t omapi_signal_in (omapi_object_t *, const char *, ...);
isc_result_t omapi_set_value (omapi_object_t *, omapi_object_t *,
			      omapi_data_string_t *,
			      omapi_typed_data_t *);
isc_result_t omapi_set_value_str (omapi_object_t *, omapi_object_t *,
				  const char *, omapi_typed_data_t *);
isc_result_t omapi_set_boolean_value (omapi_object_t *, omapi_object_t *,
				      const char *, int);
isc_result_t omapi_set_int_value (omapi_object_t *, omapi_object_t *,
				  const char *, int);
isc_result_t omapi_set_object_value (omapi_object_t *, omapi_object_t *,
				     const char *, omapi_object_t *);
isc_result_t omapi_set_string_value (omapi_object_t *, omapi_object_t *,
				     const char *, const char *);
isc_result_t omapi_get_value (omapi_object_t *, omapi_object_t *,
			      omapi_data_string_t *,
			      omapi_value_t **); 
isc_result_t omapi_get_value_str (omapi_object_t *, omapi_object_t *,
				  const char *, omapi_value_t **); 
isc_result_t omapi_stuff_values (omapi_object_t *,
				 omapi_object_t *,
				 omapi_object_t *);
isc_result_t omapi_object_create (omapi_object_t **, omapi_object_t *,
				  omapi_object_type_t *);
isc_result_t omapi_object_update (omapi_object_t *, omapi_object_t *,
				  omapi_object_t *, omapi_handle_t);
int omapi_data_string_cmp (omapi_data_string_t *, omapi_data_string_t *);
int omapi_ds_strcmp (omapi_data_string_t *, const char *);
int omapi_td_strcmp (omapi_typed_data_t *, const char *);
isc_result_t omapi_make_value (omapi_value_t **, omapi_data_string_t *,
			       omapi_typed_data_t *, const char *);
isc_result_t omapi_make_const_value (omapi_value_t **, omapi_data_string_t *,
				     const unsigned char *,
				     unsigned, const char *);
isc_result_t omapi_make_int_value (omapi_value_t **, omapi_data_string_t *,
				   int, const char *);
isc_result_t omapi_make_handle_value (omapi_value_t **, omapi_data_string_t *,
				      omapi_object_t *, const char *);
isc_result_t omapi_make_string_value (omapi_value_t **, omapi_data_string_t *,
				      char *, const char *);
isc_result_t omapi_get_int_value (unsigned long *, omapi_typed_data_t *);

isc_result_t omapi_object_handle (omapi_handle_t *, omapi_object_t *);
isc_result_t omapi_handle_lookup (omapi_object_t **, omapi_handle_t);
isc_result_t omapi_handle_td_lookup (omapi_object_t **, omapi_typed_data_t *);

isc_result_t omapi_object_reference (omapi_object_t **,
				     omapi_object_t *, const char *);
isc_result_t omapi_object_dereference (omapi_object_t **, const char *);
isc_result_t omapi_typed_data_new (omapi_typed_data_t **,
				   omapi_datatype_t, ...);
isc_result_t omapi_typed_data_reference (omapi_typed_data_t **,
					 omapi_typed_data_t *, const char *);
isc_result_t omapi_typed_data_dereference (omapi_typed_data_t **,
					   const char *);
isc_result_t omapi_data_string_new (omapi_data_string_t **,
				    unsigned, const char *);
isc_result_t omapi_data_string_reference (omapi_data_string_t **,
					  omapi_data_string_t *, const char *);
isc_result_t omapi_data_string_dereference (omapi_data_string_t **,
					    const char *);
isc_result_t omapi_value_new (omapi_value_t **, const char *);
isc_result_t omapi_value_reference (omapi_value_t **,
				    omapi_value_t *, const char *);
isc_result_t omapi_value_dereference (omapi_value_t **, const char *);


#endif /* _OMAPIP_H_ */
