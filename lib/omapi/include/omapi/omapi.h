/*
 * Copyright (C) 1996-2001  Internet Software Consortium.
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

/* $Id: omapi.h,v 1.17.4.1 2001/01/09 22:53:13 bwelling Exp $ */

/*
 * Definitions for the object management API and protocol.
 */

#ifndef OMAPI_OMAPI_H
#define OMAPI_OMAPI_H 1

#include <stdarg.h>

#include <isc/boolean.h>
#include <isc/eventclass.h>
#include <isc/lang.h>

#include <dns/acl.h>

#include <omapi/types.h>

ISC_LANG_BEGINDECLS

#define OMAPI_PROTOCOL_VERSION	100

/*
 * Protocol operations.
 */
#define OMAPI_OP_OPEN		1
#define OMAPI_OP_REFRESH	2
#define	OMAPI_OP_UPDATE		3
#define OMAPI_OP_NOTIFY		4
#define OMAPI_OP_STATUS		5
#define OMAPI_OP_DELETE		6

/*
 * This preamble is common to all objects manipulated by libomapi.a,
 * including specials objects created by external users of the library.
 * It needs to be at the start of every struct that gets used as an object.
 */
#define OMAPI_OBJECT_PREAMBLE \
	omapi_objecttype_t *	type; \
	size_t			object_size; \
	int 			refcnt; \
	isc_result_t		waitresult; \
	omapi_handle_t 		handle; \
	omapi_object_t 		*outer, *inner; \
	isc_taskaction_t	destroy_action; \
	void *			destroy_arg

/*
 * This is the most basic OMAPI object, used as the handle for all
 * other object types in most public calls.
 */
struct omapi_object {
	OMAPI_OBJECT_PREAMBLE;
};

/*
 * For use with omapi_connection_disconnect().
 * XXXDCL rename
 */
#define OMAPI_FORCE_DISCONNECT	ISC_TRUE
#define OMAPI_CLEAN_DISCONNECT	ISC_FALSE

/*
 * For use with omapi_auth_*.  Will be powers of 2 when there is ever
 * more than one authentication algorithm available.
 */
#define OMAPI_AUTH_HMACMD5	1

#define OMAPI_EVENT_OBJECTFREED	(ISC_EVENTCLASS_OMAPI + 1)

/*****
 ***** Function Prototypes.
 *****/

/*
 * Public functions defined in auth.c.
 */
isc_result_t
omapi_auth_register(const char *name, unsigned int algorithms,
		    const unsigned char *secret, size_t secretlen);

void
omapi_auth_deregister(const char *name);

isc_result_t
omapi_auth_use(omapi_object_t *manager, const char *name,
	       unsigned int algorithm);

/*
 * Public functions defined in protocol.c.
 */
isc_result_t
omapi_protocol_connect(omapi_object_t *object, const char *server,
		       in_port_t port, omapi_object_t *authinfo);

void
omapi_protocol_disconnect(omapi_object_t *handle, isc_boolean_t force);

/*
 * XXXDCL The use of one void *arg for all three callbacks/taskactions is
 * questionable.
 */
isc_result_t
omapi_protocol_listen(omapi_object_t *mgr, isc_sockaddr_t *addr,
		      isc_boolean_t ((*verify_connection)
				     (isc_sockaddr_t *incoming,
				      void *connect_arg)),
		      isc_boolean_t ((*verify_key)
				     (const char *name,
				      unsigned int algorithm,
				      void *key_arg)),
		      isc_taskaction_t destroy_action, void *arg);

/*
 * Public functions defined in connection.c.
 */
void
omapi_connection_disconnect(omapi_object_t *connection, isc_boolean_t how);

isc_result_t
omapi_connection_putmem(omapi_object_t *connection, const unsigned char *data,
			unsigned int length);

isc_result_t
omapi_connection_putuint16(omapi_object_t *c, isc_uint32_t value);

isc_result_t
omapi_connection_putuint32(omapi_object_t *c, isc_uint32_t value);

isc_result_t
omapi_connection_putdata(omapi_object_t *connection, omapi_data_t *data);

isc_result_t
omapi_connection_putname(omapi_object_t *connection, const char *name);

isc_result_t
omapi_connection_putstring(omapi_object_t *connection, const char *string);

isc_result_t
omapi_connection_puthandle(omapi_object_t *connection, omapi_object_t *object);

/*
 * Public functions defined in listen.c.
 */
isc_result_t
omapi_listener_listen(omapi_object_t *mgr, isc_sockaddr_t *addr,
		      isc_boolean_t ((*verify_connection)
				     (isc_sockaddr_t *incoming,
				      void *connect_arg)),
		      isc_boolean_t ((*verify_key)
				     (const char *name,
				      unsigned int algorithm,
				      void *key_arg)),
		      isc_taskaction_t destroy_action, void *arg);

void
omapi_listener_shutdown(omapi_object_t *mgr);

/*
 * Public functions defined in message.c.
 */
isc_result_t
omapi_message_create(omapi_object_t **message);

void
omapi_message_register(omapi_object_t *message);

void
omapi_message_unregister(omapi_object_t *message);

isc_result_t
omapi_message_send(omapi_object_t *message, omapi_object_t *protocol);

/*
 * Public functions defined in lib.c.
 */
isc_result_t
omapi_lib_init(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
	       isc_socketmgr_t *socketmgr);

void
omapi_lib_destroy(void);

/*
 * Public functions defined in object.c.
 */
isc_result_t
omapi_object_create(omapi_object_t **object, omapi_objecttype_t *type,
		    size_t size);

void
omapi_object_reference(omapi_object_t **reference, omapi_object_t *object);

void
omapi_object_dereference(omapi_object_t **reference);

isc_result_t
omapi_object_register(omapi_objecttype_t **type, const char *name,
		      isc_result_t	((*set_value)(omapi_object_t *,
						      omapi_string_t *,
						      omapi_data_t *)),

		      isc_result_t 	((*get_value)(omapi_object_t *,
						      omapi_string_t *,
						      omapi_value_t **)),

		      void		((*destroy)(omapi_object_t *)),

		      isc_result_t	((*signal_handler)(omapi_object_t *,
							   const char *,
							   va_list)),

		      isc_result_t	((*stuff_values)(omapi_object_t *,
							 omapi_object_t *)),

		      isc_result_t	((*lookup)(omapi_object_t **,
						   omapi_object_t *)),

		      isc_result_t	((*create)(omapi_object_t **)),

		      isc_result_t	((*expunge)(omapi_object_t *)));

isc_result_t
omapi_object_set(omapi_object_t *handle, omapi_string_t *name,
		 omapi_data_t *value);

isc_result_t
omapi_object_setdata(omapi_object_t *handle, const char *name,
		     omapi_data_t *value);

isc_result_t
omapi_object_setboolean(omapi_object_t *handle, const char *name,
			isc_boolean_t value);

isc_result_t
omapi_object_setinteger(omapi_object_t *handle, const char *name,
			int value);

isc_result_t
omapi_object_setobject(omapi_object_t *handle, const char *name,
		       omapi_object_t *value);

isc_result_t
omapi_object_setstring(omapi_object_t *handle, const char *name,
		       const char *value);

isc_result_t
omapi_object_getvalue(omapi_object_t *handle, const char *name,
		      omapi_value_t **value);

isc_result_t
omapi_object_passgetvalue(omapi_object_t *object, omapi_string_t *name,
			  omapi_value_t **value);

isc_result_t
omapi_object_passsetvalue(omapi_object_t *object, omapi_string_t *name,
			  omapi_data_t *value);

isc_result_t
omapi_object_passsignal(omapi_object_t *object, const char *name,
			va_list args);

isc_result_t
omapi_object_passstuffvalues(omapi_object_t *connection,
			     omapi_object_t *object);

/*
 * Public functions defined in data.c.
 */
isc_result_t
omapi_data_create(omapi_data_t **data, omapi_datatype_t type, ...);

void
omapi_data_reference(omapi_data_t **reference, omapi_data_t *data);

void
omapi_data_dereference(omapi_data_t **reference);

int
omapi_data_strcmp(omapi_data_t *string_type, const char *string);

int
omapi_data_getint(omapi_data_t *data);

char *
omapi_data_strdup(isc_mem_t *mctx, omapi_data_t *t);

/*
 * Public functions defined in string.c.
 */
isc_result_t
omapi_string_create(omapi_string_t **string, unsigned int length);

void
omapi_string_reference(omapi_string_t **reference, omapi_string_t *string);

void
omapi_string_dereference(omapi_string_t **);

/*
 * XXXDCL consider better API
 */
void
omapi_string_totext(omapi_string_t *string, isc_region_t *region);

int
omapi_string_stringcmp(omapi_string_t *string1, omapi_string_t *string2);

int
omapi_string_strcmp(omapi_string_t *data_string, const char *string);

/*
 * Public functions defined in value.c.
 */
isc_result_t
omapi_value_create(omapi_value_t **value);

void
omapi_value_reference(omapi_value_t **reference, omapi_value_t *value);

void
omapi_value_dereference(omapi_value_t **reference);

isc_result_t
omapi_value_storedata(omapi_value_t **valuep, omapi_string_t *name,
		      omapi_data_t *value);

isc_result_t
omapi_value_storemem(omapi_value_t **valuep, omapi_string_t *name,
		     const unsigned char *value, unsigned int length);

isc_result_t
omapi_value_storeint(omapi_value_t **valuep, omapi_string_t *name,
		     int value);

isc_result_t
omapi_value_storeobject(omapi_value_t **valuep, omapi_string_t *name,
			omapi_object_t *handle);

isc_result_t
omapi_value_storestr(omapi_value_t **valuep, omapi_string_t *name,
		     char *string);

/*
 * XXXDCL for completeness, it would be good to have more functions that
 * can fetch the value out of an omapi_data_t into a form that a C progammer
 * is more used to working with.
 */
int
omapi_value_getint(omapi_value_t *value);

/*
 * WARNING: The region returned is (currently) only valid for as long
 * as the value pointer is valid, which means "until it is completely
 * dereferenced".  If you want to ensure it hangs around, you should
 * use omapi_value_reference to add another reference to the value pointer,
 * and then remember to use omapi_value_dereference to free it.
 * XXXDCL yes, kind of lame.  the interface to the omapi_value_get* functions
 * will probably change.
 */
void
omapi_value_getregion(omapi_value_t *value, isc_region_t *region);

ISC_LANG_ENDDECLS

#endif /* OMAPI_OMAPI_H */
