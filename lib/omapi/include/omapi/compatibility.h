/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: compatibility.h,v 1.6.4.1 2001/01/09 22:53:11 bwelling Exp $ */

#ifndef OMAPI_COMPATIBILITY_H
#define OMAPI_COMPATIBILITY_H 1

#include <isc/result.h>

/*****
 ***** Macro definitions for partial compatability with Ted Lemon's original
 ***** design of OMAPI for DCHP.  The intent is that with by using this header
 ***** than few changes need be made immediately to the source code in order
 ***** to get it working with the updated OMAPI library.  The other changes
 ***** can then be made as is convenient.
 *****/

/*
 * Waiting is done inherently on the client now.  It didn't seem to me
 * that the server needs it, but if it does, connection_wait() could
 * be made public as omapi_connection_wait().
 */
#define omapi_wait_for_completion(o, t)	ISC_R_SUCCESS

#define omapi_value_new(v, i)		omapi_value_create(v)
#define omapi_make_value		omapi_value_storedata
#define omapi_make_const_value		omapi_value_storemem
#define omapi_make_int_value		omapi_value_storeint
#define omapi_make_handle_value		omapi_value_storeobject
#define omapi_make_string_value		omapi_value_storestr

#define omapi_data_new			omapi_data_create
#define omapi_td_strcmp			omapi_data_strcmp
#define omapi_get_int_value		omapi_data_getint

#define omapi_data_string_new(s, l, i)	omapi_string_create(s, l)
#define omapi_data_string_cmp		omapi_string_stringcmp
#define omapi_ds_strcmp			omapi_string_strcmp

/*
 * The get_value, set_value and stuff_values methods all had their id
 * parameter removed, so those functions for special client/server objects
 * need to have their definitions adjusted.
 *
 */
#define omapi_set_value(h, id, name, value) \
	omapi_object_set(h, name, value)
#define omapi_set_value_str(h, id, name, value) \
	omapi_object_setdata(h, name, value)
#define omapi_set_boolean_value(h, id, name, value) \
	omapi_object_setboolean(h, name, value)
#define omapi_set_int_value(h, id, name, value) \
	omapi_object_setinteger(h, name, value)
#define omapi_set_object_value(h, id, name, value) \
	omapi_object_setobject(h, name, value)
#define omapi_set_string_value(h, id, name, value) \
	omapi_object_setstring(h, name, value)
#define omapi_get_value_str(h, id, name, value) \
	omapi_object_getvalue(h, name, value)
#define omapi_object_type_register	omapi_object_register

#define omapi_init			omapi_lib_init

#define omapi_message_new(m, id)	omapi_message_create(m)
#define omapi_protocol_send_message(po, id, mo, omo) \
	omapi_message_send(mo, po)

#define omapi_listen			omapi_listener_listen

#define omapi_connection_copyin		omapi_connection_putmem
#define omapi_connection_put_uint16	omapi_connection_putuin16
#define omapi_connection_put_uint32	omapi_connection_putuin32
#define omapi_connection_put_name	omapi_connection_putname
#define omapi_connection_put_string	omapi_connection_putstring
#define omapi_connection_put_handle	omapi_connection_puthandle
#define omapi_connection_write_typed_data	omapi_connection_putdata

#endif /* OMAPI_COMPATIBILITY_H */
