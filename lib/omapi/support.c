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
 * Subroutines providing general support for objects.
 */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>

#include <omapi/private.h>

omapi_object_type_t *omapi_type_connection;
omapi_object_type_t *omapi_type_listener;
omapi_object_type_t *omapi_type_generic;
omapi_object_type_t *omapi_type_protocol;
omapi_object_type_t *omapi_type_protocol_listener;
omapi_object_type_t *omapi_type_message;

omapi_object_type_t *omapi_object_types;
int omapi_object_type_count;

isc_mem_t *omapi_mctx;
isc_taskmgr_t *omapi_taskmgr;
isc_socketmgr_t *omapi_socketmgr;

isc_boolean_t omapi_ipv6 = ISC_FALSE;

isc_result_t
omapi_init(isc_mem_t *mctx) {
	isc_result_t result;

	/*
	 * XXXDCL probeipv6?
	 */

	if (mctx != NULL)
		omapi_mctx = mctx;

	else {
		omapi_mctx = NULL;
		result = isc_mem_create(0, 0, &omapi_mctx);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	omapi_socketmgr = NULL;
	result = isc_socketmgr_create(omapi_mctx, &omapi_socketmgr);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_taskmgr = NULL;
	result = isc_taskmgr_create(omapi_mctx, 1, 0, &omapi_taskmgr);
	if (result != ISC_R_SUCCESS)
		return (result);

	if (isc_net_probeipv6() == ISC_R_SUCCESS)
		omapi_ipv6 = ISC_TRUE;
	else
		omapi_ipv6 = ISC_FALSE;
	
	/*
	 * Initialize all the standard object types.
	 */
	result = omapi_generic_init();
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_listener_init();
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_connection_init();
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_object_register(&omapi_type_protocol,
					    "protocol",
					    omapi_protocol_set_value,
					    omapi_protocol_get_value,
					    omapi_protocol_destroy,
					    omapi_protocol_signal_handler,
					    omapi_protocol_stuff_values,
					    0, 0, 0);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_object_register(&omapi_type_protocol_listener,
					    "protocol-listener",
					    omapi_protocol_listener_set_value,
					    omapi_protocol_listener_get_value,
					    omapi_protocol_listener_destroy,
					    omapi_protocol_listener_signal,
					    omapi_protocol_listener_stuff,
					    0, 0, 0);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_message_init();

	return (result);
}

/*
 * This does not free connections and other in-use objects, only the
 * things created by omapi_init().  It is the callers responsibility to
 * free the other things (as via omapi_connection_disconnect or
 * omapi_object_dereference).
 */
void
omapi_destroy() {
	omapi_object_type_t *type, *next_type;

	isc_socketmgr_destroy(&omapi_socketmgr);
	isc_taskmgr_destroy(&omapi_taskmgr);

	for (type = omapi_object_types; type != NULL; type = next_type) {
		next_type = type->next;
		isc_mem_put(omapi_mctx, type, sizeof(*type));
	}
}

isc_result_t
omapi_object_register(omapi_object_type_t **type, const char *name,
			   isc_result_t (*set_value)
					(omapi_object_t *,
					 omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_typed_data_t *),

			   isc_result_t (*get_value)
					(omapi_object_t *,
					 omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_value_t **),

			   void (*destroy)
					(omapi_object_t *),

			   isc_result_t (*signal_handler)
					(omapi_object_t *,
					 const char *, va_list),

			   isc_result_t (*stuff_values)
					(omapi_object_t *,
					 omapi_object_t *,
					 omapi_object_t *),

			   isc_result_t (*lookup)
					(omapi_object_t **,
					 omapi_object_t *,
					 omapi_object_t *),

			   isc_result_t (*create)
					(omapi_object_t **,
					 omapi_object_t *),

			   isc_result_t (*remove)
					(omapi_object_t *,
					 omapi_object_t *))
{
	omapi_object_type_t *t;

	t = isc_mem_get(omapi_mctx, sizeof(*t));
	if (t == NULL)
		return (ISC_R_NOMEMORY);
	memset(t, 0, sizeof(*t));

	t->name = name;
	t->set_value = set_value;
	t->get_value = get_value;
	t->destroy = destroy;
	t->signal_handler = signal_handler;
	t->stuff_values = stuff_values;
	t->lookup = lookup;
	t->create = create;
	t->remove = remove;
	t->next = omapi_object_types;
	omapi_object_types = t;
	if (type != NULL)
		*type = t;
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_signal(omapi_object_t *handle, const char *name, ...) {
	va_list ap;
	omapi_object_t *outer;
	isc_result_t result;

	va_start(ap, name);
	for (outer = handle; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->signal_handler != NULL)
		result = (*(outer->type->signal_handler))(outer, name, ap);
	else
		result = ISC_R_NOTFOUND;
	va_end(ap);
	return (result);
}

isc_result_t
omapi_signal_in(omapi_object_t *handle, const char *name, ...) {
	va_list ap;
	isc_result_t result;

	if (handle == NULL)
		return (ISC_R_NOTFOUND);

	va_start(ap, name);

	if (handle->type->signal_handler != NULL)
		result = (*(handle->type->signal_handler))(handle, name, ap);
	else
		result = ISC_R_NOTFOUND;

	va_end(ap);

	return (result);
}

isc_result_t
omapi_set_value(omapi_object_t *h, omapi_object_t *id,
		omapi_data_string_t *name, omapi_typed_data_t *value)
{
	omapi_object_t *outer;

	for (outer = h; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->set_value != NULL)
		return (*(outer->type->set_value))(outer, id, name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_set_value_str(omapi_object_t *h, omapi_object_t *id,
		    const char *name, omapi_typed_data_t *value) {
	omapi_data_string_t *nds;
	isc_result_t result;

	nds = NULL;
	result = omapi_data_newstring(&nds, strlen(name),
				      "omapi_set_value_str");
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(nds->value, name, strlen(name));

	return (omapi_set_value(h, id, nds, value));
}

isc_result_t
omapi_set_boolean_value(omapi_object_t *h, omapi_object_t *id,
			const char *name, int value)
{
	isc_result_t result;
	omapi_typed_data_t *tv = NULL;
	omapi_data_string_t *n = NULL;

	result = omapi_data_newstring(&n, strlen(name),
				      "omapi_set_boolean_value");
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_new(&tv, omapi_datatype_int, value);
	if (result != ISC_R_SUCCESS) {
		omapi_data_stringdereference(&n, "omapi_set_boolean_value");
		return (result);
	}

	result = omapi_set_value(h, id, n, tv);
	omapi_data_stringdereference(&n, "omapi_set_boolean_value");
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_set_int_value(omapi_object_t *h, omapi_object_t *id,
		    const char *name, int value)
{
	isc_result_t result;
	omapi_typed_data_t *tv = NULL;
	omapi_data_string_t *n = NULL;

	result = omapi_data_newstring(&n, strlen(name),
				      "omapi_set_int_value");
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_new(&tv, omapi_datatype_int, value);
	if (result != ISC_R_SUCCESS) {
		omapi_data_stringdereference(&n, "omapi_set_int_value");
		return (result);
	}

	result = omapi_set_value(h, id, n, tv);
	omapi_data_stringdereference(&n, "omapi_set_int_value");
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_set_object_value(omapi_object_t *h, omapi_object_t *id,
		       const char *name, omapi_object_t *value)
{
	isc_result_t result;
	omapi_typed_data_t *tv = NULL;
	omapi_data_string_t *n = NULL;

	result = omapi_data_newstring(&n, strlen(name),
				       "omapi_set_object_value");
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_new(&tv, omapi_datatype_object, value);
	if (result != ISC_R_SUCCESS) {
		omapi_data_stringdereference(&n, "omapi_set_object_value");
		return (result);
	}

	result = omapi_set_value(h, id, n, tv);
	omapi_data_stringdereference(&n, "omapi_set_object_value");
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_set_string_value(omapi_object_t *h, omapi_object_t *id,
		       const char *name, const char *value)
{
	isc_result_t result;
	omapi_typed_data_t *tv = NULL;
	omapi_data_string_t *n = NULL;

	result = omapi_data_newstring(&n, strlen(name),
				      "omapi_set_string_value");
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_new(&tv, omapi_datatype_string, value);
	if (result != ISC_R_SUCCESS) {
		omapi_data_stringdereference(&n, "omapi_set_string_value");
		return (result);
	}

	result = omapi_set_value(h, id, n, tv);
	omapi_data_stringdereference(&n, "omapi_set_string_value");
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_get_value(omapi_object_t *h, omapi_object_t *id,
		omapi_data_string_t *name, omapi_value_t **value)
{
	omapi_object_t *outer;

	for (outer = h; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->get_value != NULL)
		return (*(outer->type->get_value))(outer, id, name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_get_value_str(omapi_object_t *h, omapi_object_t *id,
		    const char *name, omapi_value_t **value)
{
	omapi_object_t *outer;
	omapi_data_string_t *nds;
	isc_result_t result;

	nds = NULL;
	result = omapi_data_newstring(&nds, strlen(name),
				      "omapi_get_value_str");
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(nds->value, name, strlen(name));

	for (outer = h; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->get_value != NULL)
		return (*(outer->type->get_value))(outer, id, nds, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_stuff_values(omapi_object_t *c, omapi_object_t *id, omapi_object_t *o) {
	omapi_object_t *outer;

	for (outer = o; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->stuff_values != NULL)
		return ((*(outer->type->stuff_values))(c, id, outer));
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_object_update(omapi_object_t *obj, omapi_object_t *id,
		    omapi_object_t *src, omapi_handle_t handle)
{
	omapi_generic_object_t *gsrc;
	isc_result_t result;
	unsigned int i;

	REQUIRE(src != NULL);

	if (src->type != omapi_type_generic)
		return (ISC_R_NOTIMPLEMENTED);
	gsrc = (omapi_generic_object_t *)src;

	for (i = 0; i < gsrc->nvalues; i++) {
		result = omapi_set_value(obj, id,
					 gsrc->values[i]->name,
					 gsrc->values[i]->value);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	if (handle != 0)
		omapi_set_int_value(obj, id, "remote-handle", (int)handle);

	result = omapi_signal(obj, "updated");

	if (result != ISC_R_NOTFOUND)
		return (result);

	return (ISC_R_SUCCESS);
}

int
omapi_data_string_cmp(omapi_data_string_t *s1, omapi_data_string_t *s2) {
	unsigned int len;
	int rv;

	if (s1->len > s2->len)
		len = s2->len;
	else
		len = s1->len;
	rv = memcmp(s1->value, s2->value, len);
	if (rv)
		return (rv);
	if (s1->len > s2->len)
		return (1);
	else if (s1->len < s2->len)
		return (-1);
	return (0);
}

int
omapi_ds_strcmp(omapi_data_string_t *s1, const char *s2) {
	unsigned int len, slen;
	int rv;

	slen = strlen(s2);
	if (slen > s1->len)
		len = s1->len;
	else
		len = slen;
	rv = memcmp(s1->value, s2, len);
	if (rv)
		return (rv);
	if (s1->len > slen)
		return (1);
	else if (s1->len < slen)
		return (-1);
	return (0);
}

int
omapi_td_strcmp(omapi_typed_data_t *s1, const char *s2) {
	unsigned int len, slen;
	int rv;

	REQUIRE(s1->type == omapi_datatype_data ||
		s1->type == omapi_datatype_string);

	slen = strlen(s2);
	if (slen > s1->u.buffer.len)
		len = s1->u.buffer.len;
	else
		len = slen;
	rv = memcmp(s1->u.buffer.value, s2, len);
	if (rv)
		return (rv);
	if (s1->u.buffer.len > slen)
		return (1);
	else if (s1->u.buffer.len < slen)
		return (-1);
	return (0);
}

isc_result_t
omapi_make_value(omapi_value_t **vp, omapi_data_string_t *name,
		 omapi_typed_data_t *value, const char *caller)
{
	isc_result_t result;

	result = omapi_data_newvalue(vp, caller);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_data_stringreference(&(*vp)->name, name, caller);

	if (value != NULL)
		omapi_data_reference(&(*vp)->value, value, caller);


	return (result);
}

isc_result_t
omapi_make_const_value(omapi_value_t **vp, omapi_data_string_t *name,
		       const unsigned char *value, unsigned int len,
		       const char *caller)
{
	isc_result_t result;

	result = omapi_data_newvalue(vp, caller);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_data_stringreference(&(*vp)->name, name, caller);

	if (value != NULL) {
		result = omapi_data_new(&(*vp)->value, omapi_datatype_data,
					len);
		if (result == ISC_R_SUCCESS)
			memcpy((*vp)->value->u.buffer.value, value, len);
	}

	if (result != ISC_R_SUCCESS)
		omapi_data_valuedereference(vp, caller);

	return (result);
}

isc_result_t
omapi_make_int_value(omapi_value_t **vp, omapi_data_string_t *name,
		     int value, const char *caller)
{
	isc_result_t result;

	result = omapi_data_newvalue(vp, caller);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_data_stringreference(&(*vp)->name, name, caller);

	if (value != 0) {
		result = omapi_data_new(&(*vp)->value, omapi_datatype_int);

		if (result == ISC_R_SUCCESS)
			(*vp)->value->u.integer = value;
	}

	if (result != ISC_R_SUCCESS)
		omapi_data_valuedereference(vp, caller);

	return (result);
}

isc_result_t
omapi_make_handle_value(omapi_value_t **vp, omapi_data_string_t *name,
			omapi_object_t *value, const char *caller)
{
	isc_result_t result;

	result = omapi_data_newvalue(vp, caller);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_data_stringreference(&(*vp)->name, name, caller);

	if (value != NULL) {
		result = omapi_data_new(&(*vp)->value, omapi_datatype_int);

		if (result == ISC_R_SUCCESS)
			result = (omapi_object_handle
				  ((omapi_handle_t *)&(*vp)->value->u.integer,
				   value));
	}

	if (result != ISC_R_SUCCESS)
		omapi_data_valuedereference(vp, caller);

	return (result);
}

isc_result_t
omapi_make_string_value(omapi_value_t **vp, omapi_data_string_t *name,
			char *value, const char *caller)
{
	isc_result_t result;

	result = omapi_data_newvalue(vp, caller);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_data_stringreference(&(*vp)->name, name, caller);

	if (value != NULL)
		result = omapi_data_new(&(*vp)->value, omapi_datatype_string,
					value);

	if (result != ISC_R_SUCCESS)
		omapi_data_valuedereference(vp, caller);

	return (result);
}

isc_result_t
omapi_get_int_value(unsigned long *v, omapi_typed_data_t *t) {
	isc_uint32_t rv;

	REQUIRE(t != NULL);
	REQUIRE(t->type == omapi_datatype_int ||
		((t->type == omapi_datatype_data ||
		 (t->type == omapi_datatype_string)) &&
		 t->u.buffer.len == sizeof(rv)));

	if (t->type == omapi_datatype_int) {
		*v = t->u.integer;

	} else if (t->type == omapi_datatype_string ||
		   t->type == omapi_datatype_data) {
		memcpy(&rv, t->u.buffer.value, sizeof rv);
		*v = ntohl (rv);
	}

	return (ISC_R_SUCCESS);
}
