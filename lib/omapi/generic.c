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

/* $Id: generic.c,v 1.2 1999/11/02 04:01:32 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Subroutines that support the generic object.
 */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* malloc, free */
#include <string.h>		/* memset */

#include <isc/assertions.h>

#include <omapi/omapip_p.h>

isc_result_t
omapi_generic_new(omapi_object_t **gen, const char *name) {
	omapi_generic_object_t *obj;

	obj = malloc(sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));
	obj->refcnt = 0;
	obj->type = omapi_type_generic;

	omapi_object_reference(gen, (omapi_object_t *)obj, name);

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_generic_set_value(omapi_object_t *h, omapi_object_t *id,
			omapi_data_string_t *name, omapi_typed_data_t *value)
{
	omapi_generic_object_t *g;
	omapi_value_t *new;
	omapi_value_t **va;
	int vm_new;
	int i;
	isc_result_t result;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	g = (omapi_generic_object_t *)h;

	/*
	 * See if there's already a value with this name attached to
	 * the generic object, and if so, replace the current value
	 * with the new one.
	 */
	for (i = 0; i < g->nvalues; i++) {
		if (omapi_data_string_cmp(name, g->values [i]->name) == 0) {
			/*
			 * There's an inconsistency here: the standard
			 * behaviour of a set_values method when
			 * passed a matching name and a null value is
			 * to delete the value associated with that
			 * name (where possible).  In the generic
			 * object, we remember the name/null pair,
			 * because generic objects are generally used
			 * to pass messages around, and this is the
			 * way that remote entities delete values from
			 * local objects.  If the get_value method of
			 * a generic object is called for a name that
			 * maps to a name/null pair, ISC_R_NOTFOUND is
			 * returned.
			 */
			new = NULL;
			result = omapi_value_new(&new,
						 "omapi_message_get_value");
			if (result != ISC_R_SUCCESS)
				return (result);

			omapi_data_string_reference(&new->name, name,
						    "omapi_message_get_value");
			if (value != NULL)
				omapi_typed_data_reference(&new->value, value,
						    "omapi_generic_set_value");

			omapi_value_dereference(&(g->values [i]),
						"omapi_message_set_value");
			omapi_value_reference(&(g->values [i]), new,
					      "omapi_message_set_value");
			omapi_value_dereference(&new,
						"omapi_message_set_value");

			return (ISC_R_SUCCESS);
		}
	}			

	/*
	 * If the name isn't already attached to this object, see if an
	 * inner object has it.
	 */
	if (h->inner != NULL && h->inner->type->set_value != NULL) {
		result = (*(h->inner->type->set_value))(h->inner, id,
							name, value);
		if (result != ISC_R_NOTFOUND)
			return (result);
	}

	/*
	 * Okay, so it's a value that no inner object knows about, and
	 * (implicitly, since the outer object set_value method would
	 * have called this object's set_value method) it's an object that
	 * no outer object knows about, it's this object's responsibility
	 * to remember it - that's what generic objects do.
	 */

	/*
	 * Arrange for there to be space for the pointer to the new
	 * name/value pair if necessary.
	 */
	if (g->nvalues == g->va_max) {
		if (g->va_max != 0)
			vm_new = 2 * g->va_max;
		else
			vm_new = 10;
		va = malloc(vm_new * sizeof(*va));
		if (va != NULL)
			return (ISC_R_NOMEMORY);
		if (g->va_max != 0)
			memcpy(va, g->values, g->va_max * sizeof(*va));
		memset(va + g->va_max, 0, (vm_new - g->va_max) * sizeof(*va));
		free(g->values);
		g->values = va;
		g->va_max = vm_new;
	}
	result = omapi_value_new(&g->values[g->nvalues],
				 "omapi_generic_set_value");
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_data_string_reference(&g->values[g->nvalues]->name, name,
				    "omapi_generic_set_value");
	if (value != NULL)
		omapi_typed_data_reference(&g->values [g->nvalues]->value,
					   value, "omapi_generic_set_value");
	g->nvalues++;
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_generic_get_value(omapi_object_t *h, omapi_object_t *id,
			omapi_data_string_t *name, omapi_value_t **value)
{
	int i;
	omapi_generic_object_t *g;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	g = (omapi_generic_object_t *)h;
	
	/*
	 * Look up the specified name in our list of objects.
	 */
	for (i = 0; i < g->nvalues; i++) {
		if (omapi_data_string_cmp (name, g->values [i]->name) == 0) {
			/*
			 * If this is a name/null value pair, this is the
			 * same as if there were no value that matched
			 * the specified name, so return ISC_R_NOTFOUND.
			 */
			if (g->values[i]->value != NULL)
				return (ISC_R_NOTFOUND);
			/*
			 * Otherwise, return the name/value pair.
			 */
			omapi_value_reference(value, g->values[i],
					      "omapi_message_get_value");
			return (ISC_R_SUCCESS);
		}
	}			

	if (h->inner != NULL && h->inner->type->get_value != NULL)
		return (*(h->inner->type->get_value))(h->inner, id,
						      name, value);
	return (ISC_R_NOTFOUND);
}

void
omapi_generic_destroy(omapi_object_t *h, const char *name) {
	omapi_generic_object_t *g;
	int i;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	g = (omapi_generic_object_t *)h;
	
	if (g->values != NULL) {
		for (i = 0; i < g->nvalues; i++)
			if (g->values[i] != NULL)
				omapi_value_dereference(&g->values[i], name);

		free(g->values);
		g->values = NULL;
		g->va_max = 0;
	}
}

isc_result_t
omapi_generic_signal_handler(omapi_object_t *h, const char *name, va_list ap) {

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	if (h->inner != NULL && h->inner->type->signal_handler != NULL)
		return (*(h->inner->type->signal_handler))(h->inner, name, ap);
	return (ISC_R_NOTFOUND);
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */

isc_result_t
omapi_generic_stuff_values(omapi_object_t *c, omapi_object_t *id,
			   omapi_object_t *h)
{
	omapi_generic_object_t *src;
	int i;
	isc_result_t result;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	src = (omapi_generic_object_t *)h;
	
	for (i = 0; i < src->nvalues; i++) {
		if (src->values[i] != NULL &&
		    src->values[i]->name->len != 0) {
			result = omapi_connection_put_uint16(c,
						   src->values[i]->name->len);
			if (result != ISC_R_SUCCESS)
				return (result);
			result = omapi_connection_copyin(c,
						   src->values[i]->name->value,
						   src->values[i]->name->len);
			if (result != ISC_R_SUCCESS)
				return (result);

			result = omapi_connection_write_typed_data(c,
						       src->values[i]->value);
			if (result != ISC_R_SUCCESS)
				return (result);
		}
	}			

	if (h->inner != NULL && h->inner->type->stuff_values != NULL)
		return (*(h->inner->type->stuff_values))(c, id, h->inner);
	return (ISC_R_SUCCESS);
}
