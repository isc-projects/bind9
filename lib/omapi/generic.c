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

/* $Id: generic.c,v 1.17 2000/08/01 01:32:51 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Subroutines that support the generic object.
 */

#include <config.h>

#include <stdlib.h>  /* Required on BSD/OS 3.1 for abort() used in va_arg(). */

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <omapi/private.h>

static isc_result_t
generic_setvalue(omapi_object_t *h, omapi_string_t *name, omapi_data_t *value)
{
	omapi_generic_t *g;
	omapi_value_t *new;
	omapi_value_t **va;
	int vm_new;
	unsigned int i;
	isc_result_t result;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	g = (omapi_generic_t *)h;

	/*
	 * See if there's already a value with this name attached to
	 * the generic object, and if so, replace the current value
	 * with the new one.
	 */
	for (i = 0; i < g->nvalues; i++) {
		if (omapi_string_stringcmp(name, g->values[i]->name) == 0) {
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
			result = omapi_value_create(&new);
			if (result != ISC_R_SUCCESS)
				return (result);

			omapi_string_reference(&new->name, name);
			if (value != NULL)
				omapi_data_reference(&new->value, value);

			omapi_value_dereference(&(g->values[i]));
			omapi_value_reference(&(g->values[i]), new);
			omapi_value_dereference(&new);

			return (ISC_R_SUCCESS);
		}
	}

	/*
	 * If the name isn't already attached to this object, see if an
	 * inner object has it.
	 */
	result = omapi_object_passsetvalue(h, name, value);
	if (result != ISC_R_NOTFOUND)
		return (result);

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
		/*
		 * Increase the maximum number of values by 10.
		 * 10 is an arbitrary constant.
		 */
		vm_new = g->va_max + 10;
		va = isc_mem_get(omapi_mctx, vm_new * sizeof(*va));
		if (va == NULL)
			return (ISC_R_NOMEMORY);
		if (g->va_max != 0) {
			memcpy(va, g->values, g->va_max * sizeof(*va));
			isc_mem_put(omapi_mctx, g->values,
				    g->va_max * sizeof(*va));
		}

		memset(va + g->va_max, 0, (vm_new - g->va_max) * sizeof(*va));
		g->values = va;
		g->va_max = vm_new;
	}
	result = omapi_value_create(&g->values[g->nvalues]);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_string_reference(&g->values[g->nvalues]->name, name);
	if (value != NULL)
		omapi_data_reference(&g->values[g->nvalues]->value, value);
	g->nvalues++;
	return (ISC_R_SUCCESS);
}

static isc_result_t
generic_getvalue(omapi_object_t *h, omapi_string_t *name,
		 omapi_value_t **value)
{
	unsigned int i;
	omapi_generic_t *g;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	g = (omapi_generic_t *)h;

	/*
	 * Look up the specified name in our list of objects.
	 */
	for (i = 0; i < g->nvalues; i++) {
		if (omapi_string_stringcmp(name, g->values[i]->name) == 0) {
			/*
			 * If this is a name/null value pair, this is the
			 * same as if there were no value that matched
			 * the specified name, so return ISC_R_NOTFOUND.
			 */
			if (g->values[i]->value == NULL)
				return (ISC_R_NOTFOUND);
			/*
			 * Otherwise, return the name/value pair.
			 */
			omapi_value_reference(value, g->values[i]);
			return (ISC_R_SUCCESS);
		}
	}

	return (omapi_object_passgetvalue(h, name, value));
}

static void
generic_destroy(omapi_object_t *h) {
	omapi_generic_t *g;
	unsigned int i;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	g = (omapi_generic_t *)h;

	if (g->values != NULL) {
		for (i = 0; i < g->nvalues; i++)
			if (g->values[i] != NULL)
				omapi_value_dereference(&g->values[i]);

		isc_mem_put(omapi_mctx, g->values,
			    g->va_max * sizeof(*g->values));
		g->values = NULL;
		g->va_max = 0;
	}
}

static isc_result_t
generic_signalhandler(omapi_object_t *h, const char *name, va_list ap) {
	REQUIRE(h != NULL && h->type == omapi_type_generic);

	/*
	 * XXXDCL I suppose that ideally the status would be set in all
	 * objects in the chain.
	 */
	if (strcmp(name, "status") == 0) {
		h->waitresult = va_arg(ap, isc_result_t);
		return (ISC_R_SUCCESS);
	}

	return (omapi_object_passsignal(h, name, ap));
}

/*
 * Write all the published values associated with the object through the
 * specified connection.
 */
static isc_result_t
generic_stuffvalues(omapi_object_t *connection, omapi_object_t *h) {
	omapi_generic_t *src;
	unsigned int i;
	isc_result_t result;

	REQUIRE(h != NULL && h->type == omapi_type_generic);

	src = (omapi_generic_t *)h;

	for (i = 0; i < src->nvalues; i++) {
		if (src->values[i] != NULL &&
		    src->values[i]->name->len != 0) {
			result = omapi_connection_putuint16(connection,
						   src->values[i]->name->len);
			if (result != ISC_R_SUCCESS)
				return (result);
			result = omapi_connection_putmem(connection,
						   src->values[i]->name->value,
						   src->values[i]->name->len);
			if (result != ISC_R_SUCCESS)
				return (result);

			result = omapi_connection_putdata(connection,
						       src->values[i]->value);
			if (result != ISC_R_SUCCESS)
				return (result);
		}
	}

	return (omapi_object_passstuffvalues(connection, h));
}

isc_result_t
generic_init(void) {
	return (omapi_object_register(&omapi_type_generic, "generic",
				      generic_setvalue,
				      generic_getvalue,
				      generic_destroy,
				      generic_signalhandler,
				      generic_stuffvalues,
				      NULL, NULL, NULL));
}
