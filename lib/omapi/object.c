/*
 * Copyright (C) 1996, 1997, 1998, 1999, 2000  Internet Software Consortium.
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

/* $Id: object.c,v 1.14 2000/03/18 00:34:53 tale Exp $ */

/* Principal Author: Ted Lemon */

#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

struct omapi_objecttype {
	const char *		name;
	omapi_objecttype_t *	next;
	
	isc_result_t		(*set_value)(omapi_object_t *object,
					     omapi_string_t *name,
					     omapi_data_t *value);

	isc_result_t		(*get_value)(omapi_object_t *object,
					     omapi_string_t *name,
					     omapi_value_t **value);

	void			(*destroy)(omapi_object_t *object);

	isc_result_t		(*signal_handler)(omapi_object_t *object,
						  const char *name,
						  va_list args);

	isc_result_t		(*stuff_values)(omapi_object_t *connection,
						omapi_object_t *object);

	isc_result_t		(*lookup)(omapi_object_t **object,
					  omapi_object_t *key);

	isc_result_t		(*create)(omapi_object_t **object);

	isc_result_t		(*remove)(omapi_object_t *object);
};

isc_result_t
omapi_object_create(omapi_object_t **object, omapi_objecttype_t *type,
		    size_t size)
{
	omapi_object_t *new;

	REQUIRE(object != NULL && *object == NULL);
	REQUIRE(size > 0 || type == NULL);

	if (type == NULL) {
		type = omapi_type_generic;
		size = sizeof(omapi_generic_t);
	}

	new = isc_mem_get(omapi_mctx, size);
	if (new == NULL)
		return (ISC_R_NOMEMORY);

	memset(new, 0, size);

	new->object_size = size;
	new->refcnt = 1;
	new->type = type;

	*object = new;

	return (ISC_R_SUCCESS);
}

void
omapi_object_reference(omapi_object_t **r, omapi_object_t *h) {
	REQUIRE(r != NULL && *r == NULL);
	REQUIRE(h != NULL);

	*r = h;
	h->refcnt++;
}

void
omapi_object_dereference(omapi_object_t **h) {
	int outer_reference = 0;
	int inner_reference = 0;
	int handle_reference = 0;
	int extra_references;
	omapi_object_t *p = NULL;

	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	/*
	 * See if this object's inner object refers back to it, but don't
	 * count this as a reference if we're being asked to free the
	 * reference from the inner object.
	 */
	/*
	 * XXXDCL my wording
	 * Note whether the object being dereferenced has an inner object, but
	 * only if the inner object's own outer pointer is not what is
	 * being dereferenced.
	 * (XXXDCL when does it happen that way ?)
	 */
	if ((*h)->inner != NULL && (*h)->inner->outer != NULL &&
	    h != &((*h)->inner->outer))
		inner_reference = 1;

	/*
	 * Ditto for the outer object.
	 */
	if ((*h)->outer != NULL && (*h)->outer->inner != NULL &&
	    h != &((*h)->outer->inner))
		outer_reference = 1;

	/*
	 * Ditto for the handle object.  The code below assumes that
	 * the only reason we'd get a dereference from the handle
	 * table is if this function does it - otherwise we'd have to
	 * traverse the handle table to find the address where the
	 * reference is stored and compare against that, and we don't
	 * want to do that if we can avoid it.
	 */
	if ((*h)->handle != 0)
		handle_reference = 1;

	/*
	 * If we are getting rid of the last reference other than
	 * references to inner and outer objects, or from the handle
	 * table, then we must examine all the objects in either
	 * direction to see if they hold any non-inner, non-outer,
	 * non-handle-table references.  If not, we need to free the
	 * entire chain of objects.
	 */
	INSIST((*h)->refcnt >=
	       inner_reference + outer_reference + handle_reference + 1);

	if ((*h)->refcnt ==
	    inner_reference + outer_reference + handle_reference + 1) {
		/*
		 * If refcnt is > 1, then inner_reference + outer_reference +
		 * handle_reference is > 0, so there are list references to
		 * chase.
		 */
		if ((*h)->refcnt > 1) {
			/*
			 * XXXTL we could check for a reference from the
                         * handle table here.
			 */
			extra_references = 0;

			if (inner_reference != 0)
				for (p = (*h)->inner;
				     p != NULL && extra_references == 0;
				     p = p->inner) {
					extra_references += p->refcnt - 1;
					if (p->inner != NULL)
						--extra_references;
					if (p->handle != 0)
						--extra_references;
				}

			if (outer_reference != 0)
				for (p = (*h)->outer;
				     p != NULL && extra_references == 0;
				     p = p->outer) {
					extra_references += p->refcnt - 1;
					if (p->outer != NULL)
						--extra_references;
					if (p->handle != 0)
						--extra_references;
				}
		} else
			extra_references = 0;

		if (extra_references == 0) {
			isc_taskaction_t action = (*h)->destroy_action;
			void *arg = (*h)->destroy_arg;

			if (inner_reference != 0)
				OBJECT_DEREF(&(*h)->inner);
			if (outer_reference != 0)
				OBJECT_DEREF(&(*h)->outer);
			if ((*h)->type->destroy != NULL)
				(*((*h)->type->destroy))(*h);
			(*h)->refcnt = 0;
			isc_mem_put(omapi_mctx, *h, (*h)->object_size);

			if (action != NULL) {
				isc_event_t *event;

				event = isc_event_allocate(omapi_mctx, *h,
						       OMAPI_EVENT_OBJECTFREED,
						       action, arg,
						       sizeof(isc_event_t));
				if (event != NULL)
					isc_task_send(omapi_task, &event);
			}

		} else
			(*h)->refcnt--;
			
	} else
		(*h)->refcnt--;

	*h = NULL;
}

isc_result_t
omapi_object_register(omapi_objecttype_t **type, const char *name,
		      isc_result_t (*set_value)(omapi_object_t *,
						omapi_string_t *,
						omapi_data_t *),

		      isc_result_t (*get_value)(omapi_object_t *,
						omapi_string_t *,
						omapi_value_t **),

		      void (*destroy)(omapi_object_t *),

		      isc_result_t (*signal_handler)(omapi_object_t *,
						     const char *, va_list),

		      isc_result_t (*stuff_values)(omapi_object_t *,
						   omapi_object_t *),

		      isc_result_t (*lookup)(omapi_object_t **,
					     omapi_object_t *),

		      isc_result_t (*create)(omapi_object_t **),

		      isc_result_t (*remove)(omapi_object_t *))
{
	omapi_objecttype_t *t;

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

omapi_objecttype_t *
object_findtype(omapi_value_t *tv) {
	omapi_objecttype_t *type;

	for (type = omapi_object_types; type != NULL; type = type->next)
		if (omapi_data_strcmp(tv->value, type->name) == 0)
			break;

	return (type);
}

void
object_destroytypes(void) {
	omapi_objecttype_t *type, *next_type;

	for (type = omapi_object_types; type != NULL; type = next_type) {
		next_type = type->next;
		isc_mem_put(omapi_mctx, type, sizeof(*type));
	}

	omapi_object_types = NULL;
}

/*
 * Call the signal method for an object chain, starting at the outermost
 * object.
 */
isc_result_t
object_signal(omapi_object_t *handle, const char *name, ...) {
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

/*
 * Call the signal method for the named object.  Used by message_process().
 */
isc_result_t
object_vsignal(omapi_object_t *handle, const char *name, va_list ap) {
	REQUIRE(handle != NULL);

	if (handle->type->signal_handler != NULL)
		return ((handle->type->signal_handler)(handle, name, ap));
	else
		return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_object_set(omapi_object_t *h, omapi_string_t *name, omapi_data_t *value)
{
	omapi_object_t *outer;

	for (outer = h; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->set_value != NULL)
		return (*(outer->type->set_value))(outer, name, value);
	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_object_setdata(omapi_object_t *h, const char *name, omapi_data_t *value)
{
	omapi_string_t *nds;
	isc_result_t result;

	nds = NULL;
	result = omapi_string_create(&nds, strlen(name));
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(nds->value, name, strlen(name));

	return (omapi_object_set(h, nds, value));
}

isc_result_t
omapi_object_setboolean(omapi_object_t *h, const char *name,
			isc_boolean_t value)
{
	int boolean_value;
	isc_result_t result;
	omapi_data_t *tv = NULL;
	omapi_string_t *n = NULL;

	result = omapi_string_create(&n, strlen(name));
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	boolean_value = (value == ISC_TRUE ? 1 : 0);

	result = omapi_data_create(&tv, omapi_datatype_int, boolean_value);
	if (result != ISC_R_SUCCESS) {
		omapi_string_dereference(&n);
		return (result);
	}

	result = omapi_object_set(h, n, tv);
	omapi_string_dereference(&n);
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_object_setinteger(omapi_object_t *h, const char *name, int value) {
	isc_result_t result;
	omapi_data_t *tv = NULL;
	omapi_string_t *n = NULL;

	result = omapi_string_create(&n, strlen(name));
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_create(&tv, omapi_datatype_int, value);
	if (result != ISC_R_SUCCESS) {
		omapi_string_dereference(&n);
		return (result);
	}

	result = omapi_object_set(h, n, tv);
	omapi_string_dereference(&n);
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_object_setobject(omapi_object_t *h, const char *name,
		       omapi_object_t *value)
{
	isc_result_t result;
	omapi_data_t *tv = NULL;
	omapi_string_t *n = NULL;

	result = omapi_string_create(&n, strlen(name));
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_create(&tv, omapi_datatype_object, value);
	if (result != ISC_R_SUCCESS) {
		omapi_string_dereference(&n);
		return (result);
	}

	result = omapi_object_set(h, n, tv);
	omapi_string_dereference(&n);
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_object_setstring(omapi_object_t *h, const char *name, const char *value)
{
	isc_result_t result;
	omapi_data_t *tv = NULL;
	omapi_string_t *n = NULL;

	result = omapi_string_create(&n, strlen(name));
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(n->value, name, strlen(name));

	result = omapi_data_create(&tv, omapi_datatype_string, value);
	if (result != ISC_R_SUCCESS) {
		omapi_string_dereference(&n);
		return (result);
	}

	result = omapi_object_set(h, n, tv);
	omapi_string_dereference(&n);
	omapi_data_dereference(&tv);
	return (result);
}

isc_result_t
omapi_object_getvalue(omapi_object_t *h, const char *name, 
		      omapi_value_t **value)
{
	omapi_object_t *outer;
	omapi_string_t *nds;
	isc_result_t result;

	nds = NULL;
	result = omapi_string_create(&nds, strlen(name));
	if (result != ISC_R_SUCCESS)
		return (result);
	memcpy(nds->value, name, strlen(name));

	for (outer = h; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->get_value != NULL)
		result = (*(outer->type->get_value))(outer, nds, value);
	else
		result = ISC_R_NOTFOUND;

	omapi_string_dereference(&nds);

	return (result);
}

isc_result_t
object_stuffvalues(omapi_object_t *connection, omapi_object_t *object) {
	omapi_object_t *outer;

	for (outer = object; outer->outer != NULL; outer = outer->outer)
		;
	if (outer->type->stuff_values != NULL)
		return ((*(outer->type->stuff_values))(connection, outer));
	return (ISC_R_NOTFOUND);
}

isc_result_t
object_update(omapi_object_t *obj, omapi_object_t *src, omapi_handle_t handle)
{
	omapi_generic_t *gsrc;
	isc_result_t result;
	unsigned int i;

	REQUIRE(src != NULL);

	if (src->type != omapi_type_generic)
		return (ISC_R_NOTIMPLEMENTED);

	gsrc = (omapi_generic_t *)src;

	for (i = 0; i < gsrc->nvalues; i++) {
		result = omapi_object_set(obj,
					  gsrc->values[i]->name,
					  gsrc->values[i]->value);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	if (handle != 0)
		omapi_object_setinteger(obj, "remote-handle", (int)handle);

	result = object_signal(obj, "updated");

	if (result != ISC_R_NOTFOUND)
		return (result);

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_object_passgetvalue(omapi_object_t *object, omapi_string_t *name,
			  omapi_value_t **value)
{
	if (PASS_CHECK(object, get_value))
		return (*(object->inner->type->get_value))(object->inner,
							   name, value);
	else
		return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_object_passsetvalue(omapi_object_t *object, omapi_string_t *name,
			  omapi_data_t *value)
{
	if (PASS_CHECK(object, set_value))
		return (*(object->inner->type->set_value))(object->inner,
							   name, value);
	else
		return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_object_passsignal(omapi_object_t *object, const char *name, va_list ap) {
	if (PASS_CHECK(object, signal_handler))
		return (*(object->inner->type->signal_handler))(object->inner,
								name, ap);
	else
		return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_object_passstuffvalues(omapi_object_t *connection,
			     omapi_object_t *object)
{
	if (PASS_CHECK(object, stuff_values))
		return (*(object->inner->type->stuff_values))(connection,
							      object->inner);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
object_methodlookup(omapi_objecttype_t *type, omapi_object_t **object,
		    omapi_object_t *key)
{
	if (type->lookup != NULL)
		return ((*(type->lookup))(object, key));
	else
		return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
object_methodcreate(omapi_objecttype_t *type, omapi_object_t **object) {
	if (type->create != NULL)
		return ((*(type->create))(object));
	else
		return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
object_methodremove(omapi_objecttype_t *type, omapi_object_t *object) {
	if (type->remove != NULL)
		return ((*(type->remove))(object));
	else
		return (ISC_R_NOTIMPLEMENTED);
}
