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

/* $Id: alloc.c,v 1.2 1999/11/02 04:01:30 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Functions supporting memory allocation for the object management protocol.
 */
#include <stdlib.h>		/* malloc, free */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/omapip_p.h>

void
omapi_object_reference(omapi_object_t **r, omapi_object_t *h,
		       const char *name)
{
	REQUIRE(r != NULL && *r == NULL);
	REQUIRE(h != NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_object_dereference(omapi_object_t **h, const char *name) {
	int outer_reference = 0;
	int inner_reference = 0;
	int handle_reference = 0;
	int extra_references;
	omapi_object_t *p;

	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	/*
	 * See if this object's inner object refers to it, but don't
	 * count this as a reference if we're being asked to free the
	 * reference from the inner object.
	 */
	if ((*h)->inner && (*h)->inner->outer && h != &((*h)->inner->outer))
		inner_reference = 1;

	/*
	 * Ditto for the outer object.
	 */
	if ((*h)->outer && (*h)->outer->inner && h != &((*h)->outer->inner))
		outer_reference = 1;

	/*
	 * Ditto for the outer object.  The code below assumes that
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
	if ((*h)->refcnt ==
	    inner_reference + outer_reference + handle_reference + 1) {
		if (inner_reference  != 0 ||
		    outer_reference  != 0 ||
		    handle_reference != 0) {
			/*
			 * XXXTL we could check for a reference from the
                         * handle table here.
			 */
			extra_references = 0;
			for (p = (*h)->inner;
			     p != NULL && extra_references == 0;
			     p = p->inner) {
				extra_references += p->refcnt - 1;
				if (p->inner != NULL)
					--extra_references;
				if (p->handle != 0)
					--extra_references;
			}
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
			if (inner_reference != 0)
				omapi_object_dereference(&(*h)->inner->outer,
							 name);
			if (outer_reference != 0)
				omapi_object_dereference(&(*h)->outer->inner,
							 name);
			if ((*h)->type->destroy != NULL)
				(*((*h)->type->destroy))(*h, name);
			free(*h);
		}
	}
	*h = NULL;
}

isc_result_t
omapi_buffer_new(omapi_buffer_t **h, const char *name) {
	omapi_buffer_t *t;

	REQUIRE(h != NULL && *h == NULL);

	t = (omapi_buffer_t *)malloc(sizeof *t);
	if (t == NULL)
		return (ISC_R_NOMEMORY);
	memset(t, 0, sizeof *t);

	omapi_buffer_reference(h, t, name);

	(*h)->head = sizeof((*h)->data) - 1;

	return (ISC_R_SUCCESS);
}

void
omapi_buffer_reference(omapi_buffer_t **r, omapi_buffer_t *h, const char *name)
{
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_buffer_dereference(omapi_buffer_t **h, const char *name) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	(void)name;		/* Unused. */

	if (--(*h)->refcnt == 0)
		free (*h);
	*h = NULL;
}

isc_result_t
omapi_typed_data_new(omapi_typed_data_t **t, omapi_datatype_t type, ...) {
	va_list l;
	omapi_typed_data_t *new;
	unsigned int len;
	unsigned int val;
	int intval;
	char *s;

	REQUIRE(type == omapi_datatype_int ||
		type == omapi_datatype_string ||
		type == omapi_datatype_data ||
		type == omapi_datatype_object);

	va_start(l, type);

	/*
	 * Quiet bogus "might be used uninitialized in this function" warnings.
	 */
	val = 0;
	intval = 0;
	s = NULL;

	switch (type) {
	      case omapi_datatype_int:
		len = OMAPI_TYPED_DATA_INT_LEN;
		intval = va_arg(l, int);
		break;
	      case omapi_datatype_string:
		s = va_arg(l, char *);
		val = strlen(s);
		len = OMAPI_TYPED_DATA_NOBUFFER_LEN + val;
		break;
	      case omapi_datatype_data:
		val = va_arg(l, unsigned int);
		len = OMAPI_TYPED_DATA_NOBUFFER_LEN + val;
		break;
	      case omapi_datatype_object:
		len = OMAPI_TYPED_DATA_OBJECT_LEN;
		break;
	      default:
                UNEXPECTED_ERROR(__FILE__, __LINE__,
                                 "unknown type in omapi_typed_data_new: %d\n",
				 type);
                return (ISC_R_UNEXPECTED);
	}

	new = malloc(len);
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, len);

	switch (type) {
	      case omapi_datatype_int:
		new->u.integer = intval;
		break;
	      case omapi_datatype_string:
		memcpy(new->u.buffer.value, s, val);
		new->u.buffer.len = val;
		break;
	      case omapi_datatype_data:
		new->u.buffer.len = val;
		break;
	      case omapi_datatype_object:
		omapi_object_reference(&new->u.object,
				       va_arg(l, omapi_object_t *),
				       "omapi_datatype_new");
		break;
	}
	new->type = type;
	omapi_typed_data_reference(t, new, "omapi_typed_data_new");

	return (ISC_R_SUCCESS);
}

void
omapi_typed_data_reference(omapi_typed_data_t **r, omapi_typed_data_t *h,
			   const char *name)
{
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r != NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_typed_data_dereference(omapi_typed_data_t **h, const char *name) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	if (--((*h)->refcnt) <= 0) {
		switch ((*h)->type) {
		      case omapi_datatype_int:
		      case omapi_datatype_string:
		      case omapi_datatype_data:
		      default:
			break;
		      case omapi_datatype_object:
			omapi_object_dereference(&(*h)->u.object, name);
			break;
		}
		free(*h);
	}
	*h = NULL;
}

isc_result_t
omapi_data_string_new(omapi_data_string_t **d, unsigned int len,
		      const char *name)
{
	omapi_data_string_t *new;

	new = malloc(OMAPI_DATA_STRING_EMPTY_SIZE + len);
	if (new != NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, OMAPI_DATA_STRING_EMPTY_SIZE);
	new->len = len;

	omapi_data_string_reference(d, new, name);

	return (ISC_R_SUCCESS);
}

void
omapi_data_string_reference(omapi_data_string_t **r, omapi_data_string_t *h,
					  const char *name)
{
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_data_string_dereference(omapi_data_string_t **h, const char *name) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	(void)name;		/* Unused. */

	if (--((*h)->refcnt) <= 0)
		free (*h);

	*h = NULL;
}

isc_result_t
omapi_value_new(omapi_value_t **d, const char *name) {
	omapi_value_t *new;

	new = malloc(sizeof *new);
	if (new != NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, sizeof *new);

	omapi_value_reference(d, new, name);

	return (ISC_R_SUCCESS);
}

void
omapi_value_reference(omapi_value_t **r, omapi_value_t *h, const char *name) {
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_value_dereference(omapi_value_t **h, const char *name) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	(void)name;		/* Unused. */

	if (--((*h)->refcnt) <= 0) {
		if ((*h)->name)
			omapi_data_string_dereference(&(*h)->name, name);
		if ((*h)->value)
			omapi_typed_data_dereference(&(*h)->value, name);
		free (*h);
	}
	*h = NULL;
}

