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

/* $Id: data.c,v 1.2 2000/01/13 06:13:21 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Functions supporting memory allocation for the object management protocol.
 */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

isc_result_t
omapi_data_new(omapi_typed_data_t **t, omapi_datatype_t type, ...) {
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
                                 "unknown type in omapi_data_new: %d\n",
				 type);
                return (ISC_R_UNEXPECTED);
	}

	new = isc_mem_get(omapi_mctx, len);
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
		OBJECT_REF(&new->u.object, va_arg(l, omapi_object_t *),
			  "omapi_datatype_new");
		break;
	}
	new->type = type;
	omapi_data_reference(t, new, "omapi_data_new");

	return (ISC_R_SUCCESS);
}

void
omapi_data_reference(omapi_typed_data_t **r, omapi_typed_data_t *h,
		     const char *name)
{
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_data_dereference(omapi_typed_data_t **h, const char *name) {
	int length = 0;


	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	if (--((*h)->refcnt) <= 0) {
		switch ((*h)->type) {
		case omapi_datatype_int:
			length = OMAPI_TYPED_DATA_INT_LEN;
			break;
		case omapi_datatype_string:
			length = OMAPI_TYPED_DATA_NOBUFFER_LEN +
				(*h)->u.buffer.len;
			break;
		case omapi_datatype_data:
			length = OMAPI_TYPED_DATA_NOBUFFER_LEN +
				(*h)->u.buffer.len;
			break;
		case omapi_datatype_object:
			OBJECT_DEREF(&(*h)->u.object, name);
			length = OMAPI_TYPED_DATA_OBJECT_LEN;
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "unknown datatype in "
				    "omapi_data_dereference: %d\n",
				    (*h)->type);
			/* NOTREACHED */
			return;
		}
		isc_mem_put(omapi_mctx, *h, length);
	}

	*h = NULL;
}

isc_result_t
omapi_data_newstring(omapi_data_string_t **d, unsigned int len,
		     const char *name)
{
	omapi_data_string_t *new;

	new = isc_mem_get(omapi_mctx, OMAPI_DATA_STRING_EMPTY_SIZE + len);
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, OMAPI_DATA_STRING_EMPTY_SIZE);
	new->len = len;

	omapi_data_stringreference(d, new, name);

	return (ISC_R_SUCCESS);
}

void
omapi_data_stringreference(omapi_data_string_t **r, omapi_data_string_t *h,
					  const char *name)
{
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_data_stringdereference(omapi_data_string_t **h, const char *name) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	(void)name;		/* Unused. */

	if (--((*h)->refcnt) <= 0)
		isc_mem_put(omapi_mctx, *h,
			    OMAPI_DATA_STRING_EMPTY_SIZE + (*h)->len);

	*h = NULL;
}

isc_result_t
omapi_data_newvalue(omapi_value_t **d, const char *name) {
	omapi_value_t *new;

	new = isc_mem_get(omapi_mctx, sizeof(*new));
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, sizeof *new);

	omapi_data_valuereference(d, new, name);

	return (ISC_R_SUCCESS);
}

void
omapi_data_valuereference(omapi_value_t **r, omapi_value_t *h,
			  const char *name)
{
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	(void)name;		/* Unused. */

	*r = h;
	h->refcnt++;
}

void
omapi_data_valuedereference(omapi_value_t **h, const char *name) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	(void)name;		/* Unused. */

	if (--((*h)->refcnt) <= 0) {
		if ((*h)->name != NULL)
			omapi_data_stringdereference(&(*h)->name, name);
		if ((*h)->value != NULL)
			omapi_data_dereference(&(*h)->value, name);
		isc_mem_put(omapi_mctx, *h, sizeof(*h));
	}
	*h = NULL;
}

