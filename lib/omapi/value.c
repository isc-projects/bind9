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

/* $Id: value.c,v 1.6 2000/05/08 14:38:22 tale Exp $ */

/* Principal Author: Ted Lemon */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <omapi/private.h>

isc_result_t
omapi_value_create(omapi_value_t **d) {
	omapi_value_t *new;

	new = isc_mem_get(omapi_mctx, sizeof(*new));
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, sizeof *new);

	omapi_value_reference(d, new);

	return (ISC_R_SUCCESS);
}

void
omapi_value_reference(omapi_value_t **r, omapi_value_t *h) {
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	*r = h;
	h->refcnt++;
}

void
omapi_value_dereference(omapi_value_t **h) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	if (--((*h)->refcnt) <= 0) {
		if ((*h)->name != NULL)
			omapi_string_dereference(&(*h)->name);
		if ((*h)->value != NULL)
			omapi_data_dereference(&(*h)->value);
		isc_mem_put(omapi_mctx, *h, sizeof(omapi_value_t));
	}
	*h = NULL;
}

isc_result_t
omapi_value_storedata(omapi_value_t **vp, omapi_string_t *name,
		      omapi_data_t *value)
{
	isc_result_t result;

	result = omapi_value_create(vp);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_string_reference(&(*vp)->name, name);

	if (value != NULL)
		omapi_data_reference(&(*vp)->value, value);


	return (result);
}

isc_result_t
omapi_value_storemem(omapi_value_t **vp, omapi_string_t *name,
		     const unsigned char *value, unsigned int len)
{
	isc_result_t result;

	result = omapi_value_create(vp);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_string_reference(&(*vp)->name, name);

	if (value != NULL) {
		result = omapi_data_create(&(*vp)->value,
					   omapi_datatype_data, len);
		if (result == ISC_R_SUCCESS)
			memcpy((*vp)->value->u.buffer.value, value, len);
	}

	if (result != ISC_R_SUCCESS)
		omapi_value_dereference(vp);

	return (result);
}

isc_result_t
omapi_value_storeint(omapi_value_t **vp, omapi_string_t *name, int value)
{
	isc_result_t result;

	result = omapi_value_create(vp);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_string_reference(&(*vp)->name, name);

	if (value != 0) {
		result = omapi_data_create(&(*vp)->value, omapi_datatype_int);

		if (result == ISC_R_SUCCESS)
			(*vp)->value->u.integer = value;
	}

	if (result != ISC_R_SUCCESS)
		omapi_value_dereference(vp);

	return (result);
}

isc_result_t
omapi_value_storeobject(omapi_value_t **vp, omapi_string_t *name,
			omapi_object_t *value)
{
	isc_result_t result;

	result = omapi_value_create(vp);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_string_reference(&(*vp)->name, name);

	if (value != NULL) {
		result = omapi_data_create(&(*vp)->value, omapi_datatype_int);

		if (result == ISC_R_SUCCESS)
			result = object_gethandle((omapi_handle_t *)
						  &(*vp)->value->u.integer,
						  value);
	}

	if (result != ISC_R_SUCCESS)
		omapi_value_dereference(vp);

	return (result);
}

isc_result_t
omapi_value_storestr(omapi_value_t **vp, omapi_string_t *name, char *value)
{
	isc_result_t result;

	result = omapi_value_create(vp);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_string_reference(&(*vp)->name, name);

	if (value != NULL)
		result = omapi_data_create(&(*vp)->value,
					   omapi_datatype_string, value);

	if (result != ISC_R_SUCCESS)
		omapi_value_dereference(vp);

	return (result);
}

int
omapi_value_getint(omapi_value_t *value) {
	REQUIRE(value != NULL && value->value != NULL);
	REQUIRE(value->value->type == omapi_datatype_int ||
		((value->value->type == omapi_datatype_data ||
		 (value->value->type == omapi_datatype_string)) &&
		 value->value->u.buffer.len == sizeof(isc_uint32_t)));

	return (omapi_data_getint(value->value));
}

/*
 * WARNING:  The region is valid only as long as the value pointer
 * is valid.  See omapi.h.
 */
void
omapi_value_getregion(omapi_value_t *value, isc_region_t *region) {
	REQUIRE(value != NULL && value->value != NULL);
	REQUIRE(value->value->type == omapi_datatype_data ||
		value->value->type == omapi_datatype_string);

	/*
	 * Boy, the word "value" appears a lot.  Almost like a Smurf song.
	 * La la la la la la, la la la la la.
	 */
	region->base = value->value->u.buffer.value;
	region->length = value->value->u.buffer.len;
}

