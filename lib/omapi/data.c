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

/* $Id: data.c,v 1.18 2000/10/11 21:19:00 marka Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Functions supporting memory allocation for the object management protocol.
 */

#include <config.h>

#include <stdlib.h>  /* Required on BSD/OS 3.1 for abort() used in va_arg(). */

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <omapi/private.h>

isc_result_t
omapi_data_create(omapi_data_t **t, omapi_datatype_t type, ...) {
	va_list l;
	omapi_data_t *new;
	unsigned int len;
	unsigned int val;
	int intval;
	char *s;

	REQUIRE(type == omapi_datatype_int ||
		type == omapi_datatype_data ||
		type == omapi_datatype_string ||
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
		len = OMAPI_DATA_INT_LEN;
		intval = va_arg(l, int);
		break;
	case omapi_datatype_string:
		s = va_arg(l, char *);
		val = strlen(s);
		len = OMAPI_DATA_NOBUFFER_LEN + val;
		break;
	case omapi_datatype_data:
		val = va_arg(l, unsigned int);
		len = OMAPI_DATA_NOBUFFER_LEN + val;
		break;
	case omapi_datatype_object:
		len = OMAPI_DATA_OBJECT_LEN;
		break;
	default:
                UNEXPECTED_ERROR(__FILE__, __LINE__,
                                 "unknown type in omapi_data_create: %d",
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
		OBJECT_REF(&new->u.object, va_arg(l, omapi_object_t *));
		break;
	}
	new->type = type;
	omapi_data_reference(t, new);

	return (ISC_R_SUCCESS);
}

void
omapi_data_reference(omapi_data_t **r, omapi_data_t *h) {
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	*r = h;
	h->refcnt++;
}

void
omapi_data_dereference(omapi_data_t **h) {
	unsigned int length = 0;


	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	if (--((*h)->refcnt) == 0) {
		switch ((*h)->type) {
		case omapi_datatype_int:
			length = OMAPI_DATA_INT_LEN;
			break;
		case omapi_datatype_string:
			length = OMAPI_DATA_NOBUFFER_LEN + (*h)->u.buffer.len;
			break;
		case omapi_datatype_data:
			length = OMAPI_DATA_NOBUFFER_LEN + (*h)->u.buffer.len;
			break;
		case omapi_datatype_object:
			OBJECT_DEREF(&(*h)->u.object);
			length = OMAPI_DATA_OBJECT_LEN;
			break;
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "unknown datatype in "
				    "omapi_data_dereference: %d\n",
				    (*h)->type);
			/* NOTREACHED */
			break;
		}
		isc_mem_put(omapi_mctx, *h, length);
	}

	*h = NULL;
}


int
omapi_data_strcmp(omapi_data_t *s1, const char *s2) {
	unsigned int len, slen;
	int order;

	REQUIRE(s1->type == omapi_datatype_data ||
		s1->type == omapi_datatype_string);

	slen = strlen(s2);
	if (slen > s1->u.buffer.len)
		len = s1->u.buffer.len;
	else
		len = slen;

	order = memcmp(s1->u.buffer.value, s2, len);
	if (order == 0) {
		if (s1->u.buffer.len > slen)
			order = 1;
		else if (s1->u.buffer.len < slen)
			order = -1;
	}

	return (order);
}

int
omapi_data_getint(omapi_data_t *t) {
	isc_uint32_t stored_value; /* Stored in network byte order. */

	REQUIRE(t != NULL);
	REQUIRE(t->type == omapi_datatype_int ||
		((t->type == omapi_datatype_data ||
		 (t->type == omapi_datatype_string)) &&
		 t->u.buffer.len == sizeof(stored_value)));

	if (t->type == omapi_datatype_int)
		return (t->u.integer);

	memcpy(&stored_value, t->u.buffer.value, sizeof(stored_value));

	return (ntohl(stored_value));
}

char *
omapi_data_strdup(isc_mem_t *mctx, omapi_data_t *t) {
	char *s;

	REQUIRE(mctx != NULL && t != NULL);
	REQUIRE(t->type == omapi_datatype_string ||
		t->type == omapi_datatype_data);

	s = isc_mem_allocate(mctx, t->u.buffer.len + 1);
	if (s != NULL) {
		memcpy(s, t->u.buffer.value, t->u.buffer.len);
		s[t->u.buffer.len] = '\0';
	}

	return (s);
}
