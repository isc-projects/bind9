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

/* $Id: string.c,v 1.9.4.1 2001/01/09 22:53:05 bwelling Exp $ */

/* Principal Author: Ted Lemon */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <omapi/private.h>

isc_result_t
omapi_string_create(omapi_string_t **d, unsigned int len) {
	omapi_string_t *new;

	new = isc_mem_get(omapi_mctx, OMAPI_STRING_EMPTY_SIZE + len);
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, OMAPI_STRING_EMPTY_SIZE);
	new->len = len;

	omapi_string_reference(d, new);

	return (ISC_R_SUCCESS);
}

void
omapi_string_reference(omapi_string_t **r, omapi_string_t *h) {
	REQUIRE(r != NULL && h != NULL);
	REQUIRE(*r == NULL);

	*r = h;
	h->refcnt++;
}

void
omapi_string_dereference(omapi_string_t **h) {
	REQUIRE(h != NULL && *h != NULL);
	REQUIRE((*h)->refcnt > 0);

	if (--((*h)->refcnt) <= 0)
		isc_mem_put(omapi_mctx, *h,
			    OMAPI_STRING_EMPTY_SIZE + (*h)->len);

	*h = NULL;
}

void
omapi_string_totext(omapi_string_t *string, isc_region_t *region) {
	REQUIRE(string != NULL && region != NULL);

	region->base = string->value;
	region->length = string->len;
}

int
omapi_string_stringcmp(omapi_string_t *s1, omapi_string_t *s2) {
	unsigned int len;
	int order;

	if (s1->len > s2->len)
		len = s2->len;
	else
		len = s1->len;

	order = memcmp(s1->value, s2->value, len);
	if (order == 0) {
		if (s1->len > s2->len)
			order = 1;
		else if (s1->len < s2->len)
			order = -1;
	}

	return (order);
}

int
omapi_string_strcmp(omapi_string_t *s1, const char *s2) {
	unsigned int len, slen;
	int order;

	slen = strlen(s2);
	if (slen > s1->len)
		len = s1->len;
	else
		len = slen;

	order = memcmp(s1->value, s2, len);
	if (order == 0) {
		if (s1->len > slen)
			order = 1;
		else if (s1->len < slen)
			order= -1;
	}

	return (order);
}
