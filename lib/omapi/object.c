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

/* $Id: object.c,v 1.1 2000/01/04 20:04:40 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Functions supporting memory allocation for the object management protocol.
 */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/error.h>

#include <omapi/private.h>

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
				OBJECT_DEREF(&(*h)->inner->outer, name);
			if (outer_reference != 0)
				OBJECT_DEREF(&(*h)->outer->inner, name);
			if ((*h)->type->destroy != NULL)
				(*((*h)->type->destroy))(*h, name);
			isc_mem_put(omapi_mctx, *h, (*h)->object_size);
		}
	}
	*h = NULL;
}
