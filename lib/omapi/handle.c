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

/* $Id: handle.c,v 1.17.4.1 2001/01/09 22:52:57 bwelling Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Functions for maintaining handles on objects.
 */

#include <config.h>

#include <isc/mem.h>
#include <isc/once.h>
#include <isc/string.h>
#include <isc/util.h>

#include <omapi/private.h>

/*
 * The handle table is a hierarchical tree designed for quick mapping
 * of handle identifiers to objects.  Objects contain their own handle
 * identifiers if they have them, so the reverse mapping is also
 * quick.  The hierarchy is made up of table objects, each of which
 * has 120 entries, a flag indicating whether the table is a leaf
 * table or an indirect table, the handle of the first object covered
 * by the table and the first object after that that's *not* covered
 * by the table, a count of how many objects of either type are
 * currently stored in the table, and an array of 120 entries pointing
 * either to objects or tables.
 *
 * When we go to add an object to the table, we look to see if the
 * next object handle to be assigned is covered by the outermost
 * table.  If it is, we find the place within that table where the
 * next handle should go, and if necessary create additional nodes in
 * the tree to contain the new handle.  The pointer to the object is
 * then stored in the correct position.
 *
 * XXXTL
 * Theoretically, we could have some code here to free up handle
 * tables as they go out of use, but by and large handle tables won't
 * go out of use, so this is being skipped for now.  It shouldn't be
 * too hard to implement in the future if there's a different
 * application.
 */

#define OMAPI_HANDLETABLE_SIZE 120

typedef struct omapi_handletable {
	omapi_handle_t		first;
	omapi_handle_t		limit;
	omapi_handle_t		next;
	isc_boolean_t		leaf;
	union {
		omapi_object_t *		object;
		struct omapi_handletable *	table;
	} children[OMAPI_HANDLETABLE_SIZE];
} omapi_handletable_t;

static omapi_handletable_t *toptable;
static omapi_handle_t next_handle = 1;	/* Next handle to be assigned. */
static isc_mutex_t mutex;		/* To lock the 2 previous variables. */
static isc_once_t once = ISC_ONCE_INIT; /* To initialize the mutex. */

/*
 * initialize_mutex() is called by isc_once_do in object_gethandle()
 */
static void
initialize_mutex(void) {
	RUNTIME_CHECK(isc_mutex_init(&mutex) == ISC_R_SUCCESS);
}

static isc_result_t
table_enclose(omapi_handletable_t **table) {
	omapi_handletable_t *inner = *table;
	omapi_handletable_t *new;
	int idx, base, scale;

	/*
	 * The scale of the table we're enclosing is going to be the
	 * difference between its "first" and "limit" members.  So the
	 * scale of the table enclosing it is going to be that multiplied
	 * by the table size.
	 */
	scale = (inner->first - inner->limit) * OMAPI_HANDLETABLE_SIZE;

	/*
	 * The range that the enclosing table covers is going to be
	 * the result of subtracting the remainder of dividing the
	 * enclosed table's first entry number by the enclosing
	 * table's scale.  If handle IDs are being allocated
	 * sequentially, the enclosing table's "first" value will be
	 * the same as the enclosed table's "first" value.
	 */
	base = inner->first - inner->first % scale;

	/*
	 * The index into the enclosing table at which the enclosed table
	 * will be stored is going to be the difference between the "first"
	 * value of the enclosing table and the enclosed table - zero, if
	 * we are allocating sequentially.
	 */
	idx = (base - inner->first) / OMAPI_HANDLETABLE_SIZE;

	new = isc_mem_get(omapi_mctx, sizeof(*new));
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, sizeof *new);
	new->first = base;
	new->limit = base + scale;
	if (scale == OMAPI_HANDLETABLE_SIZE)
		new->leaf = ISC_FALSE;
	new->children[idx].table = inner;
	*table = new;
	return (ISC_R_SUCCESS);
}

static isc_result_t
handle_store(omapi_handle_t h, omapi_handletable_t *table, omapi_object_t *o) {
	omapi_handletable_t *inner;
	omapi_handle_t scale, idx;
	isc_result_t result;

	if (table->first > h || table->limit <= h)
		return (ISC_R_NOSPACE);

	/*
	 * If this is a leaf table, just stash the object in the
	 * appropriate place.
	 */
	if (table->leaf) {
		OBJECT_REF(&table->children[h - table->first].object, o);
		o->handle = h;
		return (ISC_R_SUCCESS);
	}

	/*
	 * Scale is the number of handles represented by each child of this
	 * table.   For a leaf table, scale would be 1.   For a first level
	 * of indirection, 120.   For a second, 120 * 120.   Et cetera.
	 */
	scale = (table->limit - table->first) / OMAPI_HANDLETABLE_SIZE;

	/*
	 * So the next most direct table from this one that contains the
	 * handle must be the subtable of this table whose index into this
	 * table's array of children is the handle divided by the scale.
	 */
	idx = (h - table->first) / scale;
	inner = table->children[idx].table;

	/*
	 * If there is no more direct table than this one in the slot
	 * we came up with, make one.
	 */
	if (inner == NULL) {
		inner = isc_mem_get(omapi_mctx, sizeof(*inner));
		if (inner == NULL)
			return (ISC_R_NOMEMORY);
		memset(inner, 0, sizeof(*inner));
		inner->first = idx * scale + table->first;
		inner->limit = inner->first + scale;
		if (scale == OMAPI_HANDLETABLE_SIZE)
			inner->leaf = ISC_TRUE;
		table->children[idx].table = inner;
	}

	result = handle_store(h, inner, o);
	if (result == ISC_R_NOSPACE) {
		result = (table_enclose
			  (&table->children[idx].table));
		if (result != ISC_R_SUCCESS)
			return (result);

		return (handle_store(h, table->children[idx].table, o));
	}
	return (result);
}

isc_result_t
object_gethandle(omapi_handle_t *h, omapi_object_t *o) {
	isc_result_t result = ISC_R_SUCCESS;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	LOCK(&mutex);

	if (o->handle != 0) {
		*h = o->handle;
		UNLOCK(&mutex);
		return (ISC_R_SUCCESS);
	}

	if (toptable == NULL) {
		toptable = isc_mem_get(omapi_mctx, sizeof(*toptable));
		if (toptable != NULL) {
			memset(toptable, 0, sizeof(*toptable));
			toptable->first = 0;
			toptable->limit = OMAPI_HANDLETABLE_SIZE;
			toptable->leaf = ISC_TRUE;

		} else
			result = ISC_R_NOMEMORY;
	}

	if (result == ISC_R_SUCCESS)
		/*
		 * If this handle doesn't fit in the outer table, we need to
		 * make a new outer table.  This is a while loop in case for
		 * some reason we decide to do disjoint handle allocation,
		 * where the next level of indirection still isn't big enough
		 * to enclose the next handle ID.
		 */
		while (next_handle >= toptable->limit) {
			omapi_handletable_t *new;

			new = isc_mem_get(omapi_mctx, sizeof(*new));
			if (new != NULL) {
				memset(new, 0, sizeof(*new));
				new->first = 0;
				new->limit = toptable->limit *
					OMAPI_HANDLETABLE_SIZE;
				new->leaf = ISC_FALSE;
				new->children[0].table = toptable;
				toptable = new;

			} else
				result = ISC_R_NOMEMORY;
		}

	/*
	 * Try to cram this handle into the existing table.
	 */
	if (result == ISC_R_SUCCESS)
		result = handle_store(next_handle, toptable, o);

	if (result == ISC_R_NOSPACE) {
		result = table_enclose(&toptable);
		if (result == ISC_R_SUCCESS)
			result = handle_store(next_handle, toptable, o);
	}

	/*
	 * If it worked, return the next handle and increment it.
	 */
	if (result == ISC_R_SUCCESS)
		*h = next_handle++;

	UNLOCK(&mutex);
	return (result);
}

static isc_result_t
lookup_iterate(omapi_object_t **o, omapi_handle_t h,
		 omapi_handletable_t *table)
{
	omapi_handletable_t *inner;
	omapi_handle_t scale, idx;

	if (table == NULL || table->first > h || table->limit <= h)
		return (ISC_R_NOTFOUND);

	/*
	 * If this is a leaf table, just grab the object.
	 */
	if (table->leaf) {
		/*
		 * Not there?
		 */
		if (table->children[h - table->first].object == NULL)
			return (ISC_R_NOTFOUND);

		OBJECT_REF(o, table->children[h - table->first].object);
		return (ISC_R_SUCCESS);
	}

	/*
	 * Scale is the number of handles represented by each child of this
	 * table.   For a leaf table, scale would be 1.   For a first level
	 * of indirection, 120.   For a second, 120 * 120.   Et cetera.
	 */
	scale = (table->limit - table->first) / OMAPI_HANDLETABLE_SIZE;

	/*
	 * So the next most direct table from this one that contains the
	 * handle must be the subtable of this table whose index into this
	 * table's array of children is the handle divided by the scale.
	 */
	idx = (h - table->first) / scale;
	inner = table->children[idx].table;

	return (lookup_iterate(o, h, inner));
}

isc_result_t
handle_lookup(omapi_object_t **o, omapi_handle_t h) {
	isc_result_t result;

	LOCK(&mutex);

	result = lookup_iterate(o, h, toptable);

	UNLOCK(&mutex);

	return (result);
}

static void
free_table(omapi_handletable_t **table) {
	int i;

	if ((*table)->leaf)
		isc_mem_put(omapi_mctx, *table, sizeof(**table));

	else
		for (i = 0; i < OMAPI_HANDLETABLE_SIZE; i++)
			if ((*table)->children[i].table != NULL)
				free_table(&(*table)->children[i].table);
			else
				break;

	*table = NULL;
}

void
handle_destroy(void) {
	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	LOCK(&mutex);

	if (toptable != NULL)
		free_table(&toptable);

	UNLOCK(&mutex);

	DESTROYLOCK(&mutex);
}
