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

/* $Id: handle.c,v 1.4 2000/01/13 06:13:23 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * Functions for maintaining handles on objects.
 */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/boolean.h>

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

#define OMAPI_HANDLE_TABLE_SIZE 120

typedef struct omapi_handle_table {
	omapi_handle_t		first;
	omapi_handle_t		limit;
	omapi_handle_t		next;
	isc_boolean_t		leaf;
	union {
		omapi_object_t *		object;
		struct omapi_handle_table *	table;
	} children[OMAPI_HANDLE_TABLE_SIZE];
} omapi_handle_table_t;

omapi_handle_table_t *omapi_handle_table;
omapi_handle_t omapi_next_handle = 1;	/* Next handle to be assigned. */

/*
 * Forward declarations.
 */
static isc_result_t
omapi_handle_lookup_in(omapi_object_t **object, omapi_handle_t handle,
		       omapi_handle_table_t *table);
static isc_result_t
omapi_object_handle_in_table(omapi_handle_t handle,
			     omapi_handle_table_t *table,
			     omapi_object_t *object);
static isc_result_t
omapi_handle_table_enclose(omapi_handle_table_t **table);

isc_result_t
omapi_object_handle(omapi_handle_t *h, omapi_object_t *o) {
	isc_result_t result;

	if (o->handle != 0) {
		*h = o->handle;
		return (ISC_R_SUCCESS);
	}
	
	if (omapi_handle_table == NULL) {
		omapi_handle_table = isc_mem_get(omapi_mctx,
						 sizeof(*omapi_handle_table));
		if (omapi_handle_table == NULL)
			return (ISC_R_NOMEMORY);
		memset(omapi_handle_table, 0, sizeof(*omapi_handle_table));
		omapi_handle_table->first = 0;
		omapi_handle_table->limit = OMAPI_HANDLE_TABLE_SIZE;
		omapi_handle_table->leaf = ISC_TRUE;
	}

	/*
	 * If this handle doesn't fit in the outer table, we need to
	 * make a new outer table.  This is a while loop in case for
	 * some reason we decide to do disjoint handle allocation,
	 * where the next level of indirection still isn't big enough
	 * to enclose the next handle ID.
	 */

	while (omapi_next_handle >= omapi_handle_table->limit) {
		omapi_handle_table_t *new;
		
		new = isc_mem_get(omapi_mctx, sizeof(*new));
		if (new == NULL)
			return (ISC_R_NOMEMORY);
		memset(new, 0, sizeof(*new));
		new->first = 0;
		new->limit = (omapi_handle_table->limit *
			      OMAPI_HANDLE_TABLE_SIZE);
		new->leaf = ISC_FALSE;
		new->children[0].table = omapi_handle_table;
		omapi_handle_table = new;
	}

	/*
	 * Try to cram this handle into the existing table.
	 */
	result = omapi_object_handle_in_table(omapi_next_handle,
					      omapi_handle_table, o);
	/*
	 * If it worked, return the next handle and increment it.
	 */
	if (result == ISC_R_SUCCESS) {
		*h = omapi_next_handle;
		omapi_next_handle++;
		return (ISC_R_SUCCESS);
	}
	if (result != ISC_R_NOSPACE)
		return (result);

	result = omapi_handle_table_enclose(&omapi_handle_table);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = omapi_object_handle_in_table(omapi_next_handle,
					      omapi_handle_table, o);
	if (result != ISC_R_SUCCESS)
		return (result);

	*h = omapi_next_handle;
	omapi_next_handle++;

	return (ISC_R_SUCCESS);
}

static isc_result_t
omapi_object_handle_in_table(omapi_handle_t h, omapi_handle_table_t *table,
			     omapi_object_t *o)
{
	omapi_handle_table_t *inner;
	omapi_handle_t scale, index;
	isc_result_t result;

	if (table->first > h || table->limit <= h)
		return (ISC_R_NOSPACE);
	
	/*
	 * If this is a leaf table, just stash the object in the
	 * appropriate place.
	 */
	if (table->leaf) {
		OBJECT_REF(&table->children[h - table->first].object, o,
			  "omapi_object_handle_in_table");
		o->handle = h;
		return (ISC_R_SUCCESS);
	}

	/*
	 * Scale is the number of handles represented by each child of this
	 * table.   For a leaf table, scale would be 1.   For a first level
	 * of indirection, 120.   For a second, 120 * 120.   Et cetera.
	 */
	scale = (table->limit - table->first) / OMAPI_HANDLE_TABLE_SIZE;

	/*
	 * So the next most direct table from this one that contains the
	 * handle must be the subtable of this table whose index into this
	 * table's array of children is the handle divided by the scale.
	 */
	index = (h - table->first) / scale;
	inner = table->children[index].table;

	/*
	 * If there is no more direct table than this one in the slot
	 * we came up with, make one.
	 */
	if (inner == NULL) {
		inner = isc_mem_get(omapi_mctx, sizeof(*inner));
		if (inner == NULL)
			return (ISC_R_NOMEMORY);
		memset(inner, 0, sizeof(*inner));
		inner->first = index * scale + table->first;
		inner->limit = inner->first + scale;
		if (scale == OMAPI_HANDLE_TABLE_SIZE)
			inner->leaf = ISC_TRUE;
		table->children[index].table = inner;
	}

	result = omapi_object_handle_in_table(h, inner, o);
	if (result == ISC_R_NOSPACE) {
		result = (omapi_handle_table_enclose
			  (&table->children[index].table));
		if (result != ISC_R_SUCCESS)
			return (result);

		return (omapi_object_handle_in_table(h,
					     table->children[index].table, o));
	}
	return (result);
}

static isc_result_t
omapi_handle_table_enclose(omapi_handle_table_t **table) {
	omapi_handle_table_t *inner = *table;
	omapi_handle_table_t *new;
	int index, base, scale;

	/*
	 * The scale of the table we're enclosing is going to be the
	 * difference between its "first" and "limit" members.  So the
	 * scale of the table enclosing it is going to be that multiplied
	 * by the table size.
	 */
	scale = (inner->first - inner->limit) * OMAPI_HANDLE_TABLE_SIZE;

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
	index = (base - inner->first) / OMAPI_HANDLE_TABLE_SIZE;

	new = isc_mem_get(omapi_mctx, sizeof(*new));
	if (new == NULL)
		return (ISC_R_NOMEMORY);
	memset(new, 0, sizeof *new);
	new->first = base;
	new->limit = base + scale;
	if (scale == OMAPI_HANDLE_TABLE_SIZE)
		new->leaf = ISC_FALSE;
	new->children[index].table = inner;
	*table = new;
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_handle_lookup(omapi_object_t **o, omapi_handle_t h) {
	return (omapi_handle_lookup_in(o, h, omapi_handle_table));
}

static isc_result_t
omapi_handle_lookup_in(omapi_object_t **o, omapi_handle_t h,
		       omapi_handle_table_t *table)
{
	omapi_handle_table_t *inner;
	omapi_handle_t scale, index;

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

		OBJECT_REF(o, table->children[h - table->first].object,
			   "omapi_handle_lookup_in");
		return (ISC_R_SUCCESS);
	}

	/*
	 * Scale is the number of handles represented by each child of this
	 * table.   For a leaf table, scale would be 1.   For a first level
	 * of indirection, 120.   For a second, 120 * 120.   Et cetera.
	 */
	scale = (table->limit - table->first) / OMAPI_HANDLE_TABLE_SIZE;

	/*
	 * So the next most direct table from this one that contains the
	 * handle must be the subtable of this table whose index into this
	 * table's array of children is the handle divided by the scale.
	 */
	index = (h - table->first) / scale;
	inner = table->children[index].table;

	return (omapi_handle_lookup_in(o, h, table->children[index].table));
}

/*
 * For looking up objects based on handles that have been sent on the wire.
 */
isc_result_t
omapi_handle_td_lookup(omapi_object_t **obj, omapi_typed_data_t *h) {
	omapi_handle_t handle;

	REQUIRE(h != NULL);
	REQUIRE(h->type == omapi_datatype_int ||
		(h->type == omapi_datatype_data &&
		 h->u.buffer.len == sizeof(handle)));

	if (h->type == omapi_datatype_int)
		handle = h->u.integer;

	else if (h->type == omapi_datatype_data &&
		 h->u.buffer.len == sizeof(handle)) {
		memcpy(&handle, h->u.buffer.value, sizeof(handle));
		handle = ntohl(handle);
	}

	return (omapi_handle_lookup(obj, handle));
}
