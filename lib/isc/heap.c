/*
 * Copyright (c) 1997, 1998 by Internet Software Consortium.
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

/*
 * Heap implementation of priority queues adapted from the following:
 *
 *	_Introduction to Algorithms_, Cormen, Leiserson, and Rivest,
 *	MIT Press / McGraw Hill, 1990, ISBN 0-262-03141-8, chapter 7.
 *
 *	_Algorithms_, Second Edition, Sedgewick, Addison-Wesley, 1988,
 *	ISBN 0-201-06673-4, chapter 11.
 */

#include <stdlib.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/heap.h>

/*
 * Note: to make heap_parent and heap_left easy to compute, the first
 * element of the heap array is not used; i.e. heap subscripts are 1-based,
 * not 0-based.
 */
#define heap_parent(i)			((i) >> 1)
#define heap_left(i)			((i) << 1)

#define SIZE_INCREMENT			1024

#define HEAP_MAGIC			0x48454150U	/* HEAP. */
#define VALID_HEAP(h)			((h) != NULL && \
					 (h)->magic == HEAP_MAGIC)

struct heap_context {
	unsigned int			magic;
	mem_context_t			mctx;
	unsigned int			size;
	unsigned int			size_increment;
	unsigned int			last;
	void				**array;
	heap_higher_priority_func	higher_priority;
	heap_index_func			index;
};

isc_result
heap_create(mem_context_t mctx, heap_higher_priority_func higher_priority,
	    heap_index_func index, unsigned int size_increment,
	    heap_t *heapp)
{
	heap_t heap;

	REQUIRE(heapp != NULL && *heapp == NULL);
	REQUIRE(higher_priority != NULL);

	heap = mem_get(mctx, sizeof *heap);
	if (heap == NULL)
		return (ISC_R_NOMEMORY);
	heap->magic = HEAP_MAGIC;
	heap->size = 0;
	if (size_increment == 0)
		heap->size_increment = SIZE_INCREMENT;
	else
		heap->size_increment = size_increment;
	heap->last = 0;
	heap->array = NULL;
	heap->higher_priority = higher_priority;
	heap->index = index;

	*heapp = heap;
	
	return (ISC_R_SUCCESS);
}

void
heap_destroy(heap_t *heapp) {
	heap_t heap;

	REQUIRE(heapp != NULL);
	heap = *heapp;
	REQUIRE(VALID_HEAP(heap));

	if (heap->array != NULL)
		mem_put(heap->mctx, heap->array,
			heap->size * sizeof (void *));
	heap->magic = 0;
	mem_put(heap->mctx, heap, sizeof *heap);

	*heapp = NULL;
}

static boolean_t
resize(heap_t heap) {
	void **new_array;
	size_t new_size;

	REQUIRE(VALID_HEAP(heap));

	new_size = heap->size + heap->size_increment;
	new_array = mem_get(heap->mctx, new_size * sizeof (void *));
	if (new_array == NULL)
		return (FALSE);
	memcpy(new_array, heap->array, heap->size);
	mem_put(heap->mctx, heap->array, 
		heap->size * sizeof (void *));
	heap->size = new_size;
	heap->array = new_array;

	return (TRUE);
}

static void
float_up(heap_t heap, unsigned int i, void *elt) {
	unsigned int p;

	for ( p = heap_parent(i); 
	      i > 1 && heap->higher_priority(elt, heap->array[p]);
	      i = p, p = heap_parent(i) ) {
		heap->array[i] = heap->array[p];
		if (heap->index != NULL)
			(heap->index)(heap->array[i], i);
	}
	heap->array[i] = elt;
	if (heap->index != NULL)
		(heap->index)(heap->array[i], i);
}

static void
sink_down(heap_t heap, unsigned int i, void *elt) {
	unsigned int j, size, half_size;

	size = heap->last;
	half_size = size / 2;
	while (i <= half_size) {
		/* find smallest of the (at most) two children */
		j = heap_left(i);
		if (j < size && heap->higher_priority(heap->array[j+1],
						     heap->array[j]))
			j++;
		if (heap->higher_priority(elt, heap->array[j]))
			break;
		heap->array[i] = heap->array[j];
		if (heap->index != NULL)
			(heap->index)(heap->array[i], i);
		i = j;
	}
	heap->array[i] = elt;
	if (heap->index != NULL)
		(heap->index)(heap->array[i], i);
}

isc_result
heap_insert(heap_t heap, void *elt) {
	unsigned int i;

	REQUIRE(VALID_HEAP(heap));

	i = ++heap->last;
	if (heap->last >= heap->size && !resize(heap))
		return (ISC_R_NOMEMORY);
	
	float_up(heap, i, elt);

	return (ISC_R_SUCCESS);
}

void
heap_delete(heap_t heap, unsigned int i) {
	void *elt;

	REQUIRE(VALID_HEAP(heap));
	REQUIRE(i >= 1 && i <= heap->last);

	elt = heap->array[heap->last];
	if (--heap->last > 0)
		sink_down(heap, i, elt);
}

void
heap_increased(heap_t heap, unsigned int i) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(i >= 1 && i <= heap->last);
	
	float_up(heap, i, heap->array[i]);
}

void
heap_decreased(heap_t heap, unsigned int i) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(i >= 1 && i <= heap->last);
	
	sink_down(heap, i, heap->array[i]);
}

void *
heap_element(heap_t heap, unsigned int i) {
	REQUIRE(VALID_HEAP(heap));
	REQUIRE(i >= 1 && i <= heap->last);

	return (heap->array[i]);
}

void
heap_for_each(heap_t heap, heap_for_each_func action, void *uap) {
	unsigned int i;

	REQUIRE(VALID_HEAP(heap));
	REQUIRE(action != NULL);

	for (i = 1; i <= heap->last; i++)
		(action)(heap->array[i], uap);
}
