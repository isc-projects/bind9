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

#if !defined(LINT) && !defined(CODECENTER)
static char rcsid[] = "$Id: heap.c,v 1.1 1998/10/15 23:42:56 halley Exp $";
#endif /* not lint */

#include <stdlib.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/heap.h>

/*
 * Note: to make heap_parent and heap_left easy to compute, the first
 * element of the heap array is not used; i.e. heap subscripts are 1-based,
 * not 0-based.
 */
#define heap_parent(i) ((i) >> 1)
#define heap_left(i) ((i) << 1)

#define ARRAY_SIZE_INCREMENT 512

#define HEAP_MAGIC			0x48454150U	/* HEAP. */
#define VALID_CONTEXT(ctx)		((ctx) != NULL && \
					 (ctx)->magic == HEAP_MAGIC)

struct heap_context {
	unsigned int			magic;
	mem_context_t			mctx;
	unsigned int			array_size;
	unsigned int			array_size_increment;
	unsigned int			heap_size;
	void				**heap;
	heap_higher_priority_func	higher_priority;
	heap_index_func			index;
};

isc_result
heap_create(mem_context_t mctx, heap_higher_priority_func higher_priority,
	    heap_index_func index, unsigned int array_size_increment,
	    heap_context_t *ctxp)
{
	heap_context_t ctx;

	REQUIRE(ctxp != NULL && *ctxp == NULL);
	REQUIRE(higher_priority != NULL);

	ctx = mem_get(mctx, sizeof *ctx);
	if (ctx == NULL)
		return (ISC_R_NOMEMORY);
	ctx->magic = HEAP_MAGIC;
	ctx->array_size = 0;
	if (array_size_increment == 0)
		ctx->array_size_increment = ARRAY_SIZE_INCREMENT;
	else
		ctx->array_size_increment = array_size_increment;
	ctx->heap_size = 0;
	ctx->heap = NULL;
	ctx->higher_priority = higher_priority;
	ctx->index = index;

	*ctxp = ctx;
	
	return (ISC_R_SUCCESS);
}

void
heap_destroy(heap_context_t *ctxp) {
	heap_context_t ctx;

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	REQUIRE(VALID_CONTEXT(ctx));

	if (ctx->heap != NULL)
		mem_put(ctx->mctx, ctx->heap,
			ctx->array_size * sizeof (void *));
	ctx->magic = 0;
	mem_put(ctx->mctx, ctx, sizeof *ctx);

	*ctxp = NULL;
}

static boolean_t
heap_resize(heap_context_t ctx) {
	void **new_heap;
	size_t new_size;

	REQUIRE(VALID_CONTEXT(ctx));

	new_size = ctx->array_size + ctx->array_size_increment;
	new_heap = mem_get(ctx->mctx, new_size * sizeof (void *));
	if (new_heap == NULL)
		return (FALSE);
	memcpy(new_heap, ctx->heap, ctx->array_size);
	mem_put(ctx->mctx, ctx->heap, 
		ctx->array_size * sizeof (void *));
	ctx->array_size = new_size;
	ctx->heap = new_heap;

	return (TRUE);
}

static void
float_up(heap_context_t ctx, unsigned int i, void *elt) {
	unsigned int p;

	for ( p = heap_parent(i); 
	      i > 1 && ctx->higher_priority(elt, ctx->heap[p]);
	      i = p, p = heap_parent(i) ) {
		ctx->heap[i] = ctx->heap[p];
		if (ctx->index != NULL)
			(ctx->index)(ctx->heap[i], i);
	}
	ctx->heap[i] = elt;
	if (ctx->index != NULL)
		(ctx->index)(ctx->heap[i], i);
}

static void
sink_down(heap_context_t ctx, unsigned int i, void *elt) {
	unsigned int j, size, half_size;

	size = ctx->heap_size;
	half_size = size / 2;
	while (i <= half_size) {
		/* find smallest of the (at most) two children */
		j = heap_left(i);
		if (j < size && ctx->higher_priority(ctx->heap[j+1],
						     ctx->heap[j]))
			j++;
		if (ctx->higher_priority(elt, ctx->heap[j]))
			break;
		ctx->heap[i] = ctx->heap[j];
		if (ctx->index != NULL)
			(ctx->index)(ctx->heap[i], i);
		i = j;
	}
	ctx->heap[i] = elt;
	if (ctx->index != NULL)
		(ctx->index)(ctx->heap[i], i);
}

isc_result
heap_insert(heap_context_t ctx, void *elt) {
	unsigned int i;

	REQUIRE(VALID_CONTEXT(ctx));

	i = ++ctx->heap_size;
	if (ctx->heap_size >= ctx->array_size && !heap_resize(ctx))
		return (ISC_R_NOMEMORY);
	
	float_up(ctx, i, elt);

	return (ISC_R_SUCCESS);
}

void
heap_delete(heap_context_t ctx, unsigned int i) {
	void *elt;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->heap_size);

	elt = ctx->heap[ctx->heap_size];
	if (--ctx->heap_size > 0)
		sink_down(ctx, i, elt);
}

void
heap_increased(heap_context_t ctx, unsigned int i) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->heap_size);
	
	float_up(ctx, i, ctx->heap[i]);
}

void
heap_decreased(heap_context_t ctx, unsigned int i) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->heap_size);
	
	sink_down(ctx, i, ctx->heap[i]);
}

void *
heap_element(heap_context_t ctx, unsigned int i) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->heap_size);

	return (ctx->heap[i]);
}

void
heap_for_each(heap_context_t ctx, heap_for_each_func action, void *uap) {
	unsigned int i;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(action != NULL);

	for (i = 1; i <= ctx->heap_size; i++)
		(action)(ctx->heap[i], uap);
}
