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
#define VALID_CONTEXT(ctx)		((ctx) != NULL && \
					 (ctx)->magic == HEAP_MAGIC)

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
	    heap_context_t *ctxp)
{
	heap_context_t ctx;

	REQUIRE(ctxp != NULL && *ctxp == NULL);
	REQUIRE(higher_priority != NULL);

	ctx = mem_get(mctx, sizeof *ctx);
	if (ctx == NULL)
		return (ISC_R_NOMEMORY);
	ctx->magic = HEAP_MAGIC;
	ctx->size = 0;
	if (size_increment == 0)
		ctx->size_increment = SIZE_INCREMENT;
	else
		ctx->size_increment = size_increment;
	ctx->last = 0;
	ctx->array = NULL;
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

	if (ctx->array != NULL)
		mem_put(ctx->mctx, ctx->array,
			ctx->size * sizeof (void *));
	ctx->magic = 0;
	mem_put(ctx->mctx, ctx, sizeof *ctx);

	*ctxp = NULL;
}

static boolean_t
resize(heap_context_t ctx) {
	void **new_array;
	size_t new_size;

	REQUIRE(VALID_CONTEXT(ctx));

	new_size = ctx->size + ctx->size_increment;
	new_array = mem_get(ctx->mctx, new_size * sizeof (void *));
	if (new_array == NULL)
		return (FALSE);
	memcpy(new_array, ctx->array, ctx->size);
	mem_put(ctx->mctx, ctx->array, 
		ctx->size * sizeof (void *));
	ctx->size = new_size;
	ctx->array = new_array;

	return (TRUE);
}

static void
float_up(heap_context_t ctx, unsigned int i, void *elt) {
	unsigned int p;

	for ( p = heap_parent(i); 
	      i > 1 && ctx->higher_priority(elt, ctx->array[p]);
	      i = p, p = heap_parent(i) ) {
		ctx->array[i] = ctx->array[p];
		if (ctx->index != NULL)
			(ctx->index)(ctx->array[i], i);
	}
	ctx->array[i] = elt;
	if (ctx->index != NULL)
		(ctx->index)(ctx->array[i], i);
}

static void
sink_down(heap_context_t ctx, unsigned int i, void *elt) {
	unsigned int j, size, half_size;

	size = ctx->last;
	half_size = size / 2;
	while (i <= half_size) {
		/* find smallest of the (at most) two children */
		j = heap_left(i);
		if (j < size && ctx->higher_priority(ctx->array[j+1],
						     ctx->array[j]))
			j++;
		if (ctx->higher_priority(elt, ctx->array[j]))
			break;
		ctx->array[i] = ctx->array[j];
		if (ctx->index != NULL)
			(ctx->index)(ctx->array[i], i);
		i = j;
	}
	ctx->array[i] = elt;
	if (ctx->index != NULL)
		(ctx->index)(ctx->array[i], i);
}

isc_result
heap_insert(heap_context_t ctx, void *elt) {
	unsigned int i;

	REQUIRE(VALID_CONTEXT(ctx));

	i = ++ctx->last;
	if (ctx->last >= ctx->size && !resize(ctx))
		return (ISC_R_NOMEMORY);
	
	float_up(ctx, i, elt);

	return (ISC_R_SUCCESS);
}

void
heap_delete(heap_context_t ctx, unsigned int i) {
	void *elt;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->last);

	elt = ctx->array[ctx->last];
	if (--ctx->last > 0)
		sink_down(ctx, i, elt);
}

void
heap_increased(heap_context_t ctx, unsigned int i) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->last);
	
	float_up(ctx, i, ctx->array[i]);
}

void
heap_decreased(heap_context_t ctx, unsigned int i) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->last);
	
	sink_down(ctx, i, ctx->array[i]);
}

void *
heap_element(heap_context_t ctx, unsigned int i) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(i >= 1 && i <= ctx->last);

	return (ctx->array[i]);
}

void
heap_for_each(heap_context_t ctx, heap_for_each_func action, void *uap) {
	unsigned int i;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(action != NULL);

	for (i = 1; i <= ctx->last; i++)
		(action)(ctx->array[i], uap);
}
