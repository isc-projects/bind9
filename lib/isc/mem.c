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

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attribute.h"
#include <isc/assertions.h>

#include <isc/mutex.h>
#include <isc/memcluster.h>

#if !defined(LINT) && !defined(CODECENTER)
static char rcsid[] __attribute__((unused)) = "$Id: mem.c,v 1.3 1998/08/18 00:47:51 halley Exp $";
#endif /* not lint */

/*
 * Types.
 */

typedef struct {
	void *			next;
} memcluster_element;

typedef struct {
	size_t			size;
	/*
	 * This structure must be ALIGNMENT_SIZE bytes.
	 */
} *size_info;

struct stats {
	unsigned long		gets;
	unsigned long		totalgets;
	unsigned long		blocks;
	unsigned long		freefrags;
};

#ifdef MEMCLUSTER_RANGES
typedef struct range {
	unsigned char *		first;
	unsigned char *		last;
	struct range *		next;
} range;
#endif
	
struct mem_context {
	size_t			max_size;
	size_t			mem_target;
	memcluster_element **	freelists;
	memcluster_element *	basic_blocks;
#ifdef MEMCLUSTER_RANGES
	range *			ranges;
	range *			freeranges;
#else
	unsigned char *		lowest;
	unsigned char *		highest;
#endif
	struct stats *		stats;
	os_mutex_t		mutex;
};

/* Private Data. */
static mem_context_t 		default_context = NULL;

/* Forward. */

static size_t			quantize(size_t);

/* Macros. */

#define DEF_MAX_SIZE		1100
#define DEF_MEM_TARGET		4096
#define ALIGNMENT_SIZE		sizeof (void *)
#define NUM_BASIC_BLOCKS	64			/* must be > 1 */

#define LOCK_CONTEXT(ctx)	os_mutex_lock(&(ctx)->mutex)
#define UNLOCK_CONTEXT(ctx)	os_mutex_unlock(&(ctx)->mutex)

/* Private Inline-able. */

static __inline__ size_t 
quantize(size_t size) {
	int remainder;

	/*
	 * If there is no remainder for the integer division of 
	 *
	 *	(rightsize/ALIGNMENT_SIZE)
	 *
	 * then we already have a good size; if not, then we need
	 * to round up the result in order to get a size big
	 * enough to satisfy the request and be aligned on ALIGNMENT_SIZE
	 * byte boundaries.
	 */
	remainder = size % ALIGNMENT_SIZE;
	if (remainder != 0)
        	size += ALIGNMENT_SIZE - remainder;
	return (size);
}

/* Public. */

int
mem_context_create(size_t init_max_size, size_t target_size,
		   mem_context_t *ctxp) {
	mem_context_t ctx;

	ctx = malloc(sizeof *ctx);
	if (init_max_size == 0)
		ctx->max_size = DEF_MAX_SIZE;
	else
		ctx->max_size = init_max_size;
	if (target_size == 0)
		ctx->mem_target = DEF_MEM_TARGET;
	else
		ctx->mem_target = target_size;
	ctx->freelists = malloc(ctx->max_size * sizeof (memcluster_element *));
	if (ctx->freelists == NULL) {
		free(ctx);
		return (-1);
	}
	memset(ctx->freelists, 0,
	       ctx->max_size * sizeof (memcluster_element *));
	ctx->stats = malloc((ctx->max_size+1) * sizeof (struct stats));
	if (ctx->stats == NULL) {
		free(ctx->freelists);
		free(ctx);
		return (-1);
	}
	memset(ctx->stats, 0, (ctx->max_size + 1) * sizeof (struct stats));
	ctx->basic_blocks = NULL;
	ctx->lowest = NULL;
	ctx->highest = NULL;
	os_mutex_init(&ctx->mutex);
	*ctxp = ctx;
	return (0);
}

void
mem_context_destroy(mem_context_t *ctxp) {
	REQUIRE(ctxp != NULL);

	/* XXX Free Basic Blocks. XXX */

	*ctxp = NULL;
}

void *
__mem_get(mem_context_t ctx, size_t size) {
	size_t new_size = quantize(size);
	void *ret;

	REQUIRE(size > 0);

	LOCK_CONTEXT(ctx);

	if (size >= ctx->max_size || new_size >= ctx->max_size) {
		/* memget() was called on something beyond our upper limit. */
		ret = malloc(size);
		if (ret != NULL) {
			ctx->stats[ctx->max_size].gets++;
			ctx->stats[ctx->max_size].totalgets++;
		}
		goto done;
	}

	/* 
	 * If there are no blocks in the free list for this size, get a chunk
	 * of memory and then break it up into "new_size"-sized blocks, adding
	 * them to the free list.
	 */
	if (ctx->freelists[new_size] == NULL) {
		int i, frags;
		size_t total_size;
		void *new;
		unsigned char *curr, *next;
		unsigned char *first;
#ifdef MEMCLUSTER_RANGES
		range *r;
#else
		unsigned char *last;
#endif

		if (ctx->basic_blocks == NULL) {
			new = malloc(NUM_BASIC_BLOCKS * ctx->mem_target);
			if (new == NULL) {
				ret = NULL;
				goto done;
			}
			curr = new;
			next = curr + ctx->mem_target;
			for (i = 0; i < (NUM_BASIC_BLOCKS - 1); i++) {
				((memcluster_element *)curr)->next = next;
				curr = next;
				next += ctx->mem_target;
			}
			/*
			 * curr is now pointing at the last block in the
			 * array.
			 */
			((memcluster_element *)curr)->next = NULL;
			first = new;
#ifdef MEMCLUSTER_RANGES
			if (ctx->freeranges == NULL) {
				int nsize = quantize(sizeof(range));
				new = ((memcluster_element *)new)->next;
				curr = first;
				next = curr + nsize;
				frags = ctx->mem_target / nsize;
				for (i = 0; i < (frags - 1); i++) {
					((range *)curr)->next = (range *)next;
					curr = next;
					next += nsize;
				}
				/*
				 * curr is now pointing at the last block in
				 * the array.
				 */
				((range *)curr)->next = NULL;
				ctx->freeranges = (range *)first;
			}
			r = ctx->freeranges;
			ctx->freeranges = r->next;
			r->first = first;
			r->last = r->first +
				NUM_BASIC_BLOCKS * ctx->mem_target - 1;
			r->next = ctx->ranges;
			ctx->ranges = r;
#else
			last = first + NUM_BASIC_BLOCKS * ctx->mem_target - 1;
			if (first < ctx->lowest || ctx->lowest == NULL)
				ctx->lowest = first;
			if (last > ctx->highest)
				ctx->highest = last;
#endif
			ctx->basic_blocks = new;
		}
		total_size = ctx->mem_target;
		new = ctx->basic_blocks;
		ctx->basic_blocks = ctx->basic_blocks->next;
		frags = total_size / new_size;
		ctx->stats[new_size].blocks++;
		ctx->stats[new_size].freefrags += frags;
		/* Set up a linked-list of blocks of size "new_size". */
		curr = new;
		next = curr + new_size;
		for (i = 0; i < (frags - 1); i++) {
			((memcluster_element *)curr)->next = next;
			curr = next;
			next += new_size;
		}
		/* curr is now pointing at the last block in the array. */
		((memcluster_element *)curr)->next = NULL;
		ctx->freelists[new_size] = new;
	}

	/* The free list uses the "rounded-up" size "new_size": */
	ret = ctx->freelists[new_size];
	ctx->freelists[new_size] = ctx->freelists[new_size]->next;

	/* 
	 * The stats[] uses the _actual_ "size" requested by the
	 * caller, with the caveat (in the code above) that "size" >= the
	 * max. size (max_size) ends up getting recorded as a call to
	 * max_size.
	 */
	ctx->stats[size].gets++;
	ctx->stats[size].totalgets++;
	ctx->stats[new_size].freefrags--;

 done:
	UNLOCK_CONTEXT(ctx);

	return (ret);
}

/* 
 * This is a call from an external caller, 
 * so we want to count this as a user "put". 
 */
void
__mem_put(mem_context_t ctx, void *mem, size_t size) {
	size_t new_size = quantize(size);

	REQUIRE(size > 0);

	LOCK_CONTEXT(ctx);

	if (size == ctx->max_size || new_size >= ctx->max_size) {
		/* memput() called on something beyond our upper limit */
		free(mem);
		INSIST(ctx->stats[ctx->max_size].gets != 0);
		ctx->stats[ctx->max_size].gets--;
		goto done;
	}

	/* The free list uses the "rounded-up" size "new_size": */
	((memcluster_element *)mem)->next = ctx->freelists[new_size];
	ctx->freelists[new_size] = (memcluster_element *)mem;

	/* 
	 * The stats[] uses the _actual_ "size" requested by the
	 * caller, with the caveat (in the code above) that "size" >= the
	 * max. size (max_size) ends up getting recorded as a call to
	 * max_size.
	 */
	INSIST(ctx->stats[size].gets != 0);
	ctx->stats[size].gets--;
	ctx->stats[new_size].freefrags++;

 done:
	UNLOCK_CONTEXT(ctx);
}

void *
__mem_get_debug(mem_context_t ctx, size_t size, const char *file, int line) {
	void *ptr;
	ptr = __mem_get(ctx, size);
	fprintf(stderr, "%s:%d: mem_get(%p, %lu) -> %p\n", file, line,
		ctx, (unsigned long)size, ptr);
	return (ptr);
}

void
__mem_put_debug(mem_context_t ctx, void *ptr, size_t size, const char *file,
		int line)
{
	fprintf(stderr, "%s:%d: mem_put(%p, %p, %lu)\n", file, line, 
		ctx, ptr, (unsigned long)size);
	__mem_put(ctx, ptr, size);
}

/*
 * Print the stats[] on the stream "out" with suitable formatting.
 */
void
mem_stats(mem_context_t ctx, FILE *out) {
	size_t i;

	LOCK_CONTEXT(ctx);

	if (ctx->freelists == NULL)
		return;
	for (i = 1; i <= ctx->max_size; i++) {
		const struct stats *s = &ctx->stats[i];

		if (s->totalgets == 0 && s->gets == 0)
			continue;
		fprintf(out, "%s%5d: %11lu gets, %11lu rem",
			(i == ctx->max_size) ? ">=" : "  ",
			i, s->totalgets, s->gets);
		if (s->blocks != 0)
			fprintf(out, " (%lu bl, %lu ff)",
				s->blocks, s->freefrags);
		fputc('\n', out);
	}

	UNLOCK_CONTEXT(ctx);
}

int
mem_valid(mem_context_t ctx, void *ptr) {
	unsigned char *cp = ptr;
	int ret;
#ifdef MEMCLUSTER_RANGES
	range *r;
#endif

	LOCK_CONTEXT(ctx);

	ret = 0;
#ifdef MEMCLUSTER_RANGES
	/* should use a tree for this... */
	for (r = ctx->ranges; r != NULL; r = r->next) {
		if (cp >= r->first && cp <= r->last) {
			ret = 1;
			break;
		}
	}
#else
	if (ctx->lowest != NULL && cp >= ctx->lowest && cp <= ctx->highest)
		ret = 1;
#endif

	UNLOCK_CONTEXT(ctx);

	return (ret);
}

/*
 * Replacements for malloc() and free().
 */

void *
mem_allocate(mem_context_t ctx, size_t size) {
	size_info si;

	size += ALIGNMENT_SIZE;
	si = mem_get(ctx, size);
	if (si == NULL)
		return (NULL);
	si->size = size;
	return (&si[1]);
}

void
mem_free(mem_context_t ctx, void *ptr) {
	size_info si;

	si = &(((size_info)ptr)[-1]);
	mem_put(ctx, si, si->size);
}

/*
 * Public Legacy.
 */

int
meminit(size_t init_max_size, size_t target_size) {
	/* need default_context lock here */
	if (default_context != NULL)
		return (-1);
	return (mem_context_create(init_max_size, target_size,
				   &default_context));
}

mem_context_t
mem_default_context(void) {
	/* need default_context lock here */
	if (default_context == NULL && meminit(0, 0) == -1)
		return (NULL);
	return (default_context);
}

void *
__memget(size_t size) {
	/* need default_context lock here */
	if (default_context == NULL && meminit(0, 0) == -1)
		return (NULL);
	return (__mem_get(default_context, size));
}

void
__memput(void *mem, size_t size) {
	/* need default_context lock here */
	REQUIRE(default_context != NULL);
	__mem_put(default_context, mem, size);
}

void *
__memget_debug(size_t size, const char *file, int line) {
	void *ptr;
	ptr = __memget(size);
	fprintf(stderr, "%s:%d: memget(%lu) -> %p\n", file, line,
		(unsigned long)size, ptr);
	return (ptr);
}

void
__memput_debug(void *ptr, size_t size, const char *file, int line) {
	fprintf(stderr, "%s:%d: memput(%p, %lu)\n", file, line, 
		ptr, (unsigned long)size);
	__memput(ptr, size);
}

int
memvalid(void *ptr) {
	/* need default_context lock here */
	REQUIRE(default_context != NULL);
	return (mem_valid(default_context, ptr));
}

void
memstats(FILE *out) {
	/* need default_context lock here */
	REQUIRE(default_context != NULL);
	mem_stats(default_context, out);
}
