/*
 * Copyright (C) 1997, 1998, 1999  Internet Software Consortium.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <limits.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>

#ifndef ISC_SINGLETHREADED
#include <isc/mutex.h>
#include "util.h"
#else
#define LOCK(l)
#define UNLOCK(l)
#endif

/*
 * Types.
 */

typedef struct {
	void *			next;
} element;

typedef struct {
	size_t			size;
	/*
	 * This structure must be ALIGNMENT_SIZE bytes.
	 */
} size_info;

struct stats {
	unsigned long		gets;
	unsigned long		totalgets;
	unsigned long		blocks;
	unsigned long		freefrags;
};

#define MEM_MAGIC		0x4D656d43U	/* MemC. */
#define VALID_CONTEXT(c)	((c) != NULL && (c)->magic == MEM_MAGIC)

struct isc_mem {
	unsigned int		magic;
	isc_mutex_t		lock;
	size_t			max_size;
	size_t			mem_target;
	element **		freelists;
	element *		basic_blocks;
	unsigned char **	basic_table;
	unsigned int		basic_table_count;
	unsigned int		basic_table_size;
	unsigned char *		lowest;
	unsigned char *		highest;
	struct stats *		stats;
	size_t			quota;
	size_t			total;
	ISC_LIST(isc_mempool_t)	pools;
};

#define MEMPOOL_MAGIC		0x4D454d70U	/* MEMp. */
#define VALID_MEMPOOL(c)	((c) != NULL && (c)->magic == MEMPOOL_MAGIC)

struct isc_mempool {
	unsigned int	magic;		/* magic number */
	ISC_LINK(isc_mempool_t)	link;	/* next pool in this mem context */
	isc_mem_t      *mctx;		/* our memory context */
	element	       *items;		/* low water item list */
	size_t		size;		/* size of each item on this pool */
	unsigned int	maxalloc;	/* max number of items allowed */
	unsigned int	allocated;	/* # of items currently given out */
	unsigned int	freecount;	/* # of items on reserved list */
	unsigned int	freemax;	/* # of items allowed on free list */
	unsigned int	fillcount;	/* # of items to fetch on each fill */
	/* Stats only. */
	unsigned int	gets;		/* # of requests to this pool */
};

/* Forward. */

static inline size_t		quantize(size_t);
static inline void		mem_putunlocked(isc_mem_t *, void *, size_t);
static inline void *		mem_getunlocked(isc_mem_t *, size_t);

/* Constants. */

#define DEF_MAX_SIZE		1100
#define DEF_MEM_TARGET		4096
#define ALIGNMENT_SIZE		sizeof (void *)
#define NUM_BASIC_BLOCKS	64			/* must be > 1 */
#define TABLE_INCREMENT		1024

/* Private Inline-able. */

static inline size_t
quantize(size_t size) {
	int temp;

	/*
	 * Round up the result in order to get a size big
	 * enough to satisfy the request and be aligned on ALIGNMENT_SIZE
	 * byte boundaries.
	 */

	temp = size + (ALIGNMENT_SIZE - 1);
	return (temp - temp % ALIGNMENT_SIZE); 
}

/* Public. */

isc_result_t
isc_mem_create(size_t init_max_size, size_t target_size,
	       isc_mem_t **ctxp)
{
	isc_mem_t *ctx;

	REQUIRE(ctxp != NULL && *ctxp == NULL);

	ctx = malloc(sizeof *ctx);
	if (ctx == NULL)
		return (ISC_R_NOMEMORY);

	if (init_max_size == 0)
		ctx->max_size = DEF_MAX_SIZE;
	else
		ctx->max_size = init_max_size;
	if (target_size == 0)
		ctx->mem_target = DEF_MEM_TARGET;
	else
		ctx->mem_target = target_size;
	ctx->freelists = malloc(ctx->max_size * sizeof (element *));
	if (ctx->freelists == NULL) {
		free(ctx);
		return (ISC_R_NOMEMORY);
	}
	memset(ctx->freelists, 0,
	       ctx->max_size * sizeof (element *));
	ctx->stats = malloc((ctx->max_size+1) * sizeof (struct stats));
	if (ctx->stats == NULL) {
		free(ctx->freelists);
		free(ctx);
		return (ISC_R_NOMEMORY);
	}
	memset(ctx->stats, 0, (ctx->max_size + 1) * sizeof (struct stats));
	ctx->basic_blocks = NULL;
	ctx->basic_table = NULL;
	ctx->basic_table_count = 0;
	ctx->basic_table_size = 0;
	ctx->lowest = NULL;
	ctx->highest = NULL;
	if (isc_mutex_init(&ctx->lock) != ISC_R_SUCCESS) {
		free(ctx->stats);
		free(ctx->freelists);
		free(ctx);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	ctx->quota = 0;
	ctx->total = 0;
	ctx->magic = MEM_MAGIC;
	ISC_LIST_INIT(ctx->pools);

	*ctxp = ctx;
	return (ISC_R_SUCCESS);
}

void
isc_mem_destroy(isc_mem_t **ctxp) {
	unsigned int i;
	isc_mem_t *ctx;

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	REQUIRE(VALID_CONTEXT(ctx));

	ctx->magic = 0;

	INSIST(ISC_LIST_EMPTY(ctx->pools));

	for (i = 0; i <= ctx->max_size; i++)
		INSIST(ctx->stats[i].gets == 0);

	for (i = 0; i < ctx->basic_table_count; i++)
		free(ctx->basic_table[i]);
	free(ctx->freelists);
	free(ctx->stats);
	free(ctx->basic_table);
	(void)isc_mutex_destroy(&ctx->lock);
	free(ctx);

	*ctxp = NULL;
}

static void
more_basic_blocks(isc_mem_t *ctx) {
	void *new;
	unsigned char *curr, *next;
	unsigned char *first, *last;
	unsigned char **table;
	unsigned int table_size;
	size_t increment;
	int i;

	/* Require: we hold the context lock. */

	/*
	 * Did we hit the quota for this context?
	 */
	increment = NUM_BASIC_BLOCKS * ctx->mem_target;
	if (ctx->quota != 0 && ctx->total + increment > ctx->quota)
		return;

	INSIST(ctx->basic_table_count <= ctx->basic_table_size);
	if (ctx->basic_table_count == ctx->basic_table_size) {
		table_size = ctx->basic_table_size + TABLE_INCREMENT;
		table = malloc(table_size * sizeof (unsigned char *));
		if (table == NULL)
			return;
		if (ctx->basic_table_size != 0) {
			memcpy(table, ctx->basic_table,
			       ctx->basic_table_size *
			       sizeof (unsigned char *));
			free(ctx->basic_table);
		}
		ctx->basic_table = table;
		ctx->basic_table_size = table_size;
	}

	new = malloc(NUM_BASIC_BLOCKS * ctx->mem_target);
	if (new == NULL)
		return;
	ctx->total += increment;
	ctx->basic_table[ctx->basic_table_count] = new;
	ctx->basic_table_count++;

	curr = new;
	next = curr + ctx->mem_target;
	for (i = 0; i < (NUM_BASIC_BLOCKS - 1); i++) {
		((element *)curr)->next = next;
		curr = next;
		next += ctx->mem_target;
	}
	/*
	 * curr is now pointing at the last block in the
	 * array.
	 */
	((element *)curr)->next = NULL;
	first = new;
	last = first + NUM_BASIC_BLOCKS * ctx->mem_target - 1;
	if (first < ctx->lowest || ctx->lowest == NULL)
		ctx->lowest = first;
	if (last > ctx->highest)
		ctx->highest = last;
	ctx->basic_blocks = new;
}

void *
__isc_mem_get(isc_mem_t *ctx, size_t size)
{
	void *ret;

	REQUIRE(size > 0);
	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	ret = mem_getunlocked(ctx, size);
	UNLOCK(&ctx->lock);

	return (ret);
}

static inline void *
mem_getunlocked(isc_mem_t *ctx, size_t size)
{
	size_t new_size = quantize(size);
	void *ret;

	if (size >= ctx->max_size || new_size >= ctx->max_size) {
		/* memget() was called on something beyond our upper limit. */
		if (ctx->quota != 0 && ctx->total + size > ctx->quota) {
			ret = NULL;
			goto done;
		}
		ret = malloc(size);
		if (ret != NULL) {
			ctx->total += size;
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

		if (ctx->basic_blocks == NULL) {
			more_basic_blocks(ctx);
			if (ctx->basic_blocks == NULL) {
				ret = NULL;
				goto done;
			}
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
			((element *)curr)->next = next;
			curr = next;
			next += new_size;
		}
		/* curr is now pointing at the last block in the array. */
		((element *)curr)->next = NULL;
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

#if ISC_MEM_FILL
	if (ret != NULL)
		memset(ret, 0xbe, new_size); /* Mnemonic for "beef". */
#endif

	return (ret);
}

void
__isc_mem_put(isc_mem_t *ctx, void *mem, size_t size)
{
	REQUIRE(size > 0);
	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	mem_putunlocked(ctx, mem, size);
	UNLOCK(&ctx->lock);
}

static inline void
mem_putunlocked(isc_mem_t *ctx, void *mem, size_t size)
{
	size_t new_size = quantize(size);

#if ISC_MEM_FILL
	memset(mem, 0xde, new_size); /* Mnemonic for "dead". */
#endif

	if (size == ctx->max_size || new_size >= ctx->max_size) {
		/* memput() called on something beyond our upper limit */
		free(mem);
		INSIST(ctx->stats[ctx->max_size].gets != 0);
		ctx->stats[ctx->max_size].gets--;
		INSIST(size <= ctx->total);
		ctx->total -= size;
		return;
	}

	/* The free list uses the "rounded-up" size "new_size": */
	((element *)mem)->next = ctx->freelists[new_size];
	ctx->freelists[new_size] = (element *)mem;

	/* 
	 * The stats[] uses the _actual_ "size" requested by the
	 * caller, with the caveat (in the code above) that "size" >= the
	 * max. size (max_size) ends up getting recorded as a call to
	 * max_size.
	 */
	INSIST(ctx->stats[size].gets != 0);
	ctx->stats[size].gets--;
	ctx->stats[new_size].freefrags++;
}

void *
__isc_mem_getdebug(isc_mem_t *ctx, size_t size, const char *file, int line) {
	void *ptr;

	ptr = __isc_mem_get(ctx, size);
	fprintf(stderr, "%s:%d: mem_get(%p, %lu) -> %p\n", file, line,
		ctx, (unsigned long)size, ptr);
	return (ptr);
}

void
__isc_mem_putdebug(isc_mem_t *ctx, void *ptr, size_t size, const char *file,
		 int line)
{
	fprintf(stderr, "%s:%d: mem_put(%p, %p, %lu)\n", file, line, 
		ctx, ptr, (unsigned long)size);
	__isc_mem_put(ctx, ptr, size);
}

/*
 * Print the stats[] on the stream "out" with suitable formatting.
 */
void
isc_mem_stats(isc_mem_t *ctx, FILE *out)
{
	size_t i;
	const struct stats *s;
	const isc_mempool_t *pool;

	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	if (ctx->freelists != NULL) {
		for (i = 1; i <= ctx->max_size; i++) {
			s = &ctx->stats[i];

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
	}

	pool = ISC_LIST_HEAD(ctx->pools);
	if (pool != NULL) {
		fprintf(out, "[Pool statistics]\n");
		fprintf(out, "%10s %10s %10s %10s %10s %10s %10s\n",
			"size", "maxalloc", "allocated", "freecount",
			"freemax", "fillcount", "gets");
	}
	while (pool != NULL) {
		fprintf(out, "%10u %10u %10u %10u %10u %10u %10u\n",
			pool->size, pool->maxalloc, pool->allocated,
			pool->freecount, pool->freemax, pool->fillcount,
			pool->gets);
		pool = ISC_LIST_NEXT(pool, link);
	}

	UNLOCK(&ctx->lock);
}

isc_boolean_t
isc_mem_valid(isc_mem_t *ctx, void *ptr) {
	unsigned char *cp = ptr;
	isc_boolean_t result = ISC_FALSE;

	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	if (ctx->lowest != NULL && cp >= ctx->lowest && cp <= ctx->highest)
		result = ISC_TRUE;

	UNLOCK(&ctx->lock);

	return (result);
}

/*
 * Replacements for malloc() and free().
 */

void *
isc_mem_allocate(isc_mem_t *ctx, size_t size) {
	size_info *si;

	size += ALIGNMENT_SIZE;
	si = isc_mem_get(ctx, size);
	if (si == NULL)
		return (NULL);
	si->size = size;
	return (&si[1]);
}

void
isc_mem_free(isc_mem_t *ctx, void *ptr) {
	size_info *si;

	si = &(((size_info *)ptr)[-1]);
	isc_mem_put(ctx, si, si->size);
}

/*
 * Other useful things.
 */

char *
isc_mem_strdup(isc_mem_t *mctx, const char *s) {
	size_t len;
	char *ns;

	len = strlen(s);
	ns = isc_mem_allocate(mctx, len + 1);
	if (ns == NULL)
		return (NULL);
	strncpy(ns, s, len + 1);
	
	return (ns);
}

/*
 * Quotas
 */

void
isc_mem_setquota(isc_mem_t *ctx, size_t quota) {
	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	ctx->quota = quota;

	UNLOCK(&ctx->lock);
}

size_t
isc_mem_getquota(isc_mem_t *ctx) {
	size_t quota;

	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	quota = ctx->quota;

	UNLOCK(&ctx->lock);

	return (quota);
}

#ifdef ISC_MEMCLUSTER_LEGACY

/*
 * Public Legacy.
 */

static isc_mem_t *default_context = NULL;

int
meminit(size_t init_max_size, size_t target_size) {
	/* need default_context lock here */
	if (default_context != NULL)
		return (-1);
	return (isc_mem_create(init_max_size, target_size, &default_context));
}

isc_mem_t *
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

#endif /* ISC_MEMCLUSTER_LEGACY */


/*
 * Memory pool stuff
 */


#if 0
/*
 * Free all but "n" items from the pool's free list.  If n == 0, all items
 * will be returned to the mctx.
 */
static void
mempool_release(isc_mempool_t *mpctx, unsigned int n)
{
	isc_mem_t *mctx;
	element *item;
	element *next;
	unsigned int count;

	mctx = mpctx->mctx;

	if (mpctx->freecount <= n)
		return;

	INSIST(mpctx->items != NULL);
	item = mpctx->items;
	for (count = 0 ; count < n ; count++) {
		item = item->next;
		INSIST(item != NULL);
	}

	/*
	 * All remaining items are to be freed.  Lock the context once,
	 * free them all, and unlock the context.
	 */
	LOCK(&mctx->lock);
	do {
		next = item->next;
		mem_putunlocked(mctx, item, mpctx->size);
		INSIST(mpctx->freecount > 0);
		mpctx->freecount--;
		item = next;
	} while (item != NULL);
	UNLOCK(&mctx->lock);
}
#endif

/*
 * Release all items on the free list.  No locking is done, the memory
 * context must be locked.
 */
static void
mempool_releaseall(isc_mempool_t *mpctx)
{
	isc_mem_t *mctx;
	element *item;
	element *next;

	mctx = mpctx->mctx;

	if (mpctx->freecount == 0)
		return;

	INSIST(mpctx->items != NULL);
	item = mpctx->items;

	do {
		next = item->next;
		mem_putunlocked(mctx, item, mpctx->size);
		INSIST(mpctx->freecount > 0);
		mpctx->freecount--;
		item = next;
	} while (item != NULL);
}

isc_result_t
isc_mempool_create(isc_mem_t *mctx, size_t size,
		   isc_mempool_t **mpctxp)
{
	isc_mempool_t *mpctx;

	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(size > 0);
	REQUIRE(mpctxp != NULL && *mpctxp == NULL);

	/*
	 * Allocate space for this pool, initialize values, and if all works
	 * well, attach to the memory context.
	 */
	LOCK(&mctx->lock);

	mpctx = mem_getunlocked(mctx, sizeof(isc_mempool_t));
	if (mpctx == NULL) {
		UNLOCK(&mctx->lock);
		return (ISC_R_NOMEMORY);
	}

	mpctx->magic = MEMPOOL_MAGIC;
	mpctx->mctx = mctx;
	mpctx->size = size;
	mpctx->maxalloc = UINT_MAX;
	mpctx->allocated = 0;
	mpctx->freecount = 0;
	mpctx->freemax = 1;
	mpctx->fillcount = 1;
	mpctx->gets = 0;
	mpctx->items = NULL;

	*mpctxp = mpctx;

	ISC_LIST_APPEND(mctx->pools, mpctx, link);

	UNLOCK(&mctx->lock);

	return (ISC_R_SUCCESS);
}

void
isc_mempool_destroy(isc_mempool_t **mpctxp)
{
	isc_mempool_t *mpctx;
	isc_mem_t *mctx;

	REQUIRE(mpctxp != NULL);
	mpctx = *mpctxp;
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mpctx->allocated == 0);

	mctx = mpctx->mctx;

	LOCK(&mctx->lock);

	/*
	 * Return any items on the free list
	 */
	mempool_releaseall(mpctx);

	/*
	 * Remove our linked list entry from the memory context.
	 */
	ISC_LIST_UNLINK(mctx->pools, mpctx, link);
	
	mpctx->magic = 0;

	mem_putunlocked(mpctx->mctx, mpctx, sizeof(isc_mempool_t));

	UNLOCK(&mctx->lock);

	*mpctxp = NULL;
}

void *
__isc_mempool_get(isc_mempool_t *mpctx)
{
	element *item;
	isc_mem_t *mctx;
	unsigned int i;

	REQUIRE(VALID_MEMPOOL(mpctx));

	mctx = mpctx->mctx;

	/*
	 * Don't let the caller go over quota
	 */
	if (mpctx->allocated >= mpctx->maxalloc)
		return (NULL);

	/*
	 * if we have a free list item, return the first here
	 */
	item = mpctx->items;
	if (item != NULL) {
		mpctx->items = item->next;
		INSIST(mpctx->freecount > 0);
		mpctx->freecount--;
		mpctx->gets++;
		mpctx->allocated++;
		return (item);
	}

	/*
	 * We need to dip into the well.  Lock the memory context here and
	 * fill up our free list.
	 */
	LOCK(&mctx->lock);
	for (i = 0 ; i < mpctx->fillcount ; i++) {
		item = mem_getunlocked(mctx, mpctx->size);
		if (item == NULL)
			break;
		item->next = mpctx->items;
		mpctx->items = item;
		mpctx->freecount++;
	}
	UNLOCK(&mctx->lock);

	/*
	 * If we didn't get any items, return NULL.
	 */
	item = mpctx->items;
	if (item == NULL)
		return (NULL);

	mpctx->items = item->next;
	mpctx->freecount--;
	mpctx->gets++;
	mpctx->allocated++;
	return (item);
}

void
__isc_mempool_put(isc_mempool_t *mpctx, void *mem)
{
	isc_mem_t *mctx;
	element *item;

	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mem != NULL);

	mctx = mpctx->mctx;

	INSIST(mpctx->allocated > 0);
	mpctx->allocated--;

	/*
	 * If our free list is full, return this to the mctx directly.
	 */
	if (mpctx->freecount >= mpctx->freemax) {
		__isc_mem_put(mctx, mem, mpctx->size);
		return;
	}

	/*
	 * Otherwise, attach it to our free list and bump the counter.
	 */
	mpctx->freecount++;
	item = (element *)mem;
	item->next = mpctx->items;
	mpctx->items = item;
}

void *
__isc_mempool_getdebug(isc_mempool_t *mpctx,
		       const char *file, int line)
{
	void *ptr;

	ptr = __isc_mempool_get(mpctx);
	fprintf(stderr, "%s:%d: mempool_get(%p) -> %p\n", file, line,
		mpctx, ptr);

	return (ptr);
}

void
__isc_mempool_putdebug(isc_mempool_t *mpctx, void *ptr,
		       const char *file, int line)
{
	fprintf(stderr, "%s:%d: mempool_put(%p, %p)\n", file, line, 
		mpctx, ptr);
	__isc_mempool_put(mpctx, ptr);
}

/*
 * Quotas
 */

void
isc_mempool_setfreemax(isc_mempool_t *mpctx, unsigned int limit)
{
	REQUIRE(VALID_MEMPOOL(mpctx));

	mpctx->freemax = limit;
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx)
{
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (mpctx->freemax);
}

unsigned int
isc_mempool_getfreecount(isc_mempool_t *mpctx)
{
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (mpctx->freecount);
}

void
isc_mempool_setmaxalloc(isc_mempool_t *mpctx, unsigned int limit)
{
	REQUIRE(limit > 0);

	REQUIRE(VALID_MEMPOOL(mpctx));

	mpctx->maxalloc = limit;
}

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx)
{
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (mpctx->maxalloc);
}

unsigned int
isc_mempool_getallocated(isc_mempool_t *mpctx)
{
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (mpctx->allocated);
}

void
isc_mempool_setfillcount(isc_mempool_t *mpctx, unsigned int limit)
{
	REQUIRE(limit > 0);
	REQUIRE(VALID_MEMPOOL(mpctx));

	mpctx->fillcount = limit;
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx)
{
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (mpctx->fillcount);
}
