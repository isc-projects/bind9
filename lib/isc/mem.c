/*
 * Copyright (C) 1997-2000  Internet Software Consortium.
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

/* $Id: mem.c,v 1.68 2000/12/01 00:52:38 gson Exp $ */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <limits.h>

#include <isc/mem.h>
#include <isc/ondestroy.h>
#include <isc/string.h>

#include <isc/mutex.h>
#include <isc/util.h>

unsigned int isc_mem_debugging = 0;

/*
 * Constants.
 */

#define DEF_MAX_SIZE		1100
#define DEF_MEM_TARGET		4096
#define ALIGNMENT_SIZE		8
#define NUM_BASIC_BLOCKS	64			/* must be > 1 */
#define TABLE_INCREMENT		1024
#define DEBUGLIST_COUNT		1024

/*
 * Types.
 */
#if ISC_MEM_TRACKLINES
typedef struct debuglink debuglink_t;
struct debuglink {
	ISC_LINK(debuglink_t)	link;
	const void	       *ptr[DEBUGLIST_COUNT];
	const char	       *file[DEBUGLIST_COUNT];
	unsigned int		line[DEBUGLIST_COUNT];
	unsigned int		count;
};

#define FLARG_PASS	, file, line
#define FLARG		, const char *file, int line
#else
#define FLARG_PASS
#define FLARG
#endif

typedef struct element element;
struct element {
	element *		next;
};

typedef struct {
	/*
	 * This structure must be ALIGNMENT_SIZE bytes.
	 */
	union {
		size_t		size;
		char		bytes[ALIGNMENT_SIZE];
	} u;
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
	isc_ondestroy_t		ondestroy;
	isc_mutex_t		lock;
	isc_memalloc_t		memalloc;
	isc_memfree_t		memfree;
	void *			arg;
	size_t			max_size;
	size_t			mem_target;
	element **		freelists;
	element *		basic_blocks;
	unsigned char **	basic_table;
	unsigned int		basic_table_count;
	unsigned int		basic_table_size;
	unsigned char *		lowest;
	unsigned char *		highest;
	isc_boolean_t		checkfree;
	isc_boolean_t		trysplit;
	struct stats *		stats;
	unsigned int		references;
	size_t			quota;
	size_t			total;
	size_t			inuse;
	size_t			hi_water;
	size_t			lo_water;
	isc_boolean_t		hi_called;
	isc_mem_water_t		water;
	void *			water_arg;
	ISC_LIST(isc_mempool_t)	pools;
#if ISC_MEM_TRACKLINES
	ISC_LIST(debuglink_t)	debuglist;
#endif
};

#define MEMPOOL_MAGIC		0x4D454d70U	/* MEMp. */
#define VALID_MEMPOOL(c)	((c) != NULL && (c)->magic == MEMPOOL_MAGIC)

struct isc_mempool {
	/* always unlocked */
	unsigned int	magic;		/* magic number */
	isc_mutex_t    *lock;		/* optional lock */
	isc_mem_t      *mctx;		/* our memory context */
	/* locked via the memory context's lock */
	ISC_LINK(isc_mempool_t)	link;	/* next pool in this mem context */
	/* optionally locked from here down */
	element	       *items;		/* low water item list */
	size_t		size;		/* size of each item on this pool */
	unsigned int	maxalloc;	/* max number of items allowed */
	unsigned int	allocated;	/* # of items currently given out */
	unsigned int	freecount;	/* # of items on reserved list */
	unsigned int	freemax;	/* # of items allowed on free list */
	unsigned int	fillcount;	/* # of items to fetch on each fill */
	/* Stats only. */
	unsigned int	gets;		/* # of requests to this pool */
	/* Debugging only. */
#if ISC_MEMPOOL_NAMES
	char		name[16];	/* printed name in stats reports */
#endif
};

/*
 * Private Inline-able.
 */

#if ! ISC_MEM_TRACKLINES
#define ADD_TRACE(a, b, c, d, e)
#define DELETE_TRACE(a, b, c, d, e)
#else
#define ADD_TRACE(a, b, c, d, e)	add_trace_entry(a, b, c, d, e)
#define DELETE_TRACE(a, b, c, d, e)	delete_trace_entry(a, b, c, d, e)

#define MEM_TRACE	((isc_mem_debugging & ISC_MEM_DEBUGTRACE) != 0)
#define MEM_RECORD	((isc_mem_debugging & ISC_MEM_DEBUGRECORD) != 0)

/*
 * mctx must be locked.
 */
static inline void
add_trace_entry(isc_mem_t *mctx, const void *ptr, unsigned int size
		FLARG)
{
	debuglink_t *dl;
	unsigned int i;

	if (MEM_TRACE)
		fprintf(stderr, "add %p size %u file %s line %u mctx %p\n",
			ptr, size, file, line, mctx);

	if (!MEM_RECORD)
		return;

	dl = ISC_LIST_HEAD(mctx->debuglist);
	while (dl != NULL) {
		if (dl->count == DEBUGLIST_COUNT)
			goto next;
		for (i = 0 ; i < DEBUGLIST_COUNT ; i++) {
			if (dl->ptr[i] == NULL) {
				dl->ptr[i] = ptr;
				dl->file[i] = file;
				dl->line[i] = line;
				dl->count++;
				return;
			}
		}
	next:
		dl = ISC_LIST_NEXT(dl, link);
	}

	dl = malloc(sizeof(debuglink_t));
	INSIST(dl != NULL);

	ISC_LINK_INIT(dl, link);
	for (i = 1 ; i < DEBUGLIST_COUNT ; i++) {
		dl->ptr[i] = NULL;
		dl->file[i] = NULL;
		dl->line[i] = 0;
	}

	dl->ptr[0] = ptr;
	dl->file[0] = file;
	dl->line[0] = line;
	dl->count = 1;

	ISC_LIST_PREPEND(mctx->debuglist, dl, link);
}

static inline void
delete_trace_entry(isc_mem_t *mctx, const void *ptr, unsigned int size,
		   const char *file, unsigned int line)
{
	debuglink_t *dl;
	unsigned int i;

	if (MEM_TRACE)
		fprintf(stderr, "del %p size %u file %s line %u mctx %p\n",
			ptr, size, file, line, mctx);

	if (!MEM_RECORD)
		return;

	dl = ISC_LIST_HEAD(mctx->debuglist);
	while (dl != NULL) {
		for (i = 0 ; i < DEBUGLIST_COUNT ; i++) {
			if (dl->ptr[i] == ptr) {
				dl->ptr[i] = NULL;
				dl->file[i] = NULL;
				dl->line[i] = 0;

				INSIST(dl->count > 0);
				dl->count--;
				if (dl->count == 0) {
					ISC_LIST_UNLINK(mctx->debuglist,
							dl, link);
					free(dl);
				}
				return;
			}
		}
		dl = ISC_LIST_NEXT(dl, link);
	}

	/*
	 * If we get here, we didn't find the item on the list.  We're
	 * screwed.
	 */
	INSIST(dl != NULL);
}
#endif /* ISC_MEM_TRACKLINES */

static inline size_t
rmsize(size_t size) {
	/*
 	 * round down to ALIGNMENT_SIZE
	 */
	size -= (size % ALIGNMENT_SIZE);
	return (size);
}

static inline size_t
quantize(size_t size) {
	int temp;

	/*
	 * Round up the result in order to get a size big
	 * enough to satisfy the request and be aligned on ALIGNMENT_SIZE
	 * byte boundaries.
	 */

	if (size == 0)
		return (ALIGNMENT_SIZE);
	temp = size + (ALIGNMENT_SIZE - 1);
	return (temp - temp % ALIGNMENT_SIZE);
}

static inline void
split(isc_mem_t *ctx, size_t size, size_t new_size) {
	unsigned char *ptr;
	size_t remaining_size;

	/*
	 * Unlink a frag of size 'size'.
	 */
	ptr = (unsigned char *)ctx->freelists[size];
	ctx->freelists[size] = ctx->freelists[size]->next;
	ctx->stats[size].freefrags--;

	/*
	 * Create a frag of size 'new_size' and link it in.
	 */
	((element *)ptr)->next = ctx->freelists[new_size];
	ctx->freelists[new_size] = (element *)ptr;
	ctx->stats[new_size].freefrags++;

	/*
	 * Create a frag of size 'size - new_size' and link it in.
	 */
	remaining_size = size - new_size;
	ptr += new_size;
	((element *)ptr)->next = ctx->freelists[remaining_size];
	ctx->freelists[remaining_size] = (element *)ptr;
	ctx->stats[remaining_size].freefrags++;
}

static inline isc_boolean_t
try_split(isc_mem_t *ctx, size_t new_size) {
	size_t i, doubled_size;

	if (!ctx->trysplit)
		return (ISC_FALSE);

	/*
	 * Try splitting a frag that's at least twice as big as the size
	 * we want.
	 */
	doubled_size = new_size * 2;
	for (i = doubled_size;
	     i < ctx->max_size;
	     i += ALIGNMENT_SIZE) {
		if (ctx->freelists[i] != NULL) {
			split(ctx, i, new_size);
			return (ISC_TRUE);
		}
	}

	/*
	 * No luck.  Try splitting any frag bigger than the size we need.
	 */
	for (i = new_size + ALIGNMENT_SIZE;
	     i < doubled_size;
	     i += ALIGNMENT_SIZE) {
		if (ctx->freelists[i] != NULL) {
			split(ctx, i, new_size);
			return (ISC_TRUE);
		}
	}

	return (ISC_FALSE);
}

static inline isc_boolean_t
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
		return (ISC_FALSE);

	INSIST(ctx->basic_table_count <= ctx->basic_table_size);
	if (ctx->basic_table_count == ctx->basic_table_size) {
		table_size = ctx->basic_table_size + TABLE_INCREMENT;
		table = (ctx->memalloc)(ctx->arg,
					table_size * sizeof (unsigned char *));
		if (table == NULL)
			return (ISC_FALSE);
		if (ctx->basic_table_size != 0) {
			memcpy(table, ctx->basic_table,
			       ctx->basic_table_size *
			       sizeof (unsigned char *));
			(ctx->memfree)(ctx->arg, ctx->basic_table);
		}
		ctx->basic_table = table;
		ctx->basic_table_size = table_size;
	}

	new = (ctx->memalloc)(ctx->arg, NUM_BASIC_BLOCKS * ctx->mem_target);
	if (new == NULL)
		return (ISC_FALSE);
	ctx->total += increment;
	ctx->basic_table[ctx->basic_table_count] = new;
	ctx->basic_table_count++;

	curr = new;
	next = curr + ctx->mem_target;
	for (i = 0; i < (NUM_BASIC_BLOCKS - 1); i++) {
		((element *)curr)->next = (element *)next;
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

	return (ISC_TRUE);
}

static inline isc_boolean_t
more_frags(isc_mem_t *ctx, size_t new_size) {
	int i, frags;
	size_t total_size;
	void *new;
	unsigned char *curr, *next;

	/*
	 * Try to get more fragments by chopping up a basic block.
	 */

	if (ctx->basic_blocks == NULL) {
		if (!more_basic_blocks(ctx)) {
			/*
			 * We can't get more memory from the OS, or we've
			 * hit the quota for this context.
			 */
			/*
			 * XXXRTH  "At quota" notification here.
			 */
			/*
			 * Maybe we can split one of our existing
			 * list frags.
			 */
			return (try_split(ctx, new_size));
		}
	}

	total_size = ctx->mem_target;
	new = ctx->basic_blocks;
	ctx->basic_blocks = ctx->basic_blocks->next;
	frags = total_size / new_size;
	ctx->stats[new_size].blocks++;
	ctx->stats[new_size].freefrags += frags;
	/*
	 * Set up a linked-list of blocks of size
	 * "new_size".
	 */
	curr = new;
	next = curr + new_size;
	total_size -= new_size;
	for (i = 0; i < (frags - 1); i++) {
		((element *)curr)->next = (element *)next;
		curr = next;
		next += new_size;
		total_size -= new_size;
	}
	/*
	 * Add the remaining fragment of the basic block to a free list.
	 */
	total_size = rmsize(total_size);
	if (total_size > 0) {
		((element *)next)->next = ctx->freelists[total_size];
		ctx->freelists[total_size] = (element *)next;
		ctx->stats[total_size].freefrags++;
	}
	/*
	 * curr is now pointing at the last block in the
	 * array.
	 */
	((element *)curr)->next = NULL;
	ctx->freelists[new_size] = new;

	return (ISC_TRUE);
}

static inline void *
mem_getunlocked(isc_mem_t *ctx, size_t size) {
	size_t new_size = quantize(size);
	void *ret;

	if (size >= ctx->max_size || new_size >= ctx->max_size) {
		/*
		 * memget() was called on something beyond our upper limit.
		 */
		if (ctx->quota != 0 && ctx->total + size > ctx->quota) {
			ret = NULL;
			goto done;
		}
		ret = (ctx->memalloc)(ctx->arg, size);
		if (ret != NULL) {
			ctx->total += size;
			ctx->inuse += size;
			ctx->stats[ctx->max_size].gets++;
			ctx->stats[ctx->max_size].totalgets++;
			/*
			 * If we don't set new_size to size, then the
			 * ISC_MEM_FILL code might write over bytes we
			 * don't own.
			 */
			new_size = size;
		}
		goto done;
	}

	/*
	 * If there are no blocks in the free list for this size, get a chunk
	 * of memory and then break it up into "new_size"-sized blocks, adding
	 * them to the free list.
	 */
	if (ctx->freelists[new_size] == NULL && !more_frags(ctx, new_size))
		return (NULL);

	/*
	 * The free list uses the "rounded-up" size "new_size".
	 */
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
	ctx->inuse += new_size;

 done:

#if ISC_MEM_FILL
	if (ret != NULL)
		memset(ret, 0xbe, new_size); /* Mnemonic for "beef". */
#endif

	return (ret);
}

static inline void
mem_putunlocked(isc_mem_t *ctx, void *mem, size_t size) {
	size_t new_size = quantize(size);

	if (size == ctx->max_size || new_size >= ctx->max_size) {
		/*
		 * memput() called on something beyond our upper limit.
		 */
#if ISC_MEM_FILL
		memset(mem, 0xde, size); /* Mnemonic for "dead". */
#endif
		(ctx->memfree)(ctx->arg, mem);
		INSIST(ctx->stats[ctx->max_size].gets != 0);
		ctx->stats[ctx->max_size].gets--;
		INSIST(size <= ctx->total);
		ctx->inuse -= size;
		ctx->total -= size;
		return;
	}

#if ISC_MEM_FILL
#if ISC_MEM_CHECKOVERRUN
	check_overrun(mem, size, new_size);
#endif
	memset(mem, 0xde, new_size); /* Mnemonic for "dead". */
#endif

	/*
	 * The free list uses the "rounded-up" size "new_size".
	 */
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
	ctx->inuse -= new_size;
}

/*
 * Private.
 */

static void *
default_memalloc(void *arg, size_t size) {
	UNUSED(arg);
	return (malloc(size));
}

static void
default_memfree(void *arg, void *ptr) {
	UNUSED(arg);
	free(ptr);
}

/*
 * Public.
 */

isc_result_t
isc_mem_createx(size_t init_max_size, size_t target_size,
		isc_memalloc_t memalloc, isc_memfree_t memfree, void *arg,
		isc_mem_t **ctxp)
{
	isc_mem_t *ctx;

	REQUIRE(ctxp != NULL && *ctxp == NULL);
	REQUIRE(memalloc != NULL);
	REQUIRE(memfree != NULL);

	ctx = (memalloc)(arg, sizeof *ctx);
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
	ctx->memalloc = memalloc;
	ctx->memfree = memfree;
	ctx->arg = arg;
	ctx->freelists = (memalloc)(arg, ctx->max_size * sizeof (element *));
	if (ctx->freelists == NULL) {
		(memfree)(arg, ctx);
		return (ISC_R_NOMEMORY);
	}
	ctx->checkfree = ISC_TRUE;
	ctx->trysplit = ISC_FALSE;
	memset(ctx->freelists, 0,
	       ctx->max_size * sizeof (element *));
	ctx->stats = (memalloc)(arg,
				(ctx->max_size+1) * sizeof (struct stats));
	if (ctx->stats == NULL) {
		(memfree)(arg, ctx->freelists);
		(memfree)(arg, ctx);
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
		(memfree)(arg, ctx->stats);
		(memfree)(arg, ctx->freelists);
		(memfree)(arg, ctx);
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed");
		return (ISC_R_UNEXPECTED);
	}
	ctx->references = 1;
	ctx->quota = 0;
	ctx->total = 0;
	ctx->inuse = 0;
	ctx->hi_water = 0;
	ctx->lo_water = 0;
	ctx->hi_called = ISC_FALSE;
	ctx->water = NULL;
	ctx->water_arg = NULL;
	ctx->magic = MEM_MAGIC;
	isc_ondestroy_init(&ctx->ondestroy);
	ISC_LIST_INIT(ctx->pools);
#if ISC_MEM_TRACKLINES
	ISC_LIST_INIT(ctx->debuglist);
#endif

	*ctxp = ctx;
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mem_create(size_t init_max_size, size_t target_size,
	       isc_mem_t **ctxp)
{
	return (isc_mem_createx(init_max_size, target_size,
				default_memalloc, default_memfree, NULL,
				ctxp));
}

static void
destroy(isc_mem_t *ctx) {
	unsigned int i;
	isc_ondestroy_t ondest;

	ctx->magic = 0;

	INSIST(ISC_LIST_EMPTY(ctx->pools));
#if ISC_MEM_TRACKLINES
	if (ctx->checkfree)
		INSIST(ISC_LIST_EMPTY(ctx->debuglist));
	else {
		debuglink_t *dl;

		for (dl = ISC_LIST_HEAD(ctx->debuglist);
		     dl != NULL;
		     dl = ISC_LIST_HEAD(ctx->debuglist)) {
			ISC_LIST_UNLINK(ctx->debuglist, dl, link);
			free(dl);
		}
	}
#endif
	INSIST(ctx->references == 0);

	if (ctx->checkfree) {
		for (i = 0; i <= ctx->max_size; i++)
			INSIST(ctx->stats[i].gets == 0);
	}

#if 0					/* XXX brister debugging */
	for (i = 0; i < ctx->basic_table_count; i++)
		memset(ctx->basic_table[i], 0x0,
		       NUM_BASIC_BLOCKS * ctx->mem_target);
#endif


	for (i = 0; i < ctx->basic_table_count; i++)
		(ctx->memfree)(ctx->arg, ctx->basic_table[i]);
	(ctx->memfree)(ctx->arg, ctx->freelists);
	(ctx->memfree)(ctx->arg, ctx->stats);
	(ctx->memfree)(ctx->arg, ctx->basic_table);

	ondest = ctx->ondestroy;

	DESTROYLOCK(&ctx->lock);
	(ctx->memfree)(ctx->arg, ctx);

	isc_ondestroy_notify(&ondest, ctx);
}

void
isc_mem_attach(isc_mem_t *source, isc_mem_t **targetp) {
	REQUIRE(VALID_CONTEXT(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	LOCK(&source->lock);
	source->references++;
	UNLOCK(&source->lock);

	*targetp = source;
}

void
isc_mem_detach(isc_mem_t **ctxp) {
	isc_mem_t *ctx;
	isc_boolean_t want_destroy = ISC_FALSE;

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	INSIST(ctx->references > 0);
	ctx->references--;
	if (ctx->references == 0)
		want_destroy = ISC_TRUE;
	UNLOCK(&ctx->lock);

	if (want_destroy)
		destroy(ctx);

	*ctxp = NULL;
}

/*
 * isc_mem_putanddetach() is the equivalent of:
 *
 * mctx = NULL;
 * isc_mem_attach(ptr->mctx, &mctx);
 * isc_mem_detach(&ptr->mctx);
 * isc_mem_put(mctx, ptr, sizeof(*ptr);
 * isc_mem_detach(&mctx);
 */

void
isc__mem_putanddetach(isc_mem_t **ctxp, void *ptr, size_t size FLARG) {
	isc_mem_t *ctx;
	isc_boolean_t want_destroy = ISC_FALSE;

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	/*
	 * Must be before mem_putunlocked() as ctxp is usually within
	 * [ptr..ptr+size).
	 */
	*ctxp = NULL;

	LOCK(&ctx->lock);
	DELETE_TRACE(ctx, ptr, size, file, line);
	mem_putunlocked(ctx, ptr, size);
	INSIST(ctx->references > 0);
	ctx->references--;
	if (ctx->references == 0)
		want_destroy = ISC_TRUE;
	UNLOCK(&ctx->lock);

	if (want_destroy)
		destroy(ctx);
}

void
isc_mem_destroy(isc_mem_t **ctxp) {
	isc_mem_t *ctx;
	isc_boolean_t want_destroy = ISC_FALSE;

	/*
	 * This routine provides legacy support for callers who use mctxs
	 * without attaching/detaching.
	 */

	REQUIRE(ctxp != NULL);
	ctx = *ctxp;
	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	REQUIRE(ctx->references == 1);
	ctx->references--;
	if (ctx->references == 0)
		want_destroy = ISC_TRUE;
	UNLOCK(&ctx->lock);

	if (want_destroy)
		destroy(ctx);

	*ctxp = NULL;
}

isc_result_t
isc_mem_ondestroy(isc_mem_t *ctx, isc_task_t *task, isc_event_t **event) {
	isc_result_t res;

	LOCK(&ctx->lock);
	res = isc_ondestroy_register(&ctx->ondestroy, task, event);
	UNLOCK(&ctx->lock);

	return (res);
}


isc_result_t
isc_mem_restore(isc_mem_t *ctx) {
	isc_result_t result;

	result = isc_mutex_init(&ctx->lock);
	if (result != ISC_R_SUCCESS)
		ctx->magic = 0;

	return (result);
}

#if ISC_MEM_FILL && ISC_MEM_CHECKOVERRUN
static inline void
check_overrun(void *mem, size_t size, size_t new_size) {
	unsigned char *cp;

	cp = (unsigned char *)mem;
	cp += size;
	while (size < new_size) {
		INSIST(*cp == 0xbe);
		cp++;
		size++;
	}
}
#endif

void *
isc__mem_get(isc_mem_t *ctx, size_t size FLARG) {
	void *ptr;
	isc_boolean_t call_water = ISC_FALSE;

	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	ptr = mem_getunlocked(ctx, size);
	ADD_TRACE(ctx, ptr, size, file, line);
	if (ctx->hi_water != 0 && !ctx->hi_called &&
	    ctx->inuse > ctx->hi_water) {
		ctx->hi_called = ISC_TRUE;
		call_water = ISC_TRUE;
	}
	UNLOCK(&ctx->lock);

	/* XXX remove */
	if (ctx->hi_water)
		fprintf(stderr,"inuse %u, total %u\n", ctx->inuse, ctx->total);

	if (call_water) {
		/* XXX remove */
		fprintf(stderr, "calling water(%p,ISC_MEM_HIWATER)\n",
			 ctx->water_arg);
		(ctx->water)(ctx->water_arg, ISC_MEM_HIWATER);
	}

	return (ptr);
}

void
isc__mem_put(isc_mem_t *ctx, void *ptr, size_t size FLARG)
{
	isc_boolean_t call_water = ISC_FALSE;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	LOCK(&ctx->lock);
	DELETE_TRACE(ctx, ptr, size, file, line);
	mem_putunlocked(ctx, ptr, size);
	if (ctx->hi_called && ctx->inuse < ctx->lo_water) {
		ctx->hi_called = ISC_FALSE;
		call_water = ISC_TRUE;
	}
	UNLOCK(&ctx->lock);

	/* XXX remove */
	if (ctx->hi_water)
		fprintf(stderr,"inuse %u, total %u\n", ctx->inuse, ctx->total);

	if (call_water) {
		/* XXX remove */
		fprintf(stderr, "calling water(%p,ISC_MEM_LOWATER)\n",
			 ctx->water_arg);
		(ctx->water)(ctx->water_arg, ISC_MEM_LOWATER);
	}
}

isc_result_t
isc_mem_preallocate(isc_mem_t *ctx) {
	size_t i;
	isc_result_t result = ISC_R_SUCCESS;
	void *ptr;

	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);

	for (i = 0; i < ctx->max_size; i += ALIGNMENT_SIZE) {
		ptr = mem_getunlocked(ctx, i);
		if (ptr == NULL) {
			result = ISC_R_NOMEMORY;
			break;
		}
		mem_putunlocked(ctx, ptr, i);
	}

	UNLOCK(&ctx->lock);

	return (result);
}

/*
 * Print the stats[] on the stream "out" with suitable formatting.
 */
void
isc_mem_stats(isc_mem_t *ctx, FILE *out) {
	size_t i;
	const struct stats *s;
	const isc_mempool_t *pool;

	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	if (ctx->freelists != NULL) {
		for (i = 0; i <= ctx->max_size; i++) {
			s = &ctx->stats[i];

			if (s->totalgets == 0 && s->gets == 0)
				continue;
			fprintf(out, "%s%5lu: %11lu gets, %11lu rem",
				(i == ctx->max_size) ? ">=" : "  ",
				(unsigned long) i, s->totalgets, s->gets);
			if (s->blocks != 0 || s->freefrags != 0)
				fprintf(out, " (%lu bl, %lu ff)",
					s->blocks, s->freefrags);
			fputc('\n', out);
		}
	}

	/*
	 * Note that since a pool can be locked now, these stats might be
	 * somewhat off if the pool is in active use at the time the stats
	 * are dumped.  The link fields are protected by the isc_mem_t's
	 * lock, however, so walking this list and extracting integers from
	 * stats fields is always safe.
	 */
	pool = ISC_LIST_HEAD(ctx->pools);
	if (pool != NULL) {
		fprintf(out, "[Pool statistics]\n");
		fprintf(out, "%15s %10s %10s %10s %10s %10s %10s %10s %1s\n",
			"name", "size", "maxalloc", "allocated", "freecount",
			"freemax", "fillcount", "gets", "L");
	}
	while (pool != NULL) {
		fprintf(out, "%15s %10lu %10u %10u %10u %10u %10u %10u %s\n",
			pool->name, (unsigned long) pool->size, pool->maxalloc,
			pool->allocated, pool->freecount, pool->freemax,
			pool->fillcount, pool->gets,
			(pool->lock == NULL ? "N" : "Y"));
		pool = ISC_LIST_NEXT(pool, link);
	}

#if ISC_MEM_TRACKLINES
	if (isc_mem_debugging > 1) {
		debuglink_t *dl;
		unsigned int i;

		fprintf(out, "DUMP OF ALL OUTSTANDING MEMORY ALLOCATIONS\n");
		dl = ISC_LIST_HEAD(ctx->debuglist);
		if (dl == NULL)
			fprintf(out, "\tNone.\n");
		while (dl != NULL) {
			for (i = 0 ; i < DEBUGLIST_COUNT ; i++)
				if (dl->ptr[i] != NULL)
					fprintf(out,
						"\tptr %p file %s line %u\n",
						dl->ptr[i], dl->file[i],
						dl->line[i]);
			dl = ISC_LIST_NEXT(dl, link);
		}
	}
#endif

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
 * Replacements for malloc() and free() -- they implicitly remember the
 * size of the object allocated (with some additional overhead).
 */

static void *
isc__mem_allocateunlocked(isc_mem_t *ctx, size_t size) {
	size_info *si;

	size += ALIGNMENT_SIZE;
	si = mem_getunlocked(ctx, size);
	if (si == NULL)
		return (NULL);
	si->u.size = size;
	return (&si[1]);
}

void *
isc__mem_allocate(isc_mem_t *ctx, size_t size FLARG) {
	size_info *si;

	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	si = isc__mem_allocateunlocked(ctx, size);
#if ISC_MEM_TRACKLINES
	if (si != NULL)
		ADD_TRACE(ctx, si, si[-1].u.size, file, line);
#endif
	UNLOCK(&ctx->lock);

	return (si);
}

void
isc__mem_free(isc_mem_t *ctx, void *ptr FLARG) {
	size_info *si;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	si = &(((size_info *)ptr)[-1]);
	LOCK(&ctx->lock);
	DELETE_TRACE(ctx, ptr, si->u.size, file, line);
	mem_putunlocked(ctx, si, si->u.size);
	UNLOCK(&ctx->lock);
}

/*
 * Other useful things.
 */

char *
isc__mem_strdup(isc_mem_t *mctx, const char *s FLARG) {
	size_t len;
	char *ns;

	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(s != NULL);

	len = strlen(s);

	ns = isc__mem_allocate(mctx, len + 1 FLARG_PASS);

	if (ns != NULL)
		strncpy(ns, s, len + 1);

	return (ns);
}

void
isc_mem_setdestroycheck(isc_mem_t *ctx, isc_boolean_t flag) {
	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	ctx->checkfree = flag;

	UNLOCK(&ctx->lock);
}

void
isc_mem_setsplit(isc_mem_t *ctx, isc_boolean_t flag) {
	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	ctx->trysplit = flag;

	UNLOCK(&ctx->lock);
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

size_t
isc_mem_inuse(isc_mem_t *ctx) {
	size_t inuse;

	REQUIRE(VALID_CONTEXT(ctx));
	LOCK(&ctx->lock);

	inuse = ctx->inuse;

	UNLOCK(&ctx->lock);

	return (inuse);
}

void
isc_mem_setwater(isc_mem_t *ctx, isc_mem_water_t water, void *water_arg,
                 size_t hiwater, size_t lowater)
{
	REQUIRE(VALID_CONTEXT(ctx));

	if (water != NULL) {
		REQUIRE(hiwater > lowater);
		REQUIRE(hiwater > 0);
		REQUIRE(lowater > 0);
	}

	LOCK(&ctx->lock);
	if (water == NULL) {
		ctx->water = NULL;
		ctx->water_arg = NULL;
		ctx->hi_water = 0;
		ctx->lo_water = 0;
		ctx->hi_called = ISC_FALSE;
	} else {
		ctx->water = water;
		ctx->water_arg = water_arg;
		ctx->hi_water = hiwater;
		ctx->lo_water = lowater;
		ctx->hi_called = ISC_FALSE;
	}
	UNLOCK(&ctx->lock);
}

/*
 * Memory pool stuff
 */


#if 0
/*
 * Free all but "n" items from the pool's free list.  If n == 0, all items
 * will be returned to the mctx.
 */
static void
mempool_release(isc_mempool_t *mpctx, unsigned int n) {
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
 * context must be locked, and the pool if needed.
 */
static void
mempool_releaseall(isc_mempool_t *mpctx) {
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
isc_mempool_create(isc_mem_t *mctx, size_t size, isc_mempool_t **mpctxp) {
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
	mpctx->lock = NULL;
	mpctx->mctx = mctx;
	mpctx->size = size;
	mpctx->maxalloc = UINT_MAX;
	mpctx->allocated = 0;
	mpctx->freecount = 0;
	mpctx->freemax = 1;
	mpctx->fillcount = 1;
	mpctx->gets = 0;
#if ISC_MEMPOOL_NAMES
	mpctx->name[0] = 0;
#endif
	mpctx->items = NULL;

	*mpctxp = mpctx;

	ISC_LIST_APPENDUNSAFE(mctx->pools, mpctx, link);

	UNLOCK(&mctx->lock);

	return (ISC_R_SUCCESS);
}

void
isc_mempool_setname(isc_mempool_t *mpctx, const char *name) {
	REQUIRE(name != NULL);

#if ISC_MEMPOOL_NAMES
	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	memset(mpctx->name, 0, sizeof(mpctx->name));
	strncpy(mpctx->name, name, sizeof(mpctx->name) - 1);

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
#else
	UNUSED(mpctx);
	UNUSED(name);
#endif
}

void
isc_mempool_destroy(isc_mempool_t **mpctxp) {
	isc_mempool_t *mpctx;
	isc_mem_t *mctx;
	isc_mutex_t *lock;

	REQUIRE(mpctxp != NULL);
	mpctx = *mpctxp;
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mpctx->allocated == 0);

	mctx = mpctx->mctx;

	lock = mpctx->lock;

	if (lock != NULL)
		LOCK(lock);

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

	if (lock != NULL)
		UNLOCK(lock);

	*mpctxp = NULL;
}

void
isc_mempool_associatelock(isc_mempool_t *mpctx, isc_mutex_t *lock) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mpctx->lock == NULL);
	REQUIRE(lock != NULL);

	mpctx->lock = lock;
}

void *
isc__mempool_get(isc_mempool_t *mpctx FLARG) {
	element *item;
	isc_mem_t *mctx;
	unsigned int i;

	REQUIRE(VALID_MEMPOOL(mpctx));

	mctx = mpctx->mctx;

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	/*
	 * Don't let the caller go over quota
	 */
	if (mpctx->allocated >= mpctx->maxalloc) {
		item = NULL;
		goto out;
	}

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
		goto out;
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
		goto out;

	mpctx->items = item->next;
	mpctx->freecount--;
	mpctx->gets++;
	mpctx->allocated++;

 out:
	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	if (item != NULL) {
		LOCK(&mctx->lock);
		ADD_TRACE(mctx, item, mpctx->size, file, line);
		UNLOCK(&mctx->lock);
	}

	return (item);
}

void
isc__mempool_put(isc_mempool_t *mpctx, void *mem FLARG) {
	isc_mem_t *mctx;
	element *item;

	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mem != NULL);

	mctx = mpctx->mctx;

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	INSIST(mpctx->allocated > 0);
	mpctx->allocated--;

	DELETE_TRACE(mctx, mem, mpctx->size, file, line);

	/*
	 * If our free list is full, return this to the mctx directly.
	 */
	if (mpctx->freecount >= mpctx->freemax) {
		LOCK(&mctx->lock);
		mem_putunlocked(mctx, mem, mpctx->size);
		UNLOCK(&mctx->lock);
		if (mpctx->lock != NULL)
			UNLOCK(mpctx->lock);
		return;
	}

	/*
	 * Otherwise, attach it to our free list and bump the counter.
	 */
	mpctx->freecount++;
	item = (element *)mem;
	item->next = mpctx->items;
	mpctx->items = item;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

/*
 * Quotas
 */

void
isc_mempool_setfreemax(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->freemax = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx) {
	unsigned int freemax;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	freemax = mpctx->freemax;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (freemax);
}

unsigned int
isc_mempool_getfreecount(isc_mempool_t *mpctx) {
	unsigned int freecount;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	freecount = mpctx->freecount;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (freecount);
}

void
isc_mempool_setmaxalloc(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(limit > 0);

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->maxalloc = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx) {
	unsigned int maxalloc;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	maxalloc = mpctx->maxalloc;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (maxalloc);
}

unsigned int
isc_mempool_getallocated(isc_mempool_t *mpctx) {
	unsigned int allocated;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	allocated = mpctx->allocated;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (allocated);
}

void
isc_mempool_setfillcount(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(limit > 0);
	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->fillcount = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx) {
	unsigned int fillcount;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	fillcount = mpctx->fillcount;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (fillcount);
}
