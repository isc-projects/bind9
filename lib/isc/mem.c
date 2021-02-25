/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <isc/align.h>
#include <isc/bind9.h>
#include <isc/hash.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/refcount.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#ifdef HAVE_LIBXML2
#include <libxml/xmlwriter.h>
#define ISC_XMLCHAR (const xmlChar *)
#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#include <json_object.h>
#endif /* HAVE_JSON_C */

#include "mem_p.h"

#define MCTXLOCK(m)   LOCK(&m->lock)
#define MCTXUNLOCK(m) UNLOCK(&m->lock)
#define MPCTXLOCK(mp)           \
	if (mp->lock != NULL) { \
		LOCK(mp->lock); \
	}
#define MPCTXUNLOCK(mp)           \
	if (mp->lock != NULL) {   \
		UNLOCK(mp->lock); \
	}

#ifndef ISC_MEM_DEBUGGING
#define ISC_MEM_DEBUGGING 0
#endif /* ifndef ISC_MEM_DEBUGGING */
LIBISC_EXTERNAL_DATA unsigned int isc_mem_debugging = ISC_MEM_DEBUGGING;
LIBISC_EXTERNAL_DATA unsigned int isc_mem_defaultflags = ISC_MEMFLAG_DEFAULT;

/*
 * Constants.
 */

#define ALIGNMENT	  8U /*%< must be a power of 2 */
#define ALIGNMENT_SIZE	  sizeof(size_info)
#define DEBUG_TABLE_COUNT 512U
#define STATS_BUCKETS	  512U
#define STATS_BUCKET_SIZE 32U

/*
 * Types.
 */
#if ISC_MEM_TRACKLINES
typedef struct debuglink debuglink_t;
struct debuglink {
	ISC_LINK(debuglink_t) link;
	const void *ptr;
	size_t size;
	const char *file;
	unsigned int line;
};

typedef ISC_LIST(debuglink_t) debuglist_t;

#define FLARG_PASS , file, line
#define FLARG	   , const char *file, unsigned int line
#else /* if ISC_MEM_TRACKLINES */
#define FLARG_PASS
#define FLARG
#endif /* if ISC_MEM_TRACKLINES */

typedef struct element element;
struct element {
	element *next;
};

typedef struct {
	alignas(ALIGNMENT) union {
		size_t size;
		isc_mem_t *ctx;
	};
} size_info;

struct stats {
	atomic_size_t gets;
	atomic_size_t totalgets;
};

#define MEM_MAGIC	 ISC_MAGIC('M', 'e', 'm', 'C')
#define VALID_CONTEXT(c) ISC_MAGIC_VALID(c, MEM_MAGIC)

/* List of all active memory contexts. */

static ISC_LIST(isc_mem_t) contexts;

static isc_once_t init_once = ISC_ONCE_INIT;
static isc_once_t shut_once = ISC_ONCE_INIT;
static isc_mutex_t contextslock;

/*%
 * Total size of lost memory due to a bug of external library.
 * Locked by the global lock.
 */
static uint64_t totallost;

struct isc_mem {
	unsigned int magic;
	unsigned int flags;
	isc_mutex_t lock;
	bool checkfree;
	struct stats stats[STATS_BUCKETS + 1];
	isc_refcount_t references;
	char name[16];
	atomic_size_t total;
	atomic_size_t inuse;
	atomic_size_t maxinuse;
	atomic_size_t malloced;
	atomic_size_t maxmalloced;
	atomic_size_t hi_water;
	atomic_size_t lo_water;
	atomic_bool hi_called;
	atomic_bool is_overmem;
	isc_mem_water_t water;
	void *water_arg;
	ISC_LIST(isc_mempool_t) pools;
	unsigned int poolcnt;

#if ISC_MEM_TRACKLINES
	debuglist_t *debuglist;
	size_t debuglistcnt;
#endif /* if ISC_MEM_TRACKLINES */

	ISC_LINK(isc_mem_t) link;
};

#define MEMPOOL_MAGIC	 ISC_MAGIC('M', 'E', 'M', 'p')
#define VALID_MEMPOOL(c) ISC_MAGIC_VALID(c, MEMPOOL_MAGIC)

struct isc_mempool {
	/* always unlocked */
	unsigned int magic;
	isc_mutex_t *lock; /*%< optional lock */
	isc_mem_t *mctx;   /*%< our memory context */
	/*%< locked via the memory context's lock */
	ISC_LINK(isc_mempool_t) link; /*%< next pool in this mem context */
	/*%< optionally locked from here down */
	element *items;		 /*%< low water item list */
	size_t size;		 /*%< size of each item on this pool */
	atomic_size_t maxalloc;	 /*%< max number of items allowed */
	atomic_size_t allocated; /*%< # of items currently given out */
	atomic_size_t freecount; /*%< # of items on reserved list */
	atomic_size_t freemax;	 /*%< # of items allowed on free list */
	atomic_size_t fillcount; /*%< # of items to fetch on each fill */
	/*%< Stats only. */
	atomic_size_t gets; /*%< # of requests to this pool */
			    /*%< Debugging only. */
	char name[16];	    /*%< printed name in stats reports */
};

/*
 * Private Inline-able.
 */

#if !ISC_MEM_TRACKLINES
#define ADD_TRACE(a, b, c, d, e)
#define DELETE_TRACE(a, b, c, d, e)
#define ISC_MEMFUNC_SCOPE
#else /* if !ISC_MEM_TRACKLINES */
#define TRACE_OR_RECORD (ISC_MEM_DEBUGTRACE | ISC_MEM_DEBUGRECORD)

#define SHOULD_TRACE_OR_RECORD(ptr)                                  \
	(ISC_UNLIKELY((isc_mem_debugging & TRACE_OR_RECORD) != 0) && \
	 ptr != NULL)

#define ADD_TRACE(a, b, c, d, e)                \
	if (SHOULD_TRACE_OR_RECORD(b)) {        \
		add_trace_entry(a, b, c, d, e); \
	}

#define DELETE_TRACE(a, b, c, d, e)                \
	if (SHOULD_TRACE_OR_RECORD(b)) {           \
		delete_trace_entry(a, b, c, d, e); \
	}

static void
print_active(isc_mem_t *ctx, FILE *out);
#endif /* ISC_MEM_TRACKLINES */

static inline size_t
increment_malloced(isc_mem_t *ctx, size_t size) {
	size_t malloced = atomic_fetch_add_relaxed(&ctx->malloced, size) + size;
	size_t maxmalloced = atomic_load_acquire(&ctx->maxmalloced);
	if (malloced > maxmalloced) {
		atomic_compare_exchange_strong(&ctx->maxmalloced, &maxmalloced,
					       malloced);
	}

	return (malloced);
}

static inline size_t
decrement_malloced(isc_mem_t *ctx, size_t size) {
	size_t malloced = atomic_fetch_sub_release(&ctx->malloced, size) - size;

	return (malloced);
}

#if ISC_MEM_TRACKLINES
/*!
 * mctx must not be locked.
 */
static void
add_trace_entry(isc_mem_t *mctx, const void *ptr, size_t size FLARG) {
	debuglink_t *dl;
	uint32_t hash;
	uint32_t idx;

	MCTXLOCK(mctx);

	if ((isc_mem_debugging & ISC_MEM_DEBUGTRACE) != 0) {
		fprintf(stderr, "add %p size %zu file %s line %u mctx %p\n",
			ptr, size, file, line, mctx);
	}

	if (mctx->debuglist == NULL) {
		goto unlock;
	}

#ifdef __COVERITY__
	/*
	 * Use simple conversion from pointer to hash to avoid
	 * tainting 'ptr' due to byte swap in isc_hash_function.
	 */
	hash = (uintptr_t)ptr >> 3;
#else
	hash = isc_hash_function(&ptr, sizeof(ptr), true);
#endif
	idx = hash % DEBUG_TABLE_COUNT;

	dl = malloc(sizeof(debuglink_t));
	INSIST(dl != NULL);
	increment_malloced(mctx, sizeof(debuglink_t));

	ISC_LINK_INIT(dl, link);
	dl->ptr = ptr;
	dl->size = size;
	dl->file = file;
	dl->line = line;

	ISC_LIST_PREPEND(mctx->debuglist[idx], dl, link);
	mctx->debuglistcnt++;
unlock:
	MCTXUNLOCK(mctx);
}

static void
delete_trace_entry(isc_mem_t *mctx, const void *ptr, size_t size,
		   const char *file, unsigned int line) {
	debuglink_t *dl;
	uint32_t hash;
	uint32_t idx;

	MCTXLOCK(mctx);

	if ((isc_mem_debugging & ISC_MEM_DEBUGTRACE) != 0) {
		fprintf(stderr, "del %p size %zu file %s line %u mctx %p\n",
			ptr, size, file, line, mctx);
	}

	if (mctx->debuglist == NULL) {
		goto unlock;
	}

#ifdef __COVERITY__
	/*
	 * Use simple conversion from pointer to hash to avoid
	 * tainting 'ptr' due to byte swap in isc_hash_function.
	 */
	hash = (uintptr_t)ptr >> 3;
#else
	hash = isc_hash_function(&ptr, sizeof(ptr), true);
#endif
	idx = hash % DEBUG_TABLE_COUNT;

	dl = ISC_LIST_HEAD(mctx->debuglist[idx]);
	while (ISC_LIKELY(dl != NULL)) {
		if (ISC_UNLIKELY(dl->ptr == ptr)) {
			ISC_LIST_UNLINK(mctx->debuglist[idx], dl, link);
			decrement_malloced(mctx, sizeof(*dl));
			free(dl);
			goto unlock;
		}
		dl = ISC_LIST_NEXT(dl, link);
	}

	/*
	 * If we get here, we didn't find the item on the list.  We're
	 * screwed.
	 */
	INSIST(0);
	ISC_UNREACHABLE();
unlock:
	MCTXUNLOCK(mctx);
}
#endif /* ISC_MEM_TRACKLINES */

static void *
default_memalloc(size_t size);
static void
default_memfree(void *ptr);

/*!
 * Perform a malloc, doing memory filling and overrun detection as necessary.
 */
static inline void *
mem_get(isc_mem_t *ctx, size_t size) {
	char *ret;

	ret = default_memalloc(size);

	if (ISC_UNLIKELY((ctx->flags & ISC_MEMFLAG_FILL) != 0)) {
		if (ISC_LIKELY(ret != NULL)) {
			memset(ret, 0xbe, size); /* Mnemonic for "beef". */
		}
	}

	return (ret);
}

/*!
 * Perform a free, doing memory filling and overrun detection as necessary.
 */
/* coverity[+free : arg-1] */
static inline void
mem_put(isc_mem_t *ctx, void *mem, size_t size) {
	if (ISC_UNLIKELY((ctx->flags & ISC_MEMFLAG_FILL) != 0)) {
		memset(mem, 0xde, size); /* Mnemonic for "dead". */
	}
	default_memfree(mem);
}

#define stats_bucket(ctx, size)                      \
	((size / STATS_BUCKET_SIZE) >= STATS_BUCKETS \
		 ? &ctx->stats[STATS_BUCKETS]        \
		 : &ctx->stats[size / STATS_BUCKET_SIZE])

/*!
 * Update internal counters after a memory get.
 */
static inline void
mem_getstats(isc_mem_t *ctx, size_t size) {
	struct stats *stats = stats_bucket(ctx, size);

	atomic_fetch_add_relaxed(&ctx->total, size);
	atomic_fetch_add_release(&ctx->inuse, size);

	atomic_fetch_add_relaxed(&stats->gets, 1);
	atomic_fetch_add_relaxed(&stats->totalgets, 1);

	increment_malloced(ctx, size);
}

/*!
 * Update internal counters after a memory put.
 */
static inline void
mem_putstats(isc_mem_t *ctx, void *ptr, size_t size) {
	struct stats *stats = stats_bucket(ctx, size);

	UNUSED(ptr);

	INSIST(atomic_fetch_sub_release(&ctx->inuse, size) >= size);

	INSIST(atomic_fetch_sub_release(&stats->gets, 1) >= 1);

	decrement_malloced(ctx, size);
}

/*
 * Private.
 */

static void *
default_memalloc(size_t size) {
	void *ptr;

	ptr = malloc(size);

	/*
	 * If the space cannot be allocated, a null pointer is returned. If the
	 * size of the space requested is zero, the behavior is
	 * implementation-defined: either a null pointer is returned, or the
	 * behavior is as if the size were some nonzero value, except that the
	 * returned pointer shall not be used to access an object.
	 * [ISO9899 § 7.22.3]
	 *
	 * [ISO9899]
	 *   ISO/IEC WG 9899:2011: Programming languages - C.
	 *   International Organization for Standardization, Geneva,
	 * Switzerland.
	 *   http://www.open-std.org/JTC1/SC22/WG14/www/docs/n1570.pdf
	 */

	if (ptr == NULL && size != 0) {
		char strbuf[ISC_STRERRORSIZE];
		strerror_r(errno, strbuf, sizeof(strbuf));
		isc_error_fatal(__FILE__, __LINE__, "malloc failed: %s",
				strbuf);
	}

	return (ptr);
}

static void
default_memfree(void *ptr) {
	free(ptr);
}

static void
mem_initialize(void) {
	isc_mutex_init(&contextslock);
	ISC_LIST_INIT(contexts);
	totallost = 0;
}

void
isc__mem_initialize(void) {
	RUNTIME_CHECK(isc_once_do(&init_once, mem_initialize) == ISC_R_SUCCESS);
}

static void
mem_shutdown(void) {
	isc__mem_checkdestroyed();

	isc_mutex_destroy(&contextslock);
}

void
isc__mem_shutdown(void) {
	RUNTIME_CHECK(isc_once_do(&shut_once, mem_shutdown) == ISC_R_SUCCESS);
}

static void
mem_create(isc_mem_t **ctxp, unsigned int flags) {
	REQUIRE(ctxp != NULL && *ctxp == NULL);

	isc_mem_t *ctx;

	STATIC_ASSERT((ALIGNMENT_SIZE & (ALIGNMENT_SIZE - 1)) == 0,
		      "alignment size not power of 2");
	STATIC_ASSERT(ALIGNMENT_SIZE >= sizeof(size_info),
		      "alignment size too small");

	ctx = default_memalloc(sizeof(*ctx));

	*ctx = (isc_mem_t){
		.magic = MEM_MAGIC,
		.flags = flags,
		.checkfree = true,
	};

	isc_mutex_init(&ctx->lock);
	isc_refcount_init(&ctx->references, 1);

	atomic_init(&ctx->total, 0);
	atomic_init(&ctx->inuse, 0);
	atomic_init(&ctx->maxinuse, 0);
	atomic_init(&ctx->malloced, sizeof(*ctx));
	atomic_init(&ctx->maxmalloced, sizeof(*ctx));

	ISC_LIST_INIT(ctx->pools);

#if ISC_MEM_TRACKLINES
	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGRECORD) != 0)) {
		unsigned int i;

		ctx->debuglist = default_memalloc(
			(DEBUG_TABLE_COUNT * sizeof(debuglist_t)));
		for (i = 0; i < DEBUG_TABLE_COUNT; i++) {
			ISC_LIST_INIT(ctx->debuglist[i]);
		}
		increment_malloced(ctx,
				   DEBUG_TABLE_COUNT * sizeof(debuglist_t));
	}
#endif /* if ISC_MEM_TRACKLINES */

	LOCK(&contextslock);
	ISC_LIST_INITANDAPPEND(contexts, ctx, link);
	UNLOCK(&contextslock);

	*ctxp = ctx;
}

/*
 * Public.
 */

static void
destroy(isc_mem_t *ctx) {
	unsigned int i;
	size_t malloced;

	LOCK(&contextslock);
	ISC_LIST_UNLINK(contexts, ctx, link);
	totallost += isc_mem_inuse(ctx);
	UNLOCK(&contextslock);

	ctx->magic = 0;

	INSIST(ISC_LIST_EMPTY(ctx->pools));

#if ISC_MEM_TRACKLINES
	if (ISC_UNLIKELY(ctx->debuglist != NULL)) {
		debuglink_t *dl;
		for (i = 0; i < DEBUG_TABLE_COUNT; i++) {
			for (dl = ISC_LIST_HEAD(ctx->debuglist[i]); dl != NULL;
			     dl = ISC_LIST_HEAD(ctx->debuglist[i]))
			{
				if (ctx->checkfree && dl->ptr != NULL) {
					print_active(ctx, stderr);
				}
				INSIST(!ctx->checkfree || dl->ptr == NULL);

				ISC_LIST_UNLINK(ctx->debuglist[i], dl, link);
				free(dl);
				decrement_malloced(ctx, sizeof(*dl));
			}
		}

		default_memfree(ctx->debuglist);
		decrement_malloced(ctx,
				   DEBUG_TABLE_COUNT * sizeof(debuglist_t));
	}
#endif /* if ISC_MEM_TRACKLINES */

	if (ctx->checkfree) {
		for (i = 0; i <= STATS_BUCKETS; i++) {
			struct stats *stats = &ctx->stats[i];
			size_t gets = atomic_load_acquire(&stats->gets);
			if (gets != 0U) {
				fprintf(stderr,
					"Failing assertion due to probable "
					"leaked memory in context %p (\"%s\") "
					"(stats[%u].gets == %zu).\n",
					ctx, ctx->name, i, gets);
#if ISC_MEM_TRACKLINES
				print_active(ctx, stderr);
#endif /* if ISC_MEM_TRACKLINES */
				INSIST(gets == 0U);
			}
		}
	}

	isc_mutex_destroy(&ctx->lock);

	malloced = decrement_malloced(ctx, sizeof(*ctx));

	if (ctx->checkfree) {
		INSIST(malloced == 0);
	}
	default_memfree(ctx);
}

void
isc_mem_attach(isc_mem_t *source, isc_mem_t **targetp) {
	REQUIRE(VALID_CONTEXT(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
isc_mem_detach(isc_mem_t **ctxp) {
	REQUIRE(ctxp != NULL && VALID_CONTEXT(*ctxp));

	isc_mem_t *ctx = *ctxp;
	*ctxp = NULL;

	if (isc_refcount_decrement(&ctx->references) == 1) {
		isc_refcount_destroy(&ctx->references);
		destroy(ctx);
	}
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
	REQUIRE(ctxp != NULL && VALID_CONTEXT(*ctxp));
	REQUIRE(ptr != NULL);

	isc_mem_t *ctx = *ctxp;
	*ctxp = NULL;

	if (ISC_UNLIKELY((isc_mem_debugging &
			  (ISC_MEM_DEBUGSIZE | ISC_MEM_DEBUGCTX)) != 0))
	{
		if ((isc_mem_debugging & ISC_MEM_DEBUGSIZE) != 0) {
			size_info *si = &(((size_info *)ptr)[-1]);
			size_t oldsize = si->size - ALIGNMENT_SIZE;
			if ((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0) {
				oldsize -= ALIGNMENT_SIZE;
			}
			INSIST(oldsize == size);
		}
		isc__mem_free(ctx, ptr FLARG_PASS);

		goto destroy;
	}

	DELETE_TRACE(ctx, ptr, size, file, line);

	mem_putstats(ctx, ptr, size);
	mem_put(ctx, ptr, size);

destroy:
	if (isc_refcount_decrement(&ctx->references) == 1) {
		isc_refcount_destroy(&ctx->references);
		destroy(ctx);
	}
}

void
isc_mem_destroy(isc_mem_t **ctxp) {
	/*
	 * This routine provides legacy support for callers who use mctxs
	 * without attaching/detaching.
	 */

	REQUIRE(ctxp != NULL && VALID_CONTEXT(*ctxp));

	isc_mem_t *ctx = *ctxp;

#if ISC_MEM_TRACKLINES
	if (isc_refcount_decrement(&ctx->references) > 1) {
		print_active(ctx, stderr);
	}
#else  /* if ISC_MEM_TRACKLINES */
	isc_refcount_decrementz(&ctx->references);
#endif /* if ISC_MEM_TRACKLINES */
	isc_refcount_destroy(&ctx->references);
	destroy(ctx);

	*ctxp = NULL;
}

static inline bool
hi_water(isc_mem_t *ctx) {
	bool call_water = false;
	size_t inuse = atomic_load_acquire(&ctx->inuse);
	size_t maxinuse = atomic_load_acquire(&ctx->maxinuse);
	size_t hi_water = atomic_load_acquire(&ctx->hi_water);

	if (hi_water != 0U && inuse > hi_water) {
		atomic_store(&ctx->is_overmem, true);
		if (!atomic_load_acquire(&ctx->hi_called)) {
			call_water = true;
		}
	}
	if (inuse > maxinuse) {
		(void)atomic_compare_exchange_strong(&ctx->maxinuse, &maxinuse,
						     inuse);

		if (hi_water != 0U && inuse > hi_water &&
		    (isc_mem_debugging & ISC_MEM_DEBUGUSAGE) != 0)
		{
			fprintf(stderr, "maxinuse = %lu\n",
				(unsigned long)inuse);
		}
	}

	return (call_water);
}

/*
 * The check against ctx->lo_water == 0 is for the condition
 * when the context was pushed over hi_water but then had
 * isc_mem_setwater() called with 0 for hi_water and lo_water.
 */
static inline bool
lo_water(isc_mem_t *ctx) {
	bool call_water = false;
	size_t inuse = atomic_load_acquire(&ctx->inuse);
	size_t lo_water = atomic_load_acquire(&ctx->lo_water);

	if ((inuse < lo_water) || (lo_water == 0U)) {
		atomic_store(&ctx->is_overmem, false);
		if (atomic_load_acquire(&ctx->hi_called)) {
			call_water = true;
		}
	}

	return (call_water);
}

void *
isc__mem_get(isc_mem_t *ctx, size_t size FLARG) {
	REQUIRE(VALID_CONTEXT(ctx));

	void *ptr;
	bool call_water = false;

	if (ISC_UNLIKELY((isc_mem_debugging &
			  (ISC_MEM_DEBUGSIZE | ISC_MEM_DEBUGCTX)) != 0))
	{
		return (isc__mem_allocate(ctx, size FLARG_PASS));
	}

	ptr = mem_get(ctx, size);
	mem_getstats(ctx, size);

	ADD_TRACE(ctx, ptr, size, file, line);

	call_water = hi_water(ctx);

	if (call_water && (ctx->water != NULL)) {
		(ctx->water)(ctx->water_arg, ISC_MEM_HIWATER);
	}

	return (ptr);
}

void
isc__mem_put(isc_mem_t *ctx, void *ptr, size_t size FLARG) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	bool call_water = false;
	size_info *si;

	if (ISC_UNLIKELY((isc_mem_debugging &
			  (ISC_MEM_DEBUGSIZE | ISC_MEM_DEBUGCTX)) != 0))
	{
		if ((isc_mem_debugging & ISC_MEM_DEBUGSIZE) != 0) {
			size_t oldsize;
			si = &(((size_info *)ptr)[-1]);
			oldsize = si->size - ALIGNMENT_SIZE;
			if ((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0) {
				oldsize -= ALIGNMENT_SIZE;
			}
			INSIST(oldsize == size);
		}
		isc__mem_free(ctx, ptr FLARG_PASS);
		return;
	}

	DELETE_TRACE(ctx, ptr, size, file, line);

	mem_putstats(ctx, ptr, size);
	mem_put(ctx, ptr, size);

	call_water = lo_water(ctx);

	if (call_water && (ctx->water != NULL)) {
		(ctx->water)(ctx->water_arg, ISC_MEM_LOWATER);
	}
}

void
isc_mem_waterack(isc_mem_t *ctx, int flag) {
	REQUIRE(VALID_CONTEXT(ctx));

	if (flag == ISC_MEM_LOWATER) {
		atomic_store(&ctx->hi_called, false);
	} else if (flag == ISC_MEM_HIWATER) {
		atomic_store(&ctx->hi_called, true);
	}
}

#if ISC_MEM_TRACKLINES
static void
print_active(isc_mem_t *mctx, FILE *out) {
	if (mctx->debuglist != NULL) {
		debuglink_t *dl;
		unsigned int i;
		bool found;

		fprintf(out, "Dump of all outstanding memory "
			     "allocations:\n");
		found = false;
		for (i = 0; i < DEBUG_TABLE_COUNT; i++) {
			dl = ISC_LIST_HEAD(mctx->debuglist[i]);

			if (dl != NULL) {
				found = true;
			}

			while (dl != NULL) {
				if (dl->ptr != NULL) {
					fprintf(out,
						"\tptr %p size %zu "
						"file %s "
						"line %u\n",
						dl->ptr, dl->size, dl->file,
						dl->line);
				}
				dl = ISC_LIST_NEXT(dl, link);
			}
		}

		if (!found) {
			fprintf(out, "\tNone.\n");
		}
	}
}
#endif /* if ISC_MEM_TRACKLINES */

/*
 * Print the stats[] on the stream "out" with suitable formatting.
 */
void
isc_mem_stats(isc_mem_t *ctx, FILE *out) {
	REQUIRE(VALID_CONTEXT(ctx));

	isc_mempool_t *pool;

	MCTXLOCK(ctx);

	for (size_t i = 0; i <= STATS_BUCKETS; i++) {
		size_t totalgets;
		size_t gets;
		struct stats *stats = &ctx->stats[i];

		totalgets = atomic_load_acquire(&stats->totalgets);
		gets = atomic_load_acquire(&stats->gets);

		if (totalgets != 0U && gets != 0U) {
			fprintf(out, "%s%5zu: %11zu gets, %11zu rem",
				(i == STATS_BUCKETS) ? ">=" : "  ", i,
				totalgets, gets);
			fputc('\n', out);
		}
	}

	/*
	 * Note that since a pool can be locked now, these stats might
	 * be somewhat off if the pool is in active use at the time the
	 * stats are dumped.  The link fields are protected by the
	 * isc_mem_t's lock, however, so walking this list and
	 * extracting integers from stats fields is always safe.
	 */
	pool = ISC_LIST_HEAD(ctx->pools);
	if (pool != NULL) {
		fprintf(out, "[Pool statistics]\n");
		fprintf(out, "%15s %10s %10s %10s %10s %10s %10s %10s %1s\n",
			"name", "size", "maxalloc", "allocated", "freecount",
			"freemax", "fillcount", "gets", "L");
	}
	while (pool != NULL) {
		fprintf(out,
			"%15s %10zu %10zu %10zu %10zu %10zu %10zu %10zu %s\n",
			pool->name, pool->size,
			atomic_load_relaxed(&pool->maxalloc),
			atomic_load_relaxed(&pool->allocated),
			atomic_load_relaxed(&pool->freecount),
			atomic_load_relaxed(&pool->freemax),
			atomic_load_relaxed(&pool->fillcount),
			atomic_load_relaxed(&pool->gets),
			(pool->lock == NULL ? "N" : "Y"));
		pool = ISC_LIST_NEXT(pool, link);
	}

#if ISC_MEM_TRACKLINES
	print_active(ctx, out);
#endif /* if ISC_MEM_TRACKLINES */

	MCTXUNLOCK(ctx);
}

/*
 * Replacements for malloc() and free() -- they implicitly remember the
 * size of the object allocated (with some additional overhead).
 */

static void *
mem_allocateunlocked(isc_mem_t *ctx, size_t size) {
	size_info *si;

	size += ALIGNMENT_SIZE;
	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)) {
		size += ALIGNMENT_SIZE;
	}

	si = mem_get(ctx, size);

	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)) {
		si->ctx = ctx;
		si++;
	}
	si->size = size;
	return (&si[1]);
}

void *
isc__mem_allocate(isc_mem_t *ctx, size_t size FLARG) {
	REQUIRE(VALID_CONTEXT(ctx));

	size_info *si;
	bool call_water = false;

	si = mem_allocateunlocked(ctx, size);
	mem_getstats(ctx, si[-1].size);

	ADD_TRACE(ctx, si, si[-1].size, file, line);

	call_water = hi_water(ctx);

	if (call_water && (ctx->water != NULL)) {
		(ctx->water)(ctx->water_arg, ISC_MEM_HIWATER);
	}

	return (si);
}

void *
isc__mem_reallocate(isc_mem_t *ctx, void *ptr, size_t size FLARG) {
	REQUIRE(VALID_CONTEXT(ctx));

	void *new_ptr = NULL;

	/*
	 * This function emulates the realloc(3) standard library
	 * function:
	 * - if size > 0, allocate new memory; and if ptr is non NULL,
	 * copy as much of the old contents to the new buffer and free
	 * the old one. Note that when allocation fails the original
	 * pointer is intact; the caller must free it.
	 * - if size is 0 and ptr is non NULL, simply free the given
	 * ptr.
	 * - this function returns:
	 *     pointer to the newly allocated memory, or
	 *     NULL if allocation fails or doesn't happen.
	 */
	if (size > 0U) {
		new_ptr = isc__mem_allocate(ctx, size FLARG_PASS);
		if (new_ptr != NULL && ptr != NULL) {
			size_t oldsize, copysize;
			oldsize = (((size_info *)ptr)[-1]).size;
			INSIST(oldsize >= ALIGNMENT_SIZE);
			oldsize -= ALIGNMENT_SIZE;
			if (ISC_UNLIKELY((isc_mem_debugging &
					  ISC_MEM_DEBUGCTX) != 0)) {
				INSIST(oldsize >= ALIGNMENT_SIZE);
				oldsize -= ALIGNMENT_SIZE;
			}
			copysize = (oldsize > size) ? size : oldsize;
			memmove(new_ptr, ptr, copysize);
			isc__mem_free(ctx, ptr FLARG_PASS);
		}
	} else if (ptr != NULL) {
		isc__mem_free(ctx, ptr FLARG_PASS);
	}

	return (new_ptr);
}

void
isc__mem_free(isc_mem_t *ctx, void *ptr FLARG) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	size_info *si;
	size_t size;
	bool call_water = false;

	if (ISC_UNLIKELY((isc_mem_debugging & ISC_MEM_DEBUGCTX) != 0)) {
		si = &(((size_info *)ptr)[-2]);
		REQUIRE(si->ctx == ctx);
		size = si[1].size;
	} else {
		si = &(((size_info *)ptr)[-1]);
		size = si->size;
	}

	DELETE_TRACE(ctx, ptr, size, file, line);

	mem_putstats(ctx, si, size);
	mem_put(ctx, si, size);

	call_water = lo_water(ctx);

	if (call_water && (ctx->water != NULL)) {
		(ctx->water)(ctx->water_arg, ISC_MEM_LOWATER);
	}
}

/*
 * Other useful things.
 */

char *
isc__mem_strdup(isc_mem_t *mctx, const char *s FLARG) {
	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(s != NULL);

	size_t len;
	char *ns;

	len = strlen(s) + 1;

	ns = isc__mem_allocate(mctx, len FLARG_PASS);

	if (ns != NULL) {
		strlcpy(ns, s, len);
	}

	return (ns);
}

char *
isc__mem_strndup(isc_mem_t *mctx, const char *s, size_t size FLARG) {
	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(s != NULL);

	size_t len;
	char *ns;

	len = strlen(s) + 1;
	if (len > size) {
		len = size;
	}

	ns = isc__mem_allocate(mctx, len FLARG_PASS);

	if (ns != NULL) {
		strlcpy(ns, s, len);
	}

	return (ns);
}

void
isc_mem_setdestroycheck(isc_mem_t *ctx, bool flag) {
	REQUIRE(VALID_CONTEXT(ctx));

	MCTXLOCK(ctx);

	ctx->checkfree = flag;

	MCTXUNLOCK(ctx);
}

size_t
isc_mem_inuse(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_acquire(&ctx->inuse));
}

size_t
isc_mem_maxinuse(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_acquire(&ctx->maxinuse));
}

size_t
isc_mem_total(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_acquire(&ctx->total));
}

size_t
isc_mem_malloced(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_acquire(&ctx->malloced));
}

size_t
isc_mem_maxmalloced(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_acquire(&ctx->maxmalloced));
}

void
isc_mem_setwater(isc_mem_t *ctx, isc_mem_water_t water, void *water_arg,
		 size_t hiwater, size_t lowater) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(hiwater >= lowater);

	bool callwater = false;
	isc_mem_water_t oldwater;
	void *oldwater_arg;

	MCTXLOCK(ctx);
	oldwater = ctx->water;
	oldwater_arg = ctx->water_arg;
	if (water == NULL) {
		callwater = atomic_load_acquire(&ctx->hi_called);
		ctx->water = NULL;
		ctx->water_arg = NULL;
		atomic_store_release(&ctx->hi_water, 0);
		atomic_store_release(&ctx->lo_water, 0);
	} else {
		if (atomic_load_acquire(&ctx->hi_called) &&
		    (ctx->water != water || ctx->water_arg != water_arg ||
		     atomic_load_acquire(&ctx->inuse) < lowater ||
		     lowater == 0U))
		{
			callwater = true;
		}
		ctx->water = water;
		ctx->water_arg = water_arg;
		atomic_store_release(&ctx->hi_water, hiwater);
		atomic_store_release(&ctx->lo_water, lowater);
	}
	MCTXUNLOCK(ctx);

	if (callwater && oldwater != NULL) {
		(oldwater)(oldwater_arg, ISC_MEM_LOWATER);
	}
}

bool
isc_mem_isovermem(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	return (atomic_load_relaxed(&ctx->is_overmem));
}

void
isc_mem_setname(isc_mem_t *ctx, const char *name) {
	REQUIRE(VALID_CONTEXT(ctx));

	LOCK(&ctx->lock);
	strlcpy(ctx->name, name, sizeof(ctx->name));
	UNLOCK(&ctx->lock);
}

const char *
isc_mem_getname(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	if (ctx->name[0] == 0) {
		return ("");
	}

	return (ctx->name);
}

/*
 * Memory pool stuff
 */

void
isc_mempool_create(isc_mem_t *mctx, size_t size, isc_mempool_t **mpctxp) {
	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(size > 0U);
	REQUIRE(mpctxp != NULL && *mpctxp == NULL);

	isc_mempool_t *mpctx;

	/*
	 * Mempools are stored as a linked list of element.
	 */
	if (size < sizeof(element)) {
		size = sizeof(element);
	}

	/*
	 * Allocate space for this pool, initialize values, and if all
	 * works well, attach to the memory context.
	 */
	mpctx = isc_mem_get(mctx, sizeof(isc_mempool_t));

	*mpctx = (isc_mempool_t){
		.magic = MEMPOOL_MAGIC,
		.mctx = mctx,
		.size = size,
	};

	atomic_init(&mpctx->maxalloc, SIZE_MAX);
	atomic_init(&mpctx->allocated, 0);
	atomic_init(&mpctx->freecount, 0);
	atomic_init(&mpctx->freemax, 1);
	atomic_init(&mpctx->fillcount, 1);

	*mpctxp = (isc_mempool_t *)mpctx;

	MCTXLOCK(mctx);
	ISC_LIST_INITANDAPPEND(mctx->pools, mpctx, link);
	mctx->poolcnt++;
	MCTXUNLOCK(mctx);
}

void
isc_mempool_setname(isc_mempool_t *mpctx, const char *name) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(name != NULL);

	MPCTXLOCK(mpctx);

	strlcpy(mpctx->name, name, sizeof(mpctx->name));

	MPCTXUNLOCK(mpctx);
}

void
isc_mempool_destroy(isc_mempool_t **mpctxp) {
	REQUIRE(mpctxp != NULL);
	REQUIRE(VALID_MEMPOOL(*mpctxp));

	isc_mempool_t *mpctx;
	isc_mem_t *mctx;
	isc_mutex_t *lock;
	element *item;

	mpctx = *mpctxp;
	*mpctxp = NULL;
	if (atomic_load_acquire(&mpctx->allocated) > 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mempool_destroy(): mempool %s "
				 "leaked memory",
				 mpctx->name);
	}
	REQUIRE(atomic_load_acquire(&mpctx->allocated) == 0);

	mctx = mpctx->mctx;

	lock = mpctx->lock;

	if (lock != NULL) {
		LOCK(lock);
	}

	/*
	 * Return any items on the free list
	 */
	while (mpctx->items != NULL) {
		INSIST(atomic_fetch_sub_release(&mpctx->freecount, 1) > 0);

		item = mpctx->items;
		mpctx->items = item->next;

		mem_putstats(mctx, item, mpctx->size);
		mem_put(mctx, item, mpctx->size);
	}

	/*
	 * Remove our linked list entry from the memory context.
	 */
	MCTXLOCK(mctx);
	ISC_LIST_UNLINK(mctx->pools, mpctx, link);
	mctx->poolcnt--;
	MCTXUNLOCK(mctx);

	mpctx->magic = 0;

	isc_mem_put(mpctx->mctx, mpctx, sizeof(isc_mempool_t));

	if (lock != NULL) {
		UNLOCK(lock);
	}
}

void
isc_mempool_associatelock(isc_mempool_t *mpctx, isc_mutex_t *lock) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(lock != NULL);

	REQUIRE(mpctx->lock == NULL);

	mpctx->lock = lock;
}

void *
isc__mempool_get(isc_mempool_t *mpctx FLARG) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	element *item;
	unsigned int i;
	size_t allocated = atomic_fetch_add_release(&mpctx->allocated, 1);
	size_t maxalloc = atomic_load_acquire(&mpctx->maxalloc);

	/*
	 * Don't let the caller go over quota
	 */
	if (ISC_UNLIKELY(allocated >= maxalloc)) {
		atomic_fetch_sub_release(&mpctx->allocated, 1);
		return (NULL);
	}

	MPCTXLOCK(mpctx);
	if (ISC_UNLIKELY(mpctx->items == NULL)) {
		isc_mem_t *mctx = mpctx->mctx;
		size_t fillcount = atomic_load_acquire(&mpctx->fillcount);
		/*
		 * We need to dip into the well.  Lock the memory
		 * context here and fill up our free list.
		 */
		for (i = 0; i < fillcount; i++) {
			item = mem_get(mctx, mpctx->size);
			mem_getstats(mctx, mpctx->size);
			item->next = mpctx->items;
			mpctx->items = item;
			atomic_fetch_add_relaxed(&mpctx->freecount, 1);
		}
	}

	/*
	 * If we didn't get any items, return NULL.
	 */
	item = mpctx->items;
	if (ISC_UNLIKELY(item == NULL)) {
		atomic_fetch_sub_release(&mpctx->allocated, 1);
		goto out;
	}

	mpctx->items = item->next;

	INSIST(atomic_fetch_sub_release(&mpctx->freecount, 1) > 0);
	atomic_fetch_add_relaxed(&mpctx->gets, 1);

	ADD_TRACE(mpctx->mctx, item, mpctx->size, file, line);

out:
	MPCTXUNLOCK(mpctx);

	return (item);
}

/* coverity[+free : arg-1] */
void
isc__mempool_put(isc_mempool_t *mpctx, void *mem FLARG) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mem != NULL);

	isc_mem_t *mctx = mpctx->mctx;
	element *item;
	size_t freecount = atomic_load_acquire(&mpctx->freecount);
	size_t freemax = atomic_load_acquire(&mpctx->freemax);

	INSIST(atomic_fetch_sub_release(&mpctx->allocated, 1) > 0);

	DELETE_TRACE(mctx, mem, mpctx->size, file, line);

	/*
	 * If our free list is full, return this to the mctx directly.
	 */
	if (freecount >= freemax) {
		mem_putstats(mctx, mem, mpctx->size);
		mem_put(mctx, mem, mpctx->size);
		return;
	}

	/*
	 * Otherwise, attach it to our free list and bump the counter.
	 */
	MPCTXLOCK(mpctx);

	item = (element *)mem;
	item->next = mpctx->items;
	mpctx->items = item;
	atomic_fetch_add_relaxed(&mpctx->freecount, 1);

	MPCTXUNLOCK(mpctx);
}

/*
 * Quotas
 */

void
isc_mempool_setfreemax(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	atomic_store_release(&mpctx->freemax, limit);
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (atomic_load_acquire(&mpctx->freemax));
}

unsigned int
isc_mempool_getfreecount(isc_mempool_t *mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (atomic_load_relaxed(&mpctx->freecount));
}

void
isc_mempool_setmaxalloc(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(limit > 0);

	atomic_store_release(&mpctx->maxalloc, limit);
}

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (atomic_load_relaxed(&mpctx->maxalloc));
}

unsigned int
isc_mempool_getallocated(isc_mempool_t *mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (atomic_load_relaxed(&mpctx->allocated));
}

void
isc_mempool_setfillcount(isc_mempool_t *mpctx, unsigned int limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(limit > 0);

	atomic_store_release(&mpctx->fillcount, limit);
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return (atomic_load_relaxed(&mpctx->fillcount));
}

/*
 * Requires contextslock to be held by caller.
 */
#if ISC_MEM_TRACKLINES
static void
print_contexts(FILE *file) {
	isc_mem_t *ctx;

	for (ctx = ISC_LIST_HEAD(contexts); ctx != NULL;
	     ctx = ISC_LIST_NEXT(ctx, link)) {
		fprintf(file, "context: %p (%s): %" PRIuFAST32 " references\n",
			ctx, ctx->name[0] == 0 ? "<unknown>" : ctx->name,
			isc_refcount_current(&ctx->references));
		print_active(ctx, file);
	}
	fflush(file);
}
#endif

static atomic_uintptr_t checkdestroyed = ATOMIC_VAR_INIT(0);

void
isc_mem_checkdestroyed(FILE *file) {
	atomic_store_release(&checkdestroyed, (uintptr_t)file);
}

void
isc__mem_checkdestroyed(void) {
	FILE *file = (FILE *)atomic_load_acquire(&checkdestroyed);

	if (file == NULL) {
		return;
	}

	LOCK(&contextslock);
	if (!ISC_LIST_EMPTY(contexts)) {
#if ISC_MEM_TRACKLINES
		if (ISC_UNLIKELY((isc_mem_debugging & TRACE_OR_RECORD) != 0)) {
			print_contexts(file);
		}
#endif /* if ISC_MEM_TRACKLINES */
		INSIST(0);
		ISC_UNREACHABLE();
	}
	UNLOCK(&contextslock);
}

unsigned int
isc_mem_references(isc_mem_t *ctx) {
	return (isc_refcount_current(&ctx->references));
}

typedef struct summarystat {
	uint64_t total;
	uint64_t inuse;
	uint64_t malloced;
	uint64_t contextsize;
} summarystat_t;

#ifdef HAVE_LIBXML2
#define TRY0(a)                     \
	do {                        \
		xmlrc = (a);        \
		if (xmlrc < 0)      \
			goto error; \
	} while (0)
static int
xml_renderctx(isc_mem_t *ctx, summarystat_t *summary, xmlTextWriterPtr writer) {
	REQUIRE(VALID_CONTEXT(ctx));

	int xmlrc;

	MCTXLOCK(ctx);

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "context"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "id"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%p", ctx));
	TRY0(xmlTextWriterEndElement(writer)); /* id */

	if (ctx->name[0] != 0) {
		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "name"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%s", ctx->name));
		TRY0(xmlTextWriterEndElement(writer)); /* name */
	}

	summary->contextsize += sizeof(*ctx);
#if ISC_MEM_TRACKLINES
	if (ctx->debuglist != NULL) {
		summary->contextsize += DEBUG_TABLE_COUNT *
						sizeof(debuglist_t) +
					ctx->debuglistcnt * sizeof(debuglink_t);
	}
#endif /* if ISC_MEM_TRACKLINES */
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "references"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIuFAST32,
		isc_refcount_current(&ctx->references)));
	TRY0(xmlTextWriterEndElement(writer)); /* references */

	summary->total += isc_mem_total(ctx);
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "total"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)isc_mem_total(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* total */

	summary->inuse += isc_mem_inuse(ctx);
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "inuse"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)isc_mem_inuse(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* inuse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "maxinuse"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)isc_mem_maxinuse(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* maxinuse */

	summary->malloced += isc_mem_malloced(ctx);
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "malloced"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)isc_mem_malloced(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* malloced */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "maxmalloced"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIu64 "", (uint64_t)isc_mem_maxmalloced(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* maxmalloced */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "pools"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%u", ctx->poolcnt));
	TRY0(xmlTextWriterEndElement(writer)); /* pools */
	summary->contextsize += ctx->poolcnt * sizeof(isc_mempool_t);

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "hiwater"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIu64 "",
		(uint64_t)atomic_load_relaxed(&ctx->hi_water)));
	TRY0(xmlTextWriterEndElement(writer)); /* hiwater */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "lowater"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIu64 "",
		(uint64_t)atomic_load_relaxed(&ctx->lo_water)));
	TRY0(xmlTextWriterEndElement(writer)); /* lowater */

	TRY0(xmlTextWriterEndElement(writer)); /* context */

error:
	MCTXUNLOCK(ctx);

	return (xmlrc);
}

int
isc_mem_renderxml(void *writer0) {
	isc_mem_t *ctx;
	summarystat_t summary;
	uint64_t lost;
	int xmlrc;
	xmlTextWriterPtr writer = (xmlTextWriterPtr)writer0;

	memset(&summary, 0, sizeof(summary));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "contexts"));

	LOCK(&contextslock);
	lost = totallost;
	for (ctx = ISC_LIST_HEAD(contexts); ctx != NULL;
	     ctx = ISC_LIST_NEXT(ctx, link)) {
		xmlrc = xml_renderctx(ctx, &summary, writer);
		if (xmlrc < 0) {
			UNLOCK(&contextslock);
			goto error;
		}
	}
	UNLOCK(&contextslock);

	TRY0(xmlTextWriterEndElement(writer)); /* contexts */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "summary"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "TotalUse"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    summary.total));
	TRY0(xmlTextWriterEndElement(writer)); /* TotalUse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "InUse"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    summary.inuse));
	TRY0(xmlTextWriterEndElement(writer)); /* InUse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "Malloced"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    summary.malloced));
	TRY0(xmlTextWriterEndElement(writer)); /* InUse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "ContextSize"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    summary.contextsize));
	TRY0(xmlTextWriterEndElement(writer)); /* ContextSize */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "Lost"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "", lost));
	TRY0(xmlTextWriterEndElement(writer)); /* Lost */

	TRY0(xmlTextWriterEndElement(writer)); /* summary */
error:
	return (xmlrc);
}

#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#define CHECKMEM(m) RUNTIME_CHECK(m != NULL)

static isc_result_t
json_renderctx(isc_mem_t *ctx, summarystat_t *summary, json_object *array) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(summary != NULL);
	REQUIRE(array != NULL);

	json_object *ctxobj, *obj;
	char buf[1024];

	MCTXLOCK(ctx);

	summary->contextsize += sizeof(*ctx);
	summary->total += isc_mem_total(ctx);
	summary->inuse += isc_mem_inuse(ctx);
	summary->malloced += isc_mem_malloced(ctx);
#if ISC_MEM_TRACKLINES
	if (ctx->debuglist != NULL) {
		summary->contextsize += DEBUG_TABLE_COUNT *
						sizeof(debuglist_t) +
					ctx->debuglistcnt * sizeof(debuglink_t);
	}
#endif /* if ISC_MEM_TRACKLINES */

	ctxobj = json_object_new_object();
	CHECKMEM(ctxobj);

	snprintf(buf, sizeof(buf), "%p", ctx);
	obj = json_object_new_string(buf);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "id", obj);

	if (ctx->name[0] != 0) {
		obj = json_object_new_string(ctx->name);
		CHECKMEM(obj);
		json_object_object_add(ctxobj, "name", obj);
	}

	obj = json_object_new_int64(isc_refcount_current(&ctx->references));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "references", obj);

	obj = json_object_new_int64(isc_mem_total(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "total", obj);

	obj = json_object_new_int64(isc_mem_inuse(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "inuse", obj);

	obj = json_object_new_int64(isc_mem_maxinuse(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "maxinuse", obj);

	obj = json_object_new_int64(isc_mem_malloced(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "malloced", obj);

	obj = json_object_new_int64(isc_mem_maxmalloced(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "maxmalloced", obj);

	obj = json_object_new_int64(ctx->poolcnt);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "pools", obj);

	summary->contextsize += ctx->poolcnt * sizeof(isc_mempool_t);

	obj = json_object_new_int64(atomic_load_relaxed(&ctx->hi_water));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "hiwater", obj);

	obj = json_object_new_int64(atomic_load_relaxed(&ctx->lo_water));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "lowater", obj);

	MCTXUNLOCK(ctx);
	json_object_array_add(array, ctxobj);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mem_renderjson(void *memobj0) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_mem_t *ctx;
	summarystat_t summary;
	uint64_t lost;
	json_object *ctxarray, *obj;
	json_object *memobj = (json_object *)memobj0;

	memset(&summary, 0, sizeof(summary));

	ctxarray = json_object_new_array();
	CHECKMEM(ctxarray);

	LOCK(&contextslock);
	lost = totallost;
	for (ctx = ISC_LIST_HEAD(contexts); ctx != NULL;
	     ctx = ISC_LIST_NEXT(ctx, link)) {
		result = json_renderctx(ctx, &summary, ctxarray);
		if (result != ISC_R_SUCCESS) {
			UNLOCK(&contextslock);
			goto error;
		}
	}
	UNLOCK(&contextslock);

	obj = json_object_new_int64(summary.total);
	CHECKMEM(obj);
	json_object_object_add(memobj, "TotalUse", obj);

	obj = json_object_new_int64(summary.inuse);
	CHECKMEM(obj);
	json_object_object_add(memobj, "InUse", obj);

	obj = json_object_new_int64(summary.malloced);
	CHECKMEM(obj);
	json_object_object_add(memobj, "Malloced", obj);

	obj = json_object_new_int64(summary.contextsize);
	CHECKMEM(obj);
	json_object_object_add(memobj, "ContextSize", obj);

	obj = json_object_new_int64(lost);
	CHECKMEM(obj);
	json_object_object_add(memobj, "Lost", obj);

	json_object_object_add(memobj, "contexts", ctxarray);
	return (ISC_R_SUCCESS);

error:
	if (ctxarray != NULL) {
		json_object_put(ctxarray);
	}
	return (result);
}
#endif /* HAVE_JSON_C */

void
isc_mem_create(isc_mem_t **mctxp) {
	mem_create(mctxp, isc_mem_defaultflags);
}

void
isc__mem_printactive(isc_mem_t *ctx, FILE *file) {
#if ISC_MEM_TRACKLINES
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(file != NULL);

	print_active(ctx, file);
#else  /* if ISC_MEM_TRACKLINES */
	UNUSED(ctx);
	UNUSED(file);
#endif /* if ISC_MEM_TRACKLINES */
}
