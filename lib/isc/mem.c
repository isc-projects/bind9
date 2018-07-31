/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <limits.h>

#include <isc/bind9.h>
#include <isc/json.h>
#include <isc/magic.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/msgs.h>
#include <isc/once.h>
#include <isc/refcount.h>
#include <isc/string.h>
#include <isc/mutex.h>
#include <isc/print.h>
#include <isc/util.h>
#include <isc/xml.h>

#ifndef ISC_MEM_DEBUGGING
#define ISC_MEM_DEBUGGING 0
#endif
LIBISC_EXTERNAL_DATA unsigned int isc_mem_debugging = ISC_MEM_DEBUGGING;
LIBISC_EXTERNAL_DATA unsigned int isc_mem_defaultflags = ISC_MEMFLAG_DEFAULT;

typedef struct isc__mempool isc__mempool_t;

typedef struct element element;
struct element {
	element *		next;
};

#define MEMPOOL_MAGIC		ISC_MAGIC('M', 'E', 'M', 'p')
#define VALID_MEMPOOL(c)	ISC_MAGIC_VALID(c, MEMPOOL_MAGIC)

struct isc__mempool {
	/* always unlocked */
	isc_mempool_t	common;		/*%< common header of mempool's */
	isc_mutex_t    *lock;		/*%< optional lock */
	isc_mem_t      *mctx;		/*%< our memory context */
	/*%< locked via the memory context's lock */
	ISC_LINK(isc__mempool_t)	link;	/*%< next pool in this mem context */
	/*%< optionally locked from here down */
	element	       *items;		/*%< low water item list */
	size_t		size;		/*%< size of each item on this pool */
	unsigned int	maxalloc;	/*%< max number of items allowed */
	unsigned int	allocated;	/*%< # of items currently given out */
	unsigned int	freecount;	/*%< # of items on reserved list */
	unsigned int	freemax;	/*%< # of items allowed on free list */
	unsigned int	fillcount;	/*%< # of items to fetch on each fill */
	/*%< Stats only. */
	unsigned int	gets;		/*%< # of requests to this pool */
	/*%< Debugging only. */
#if ISC_MEMPOOL_NAMES
	char		name[16];	/*%< printed name in stats reports */
#endif
};

/*
 * Public.
 */

isc_result_t
isc_mem_createx(size_t init_max_size, size_t target_size,
		 isc_memalloc_t memalloc, isc_memfree_t memfree, void *arg,
		 isc_mem_t **ctxp)
{
	UNUSED(init_max_size);
	UNUSED(target_size);
	UNUSED(memalloc);
	UNUSED(memfree);
	UNUSED(arg);
	UNUSED(ctxp);
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mem_createx2(size_t init_max_size, size_t target_size,
		  isc_memalloc_t memalloc, isc_memfree_t memfree, void *arg,
		  isc_mem_t **ctxp, unsigned int flags)
{
	UNUSED(init_max_size);
	UNUSED(target_size);
	UNUSED(memalloc);
	UNUSED(memfree);
	UNUSED(arg);
	UNUSED(ctxp);
	UNUSED(flags);
	return (ISC_R_SUCCESS);
}

void
isc_mem_attach(isc_mem_t *source0, isc_mem_t **targetp) {
	UNUSED(source0);
	UNUSED(targetp);
}

void
isc_mem_detach(isc_mem_t **ctxp) {
	UNUSED(ctxp);
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
isc_mem_putanddetach(isc_mem_t **ctxp, void *ptr, size_t size) {
	isc_mem_put(*ctxp, ptr, size);
}

void
isc_mem_destroy(isc_mem_t **ctxp) {
	UNUSED(ctxp);

	return;
}

void *
isc_mem_get(isc_mem_t *ctx0, size_t size) {
	return isc_mem_allocate(ctx0, size);
}

void
isc_mem_put(isc_mem_t *ctx0, void *ptr, size_t size) {
	UNUSED(ctx0);
	UNUSED(size);
	
	free(ptr);
}

void
isc_mem_waterack(isc_mem_t *ctx0, int flag) {
	UNUSED(ctx0);
	UNUSED(flag);
}

/*
 * Print the stats[] on the stream "out" with suitable formatting.
 */
void
isc_mem_stats(isc_mem_t *ctx0, FILE *out) {
	UNUSED(ctx0);
	UNUSED(out);
}

void *
isc_mem_allocate(isc_mem_t *ctx0, size_t size) {
	UNUSED(ctx0);
	
	void *ret = malloc(size);
	REQUIRE(ret != NULL);

	return (ret);
}

void *
isc_mem_reallocate(isc_mem_t *ctx0, void *ptr, size_t size) {
	UNUSED(ctx0);

	void *ret = realloc(ptr, size);
	REQUIRE(ret != NULL);

	return (ret);
}

void
isc_mem_free(isc_mem_t *ctx0, void *ptr) {
	UNUSED(ctx0);

	free(ptr);
}

/*
 * Other useful things.
 */

char *
isc_mem_strdup(isc_mem_t *mctx0, const char *s) {
	UNUSED(mctx0);

	size_t len = strlen(s);
	char *ret = isc_mem_allocate(mctx0, len + 1);
	memcpy(ret, s, len + 1);
	return (ret);
}

void
isc_mem_setdestroycheck(isc_mem_t *ctx0, isc_boolean_t flag) {
	UNUSED(ctx0);
	UNUSED(flag);
}

/*
 * Quotas
 */

void
isc_mem_setquota(isc_mem_t *ctx0, size_t quota) {
	UNUSED(ctx0);
	UNUSED(quota);
}

size_t
isc_mem_getquota(isc_mem_t *ctx0) {
	UNUSED(ctx0);

	return (0);
}

size_t
isc_mem_inuse(isc_mem_t *ctx0) {
	UNUSED(ctx0);

	return (0);
}

size_t
isc_mem_maxinuse(isc_mem_t *ctx0) {
	UNUSED(ctx0);

	return (0);
}

size_t
isc_mem_total(isc_mem_t *ctx0) {
	UNUSED(ctx0);

	return (0);
}

void
isc_mem_setwater(isc_mem_t *ctx0, isc_mem_water_t water, void *water_arg,
		  size_t hiwater, size_t lowater)
{
	UNUSED(ctx0);
	UNUSED(water);
	UNUSED(water_arg);
	UNUSED(hiwater);
	UNUSED(lowater);
}

isc_boolean_t
isc_mem_isovermem(isc_mem_t *ctx0) {
	UNUSED(ctx0);

	return (ISC_FALSE);
}

void
isc_mem_setname(isc_mem_t *ctx0, const char *name, void *tag) {
	UNUSED(ctx0);
	UNUSED(name);
	UNUSED(tag);
}

const char *
isc_mem_getname(isc_mem_t *ctx0) {
	UNUSED(ctx0);
	return ("");
}

void *
isc_mem_gettag(isc_mem_t *ctx0) {
	UNUSED(ctx0);

	return (NULL);
}

/*
 * Memory pool stuff
 */

#define ALIGN_TO(s, a) (((s)+a-1)&~(a-1))

isc_result_t
isc_mempool_create(isc_mem_t *mctx0, size_t size, isc_mempool_t **mpctxp) {
	isc__mempool_t *mpctx;

	UNUSED(mctx0);
	
	REQUIRE(size > 0U);
	REQUIRE(mpctxp != NULL && *mpctxp == NULL);

	/*
	 * Allocate space for this pool, initialize values, and if all works
	 * well, attach to the memory context.
	 */
	mpctx = isc_mem_get(NULL, sizeof(isc__mempool_t));
	if (mpctx == NULL)
		return (ISC_R_NOMEMORY);

	mpctx->common.impmagic = MEMPOOL_MAGIC;
	mpctx->common.magic = ISCAPI_MPOOL_MAGIC;
	mpctx->lock = NULL;
	mpctx->mctx = NULL;
	mpctx->size = ALIGN_TO(size, sizeof(void *));
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

	*mpctxp = (isc_mempool_t *)mpctx;

	return (ISC_R_SUCCESS);
}

void
isc_mempool_setname(isc_mempool_t *mpctx0, const char *name) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;

	REQUIRE(name != NULL);
	REQUIRE(VALID_MEMPOOL(mpctx));

#if ISC_MEMPOOL_NAMES
	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	strlcpy(mpctx->name, name, sizeof(mpctx->name));

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
#else
	UNUSED(mpctx);
	UNUSED(name);
#endif
}

void
isc_mempool_destroy(isc_mempool_t **mpctxp) {
	isc__mempool_t *mpctx;
	isc_mutex_t *lock;
	element *item;

	REQUIRE(mpctxp != NULL);
	mpctx = (isc__mempool_t *)*mpctxp;
	REQUIRE(VALID_MEMPOOL(mpctx));
#if ISC_MEMPOOL_NAMES
	if (mpctx->allocated > 0)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc__mempool_destroy(): mempool %s "
				 "leaked memory",
				 mpctx->name);
#endif
	REQUIRE(mpctx->allocated == 0);

	lock = mpctx->lock;

	if (lock != NULL)
		LOCK(lock);

	/*
	 * Return any items on the free list
	 */
	while (mpctx->items != NULL) {
		INSIST(mpctx->freecount > 0);
		mpctx->freecount--;
		item = mpctx->items;
		mpctx->items = item->next;

		isc_mem_put(NULL, item, mpctx->size);
	}

	mpctx->common.impmagic = 0;
	mpctx->common.magic = 0;

	isc_mem_put(NULL, mpctx, sizeof(isc__mempool_t));

	if (lock != NULL)
		UNLOCK(lock);

	*mpctxp = NULL;
}

void
isc_mempool_associatelock(isc_mempool_t *mpctx0, isc_mutex_t *lock) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;

	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mpctx->lock == NULL);
	REQUIRE(lock != NULL);

	mpctx->lock = lock;
}

void *
isc_mempool_get(isc_mempool_t *mpctx0) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;
	element *item;
	unsigned int i;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	/*
	 * Don't let the caller go over quota
	 */
	if (ISC_UNLIKELY(mpctx->allocated >= mpctx->maxalloc)) {
		item = NULL;
		goto out;
	}

	if (ISC_UNLIKELY(mpctx->items == NULL)) {
		/*
		 * We need to dip into the well.  Lock the memory context
		 * here and fill up our free list.
		 */
		for (i = 0; i < mpctx->fillcount; i++) {
			item = isc_mem_get(NULL, mpctx->size);
			item->next = mpctx->items;
			mpctx->items = item;
			mpctx->freecount++;
		}
	}

	/*
	 * If we didn't get any items, return NULL.
	 */
	item = mpctx->items;
	if (ISC_UNLIKELY(item == NULL))
		goto out;

	mpctx->items = item->next;
	INSIST(mpctx->freecount > 0);
	mpctx->freecount--;
	mpctx->gets++;
	mpctx->allocated++;

 out:
	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (item);
}

/* coverity[+free : arg-1] */
void
isc_mempool_put(isc_mempool_t *mpctx0, void *mem) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;
	element *item;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (ISC_UNLIKELY(mem == NULL)) {
		return;
	}
	
	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	INSIST(mpctx->allocated > 0);
	mpctx->allocated--;

	/*
	 * If our free list is full, return this to the mctx directly.
	 */
	if (mpctx->freecount >= mpctx->freemax) {
		isc_mem_put(NULL, mem, mpctx->size);
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
isc_mempool_setfreemax(isc_mempool_t *mpctx0, unsigned int limit) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->freemax = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx0) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;
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
isc_mempool_getfreecount(isc_mempool_t *mpctx0) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;
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
isc_mempool_setmaxalloc(isc_mempool_t *mpctx0, unsigned int limit) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;

	REQUIRE(limit > 0);

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->maxalloc = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx0) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;
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
isc_mempool_getallocated(isc_mempool_t *mpctx0) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;
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
isc_mempool_setfillcount(isc_mempool_t *mpctx0, unsigned int limit) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;

	REQUIRE(limit > 0);
	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	mpctx->fillcount = limit;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx0) {
	isc__mempool_t *mpctx = (isc__mempool_t *)mpctx0;

	unsigned int fillcount;

	REQUIRE(VALID_MEMPOOL(mpctx));

	if (mpctx->lock != NULL)
		LOCK(mpctx->lock);

	fillcount = mpctx->fillcount;

	if (mpctx->lock != NULL)
		UNLOCK(mpctx->lock);

	return (fillcount);
}

void
isc_mem_printactive(isc_mem_t *ctx0, FILE *file) {
	UNUSED(ctx0);
	UNUSED(file);
}

void
isc_mem_printallactive(FILE *file) {
	UNUSED(file);
}

void
isc_mem_checkdestroyed(FILE *file) {
	UNUSED(file);
}

unsigned int
isc_mem_references(isc_mem_t *ctx0) {
	UNUSED(ctx0);
	return (1);
}


isc_result_t
isc_mem_register(isc_memcreatefunc_t createfunc) {
	UNUSED(createfunc);
	return (ISC_R_SUCCESS);
}


isc_result_t
isc_mem_create2(size_t init_max_size, size_t target_size, isc_mem_t **mctxp,
		 unsigned int flags)
{
	UNUSED(init_max_size);
	UNUSED(target_size);
	UNUSED(mctxp);
	UNUSED(flags);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mem_create(size_t init_max_size, size_t target_size, isc_mem_t **mctxp) {
	UNUSED(init_max_size);
	UNUSED(target_size);
	UNUSED(mctxp);

	return (ISC_R_SUCCESS);
}

#ifdef HAVE_LIBXML2
int
isc_mem_renderxml(xmlTextWriterPtr writer) {
	UNUSED(writer);
	return (0);
}
#endif /* HAVE_LIBXML2 */
	
#ifdef HAVE_JSON
isc_result_t
isc_mem_renderjson(json_object *memobj) {
	UNUSED(memobj);
	return (ISC_R_SUCCESS);
}
#endif /* HAVE_JSON */
