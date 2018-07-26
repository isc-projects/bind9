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
	UNUSED(mctx0);
	UNUSED(size);
	UNUSED(mpctxp);

	isc_mempool_t *mpctx = calloc(1, sizeof(*mpctx));
	REQUIRE(mpctx != NULL);
	*mpctxp = (isc_mempool_t *)mpctx;	

	mpctx->size = ALIGN_TO(size, sizeof(void *));
	REQUIRE((isc_refcount_init(&mpctx->allocated, 0)) == ISC_R_SUCCESS);
	
	return (ISC_R_SUCCESS);
}

void
isc_mempool_setname(isc_mempool_t *mpctx0, const char *name) {
	UNUSED(mpctx0);
	UNUSED(name);
}

void
isc_mempool_destroy(isc_mempool_t **mpctxp) {
	isc_mempool_t *mpctx = (isc_mempool_t *)*mpctxp;

	isc_refcount_destroy(&mpctx->allocated);
	isc_mem_free(NULL, mpctx);
	*mpctxp = NULL;
}

void
isc_mempool_associatelock(isc_mempool_t *mpctx0, isc_mutex_t *lock) {
	UNUSED(mpctx0);
	UNUSED(lock);
}

void *
isc_mempool_get(isc_mempool_t *mpctx0) {
	unsigned int refs;
	void *ret = isc_mem_allocate(NULL, mpctx0->size);
	REQUIRE(ret != NULL);
	isc_refcount_increment0(&mpctx0->allocated, &refs);
	return (ret);
}

/* coverity[+free : arg-1] */
void
isc_mempool_put(isc_mempool_t *mpctx0, void *mem) {
	unsigned int refs;
	isc_mem_free(NULL, mem);
	isc_refcount_decrement(&mpctx0->allocated, &refs);
	REQUIRE(refs >= 0);
}

/*
 * Quotas
 */

void
isc_mempool_setfreemax(isc_mempool_t *mpctx0, unsigned int limit) {
	UNUSED(mpctx0);
	UNUSED(limit);
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx0) {
	UNUSED(mpctx0);
	return (0);
}

unsigned int
isc_mempool_getfreecount(isc_mempool_t *mpctx0) {
	UNUSED(mpctx0);
	return (1);
}

void
isc_mempool_setmaxalloc(isc_mempool_t *mpctx0, unsigned int limit) {
	UNUSED(mpctx0);
	UNUSED(limit);
}

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx0) {
	UNUSED(mpctx0);

	return (0);
}

unsigned int
isc_mempool_getallocated(isc_mempool_t *mpctx0) {
	return (isc_refcount_current(&mpctx0->allocated));
}

void
isc_mempool_setfillcount(isc_mempool_t *mpctx0, unsigned int limit) {
	UNUSED(mpctx0);
	UNUSED(limit);
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx0) {
	UNUSED(mpctx0);

	return (0);
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
