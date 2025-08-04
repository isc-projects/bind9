/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file isc/mem.h */

#include <stdbool.h>
#include <stdio.h>

#include <isc/attributes.h>
#include <isc/mutex.h>
#include <isc/overflow.h>
#include <isc/refcount.h>
#include <isc/types.h>
#include <isc/urcu.h>

/* Add -DISC_MEM_TRACE=1 to CFLAGS for detailed reference tracing */

/*%
 * Define ISC_MEM_TRACKLINES=1 to turn on detailed tracing of memory
 * allocation and freeing by file and line number.
 */
#ifndef ISC_MEM_TRACKLINES
#define ISC_MEM_TRACKLINES 0
#endif /* ifndef ISC_MEM_TRACKLINES */

extern unsigned int isc_mem_defaultflags;

/*@{*/
#define ISC_MEM_DEBUGTRACE  0x00000001U
#define ISC_MEM_DEBUGRECORD 0x00000002U
#define ISC_MEM_DEBUGUSAGE  0x00000004U
#define ISC_MEM_DEBUGALL \
	(ISC_MEM_DEBUGTRACE | ISC_MEM_DEBUGRECORD | ISC_MEM_DEBUGUSAGE)
/*!<
 * The following memory debugging options can be specified:
 *
 * \li #ISC_MEM_DEBUGTRACE
 *	Log each allocation and free.
 *
 * \li #ISC_MEM_DEBUGRECORD
 *	Remember each allocation, and match them up on free.
 *	Crash if a free doesn't match an allocation.
 *
 * \li #ISC_MEM_DEBUGUSAGE
 *	Every time the memory usage is greater (lower) than hi_water
 *	(lo_water) mark, print the current inuse memory.
 *
 * These flags are set in the static variable mem_debugging.
 * When a new memory context is created, its debugging flags
 * are set to the current value of mem_debugging.
 *
 * By default, no flags are set. This can be overridden by changing
 * ISC_MEM_DEBUGGING in mem.c. The flags can be activated at runtime by
 * setting environment variables (for example, "ISC_MEM_DEBUGRECORD=1")
 * or by calling isc_mem_debugon() (see below).
 */
/*@}*/

#if ISC_MEM_TRACKLINES
#define _ISC_MEM_FILELINE , __func__, __FILE__, __LINE__
#define _ISC_MEM_FLARG	  , const char *, const char *, unsigned int
#else /* if ISC_MEM_TRACKLINES */
#define _ISC_MEM_FILELINE
#define _ISC_MEM_FLARG
#endif /* if ISC_MEM_TRACKLINES */

/*
 * Flags for isc_mem_create() calls.
 */
#define ISC_MEMFLAG_RESERVED1 0x00000001 /* reserved, obsoleted, don't use */
#define ISC_MEMFLAG_RESERVED2 0x00000002 /* reserved, obsoleted, don't use */
#define ISC_MEMFLAG_FILL \
	0x00000004 /* fill with pattern after alloc and frees */

/*%
 * Define ISC_MEM_DEFAULTFILL=1 to turn filling the memory with pattern
 * after alloc and free.
 */
#if ISC_MEM_DEFAULTFILL
#define ISC_MEMFLAG_DEFAULT ISC_MEMFLAG_FILL
#else /* if !ISC_MEM_USE_INTERNAL_MALLOC */
#define ISC_MEMFLAG_DEFAULT 0
#endif /* if !ISC_MEM_USE_INTERNAL_MALLOC */

/*%
 * A global 'default' memory context that can be used when we don't need more
 * specific memory context.  It is always available.
 */
extern isc_mem_t *isc_g_mctx;

/*%
 * isc_mem_putanddetach() is a convenience function for use where you
 * have a structure with an attached memory context.
 *
 * Given:
 *
 * \code
 * struct {
 *	...
 *	isc_mem_t *mctx;
 *	...
 * } *ptr;
 *
 * isc_mem_t *mctx;
 *
 * isc_mem_putanddetach(&ptr->mctx, ptr, sizeof(*ptr));
 * \endcode
 *
 * is the equivalent of:
 *
 * \code
 * mctx = NULL;
 * isc_mem_attach(ptr->mctx, &mctx);
 * isc_mem_detach(&ptr->mctx);
 * isc_mem_put(mctx, ptr, sizeof(*ptr));
 * isc_mem_detach(&mctx);
 * \endcode
 */

/*%
 * These functions are actually implemented in isc__mem_<function>
 * (two underscores). The single-underscore macros are used to pass
 * __FILE__ and __LINE__, and in the case of the put functions, to
 * set the pointer being freed to NULL in the calling function.
 */

/*%
 * The definitions of the macros have been pulled directly from jemalloc.h
 * and checked for consistency in mem.c.
 *
 *\li	ISC__MEM_ZERO - fill the memory with zeroes before returning
 */

#define ISC__MEM_ZERO ((int)0x40)

#define isc_mem_get(c, s) isc__mem_get((c), (s), 0 _ISC_MEM_FILELINE)
#define isc_mem_cget(c, n, s)                        \
	isc__mem_get((c), ISC_CHECKED_MUL((n), (s)), \
		     ISC__MEM_ZERO _ISC_MEM_FILELINE)
#define isc_mem_reget(c, p, o, n) \
	isc__mem_reget((c), (p), (o), (n), 0 _ISC_MEM_FILELINE)
#define isc_mem_creget(c, p, o, n, s)                       \
	isc__mem_reget((c), (p), ISC_CHECKED_MUL((o), (s)), \
		       ISC_CHECKED_MUL((n), (s)),           \
		       ISC__MEM_ZERO _ISC_MEM_FILELINE)
#define isc_mem_allocate(c, s) isc__mem_allocate((c), (s), 0 _ISC_MEM_FILELINE)
#define isc_mem_callocate(c, n, s)                        \
	isc__mem_allocate((c), ISC_CHECKED_MUL((n), (s)), \
			  ISC__MEM_ZERO _ISC_MEM_FILELINE)
#define isc_mem_reallocate(c, p, s) \
	isc__mem_reallocate((c), (p), (s), 0 _ISC_MEM_FILELINE)
#define isc_mem_strdup(c, p) isc__mem_strdup((c), (p)_ISC_MEM_FILELINE)
#define isc_mem_strndup(c, p, l) \
	isc__mem_strndup((c), (p), (l)_ISC_MEM_FILELINE)
#define isc_mempool_get(c) isc__mempool_get((c)_ISC_MEM_FILELINE)

#define isc_mem_put(c, p, s)                                      \
	do {                                                      \
		isc__mem_put((c), (p), (s), 0 _ISC_MEM_FILELINE); \
		(p) = NULL;                                       \
	} while (0)
#define isc_mem_cput(c, p, n, s)                                  \
	do {                                                      \
		isc__mem_put((c), (p), ISC_CHECKED_MUL((n), (s)), \
			     ISC__MEM_ZERO _ISC_MEM_FILELINE);    \
		(p) = NULL;                                       \
	} while (0)
#define isc_mem_putanddetach(c, p, s)                                      \
	do {                                                               \
		isc__mem_putanddetach((c), (p), (s), 0 _ISC_MEM_FILELINE); \
		(p) = NULL;                                                \
	} while (0)
#define isc_mem_free(c, p)                                    \
	do {                                                  \
		isc__mem_free((c), (p), 0 _ISC_MEM_FILELINE); \
		(p) = NULL;                                   \
	} while (0)
#define isc_mempool_put(c, p)                                \
	do {                                                 \
		isc__mempool_put((c), (p)_ISC_MEM_FILELINE); \
		(p) = NULL;                                  \
	} while (0)

/*@{*/
/*
 * This is a little hack to help with dynamic link order,
 * see https://github.com/jemalloc/jemalloc/issues/2566
 * for more information.
 */
#if HAVE_JEMALLOC

/*
 * cmocka.h has confliction definitions with the jemalloc header but we only
 * need the mallocx symbol from jemalloc.
 */
void *
mallocx(size_t size, int flags);

extern volatile void *isc__mem_malloc;

#define isc_mem_create(name, cp)                                      \
	{                                                             \
		isc__mem_create((name), (cp)_ISC_MEM_FILELINE);       \
		isc__mem_malloc = mallocx;                            \
		ISC_INSIST(CMM_ACCESS_ONCE(isc__mem_malloc) != NULL); \
	}
#else
#define isc_mem_create(name, cp) isc__mem_create((name), (cp)_ISC_MEM_FILELINE)
#endif
void
isc__mem_create(const char *name, isc_mem_t **_ISC_MEM_FLARG);
/*!<
 * \brief Create a memory context.
 *
 * Requires:
 * mctxp != NULL && *mctxp == NULL */
/*@}*/

unsigned int
isc_mem_debugon(unsigned int debugging);
unsigned int
isc_mem_debugoff(unsigned int debugging);
/*!<
 * Set or clear debugging the flags for the main memory context
 * (isc_g_mctx), and the default debugging flags for all memory
 * contexts yet to be created (mem_debugging).
 *
 * Note: These are bitwise operations. To clear the existing flags
 * before setting new ones, use isc_mem_debugoff(ISC_MEM_DEBUGALL).
 *
 * Returns:
 * \li	the previous value of the debugging flags
 */

void
isc_mem_setdebugging(isc_mem_t *ctx, unsigned int debugging);
/*!<
 * Set the debugging flags for a single memory context.
 *
 * Note: This is an assignemnt, not a bitwise operation.
 *
 * Requires:
 * \li	'ctx' valid memory context without active allocation.
 */

#if ISC_MEM_TRACE
#define isc_mem_ref(ptr)   isc_mem__ref(ptr, __func__, __FILE__, __LINE__)
#define isc_mem_unref(ptr) isc_mem__unref(ptr, __func__, __FILE__, __LINE__)
#define isc_mem_attach(ptr, ptrp) \
	isc_mem__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define isc_mem_detach(ptrp) isc_mem__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(isc_mem);
#else
ISC_REFCOUNT_DECL(isc_mem);
#endif

void
isc_mem_stats(isc_mem_t *mctx, FILE *out);
/*%<
 * Print memory usage statistics for 'mctx' on the stream 'out'.
 */

void
isc_mem_setdestroycheck(isc_mem_t *mctx, bool on);
/*%<
 * If 'on' is true, 'mctx' will check for memory leaks when
 * destroyed and abort the program if any are present.
 */

size_t
isc_mem_inuse(isc_mem_t *mctx);
/*%<
 * Get an estimate of the amount of memory in use in 'mctx', in bytes.
 * This includes quantization overhead, but does not include memory
 * allocated from the system but not yet used.
 */

bool
isc_mem_isovermem(isc_mem_t *mctx);
/*%<
 * Return true iff the memory context is in "over memory" state, i.e.,
 * a hiwater mark has been set and the used amount of memory has exceeds
 * the mark.
 */

void
isc_mem_clearwater(isc_mem_t *mctx);
void
isc_mem_setwater(isc_mem_t *mctx, size_t hiwater, size_t lowater);
/*%<
 * Set high and low water marks for this memory context.
 *
 * When the memory usage of 'mctx' exceeds 'hiwater', the overmem condition
 * will be met and isc_mem_isovermem() will return true.
 *
 * If the 'hiwater' and 'lowater' is set to 0, the high- and low-water
 * processing are disabled for this memory context.
 *
 * There's a convenient function isc_mem_clearwater().
 *
 * Requires:
 *\li	'hiwater' >= 'lowater'
 */

void
isc_mem_checkdestroyed(FILE *file);
/*%<
 * Check that all memory contexts have been destroyed.
 * Prints out those that have not been.
 * Fatally fails if there are still active contexts.
 */

unsigned int
isc_mem_references(isc_mem_t *ctx);
/*%<
 * Return the current reference count.
 */

const char *
isc_mem_getname(isc_mem_t *ctx);
/*%<
 * Get the name of 'ctx', as previously set using isc_mem_setname().
 *
 * Requires:
 *\li	'ctx' is a valid ctx.
 *
 * Returns:
 *\li	A non-NULL pointer to a null-terminated string.
 * 	If the ctx has not been named, the string is
 * 	empty.
 */

#ifdef HAVE_LIBXML2
int
isc_mem_renderxml(void *writer0);
/*%<
 * Render all contexts' statistics and status in XML for writer.
 */
#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
isc_result_t
isc_mem_renderjson(void *memobj0);
/*%<
 * Render all contexts' statistics and status in JSON.
 */
#endif /* HAVE_JSON_C */

/*
 * Memory pools
 */

#define isc_mempool_create(c, s, n, mp) \
	isc__mempool_create((c), (s), (n), (mp)_ISC_MEM_FILELINE)
void
isc__mempool_create(isc_mem_t *restrict mctx, const size_t element_size,
		    const char *name, isc_mempool_t **mpctxp _ISC_MEM_FLARG);
/*%<
 * Create a memory pool.
 *
 * Requires:
 *\li	mctx is a valid memory context.
 *\li	size > 0
 *\li	mpctxp != NULL and *mpctxp == NULL
 *
 * Defaults:
 *\li	freemax = 1
 *\li	fillcount = 1
 */

#define isc_mempool_destroy(mp) isc__mempool_destroy((mp)_ISC_MEM_FILELINE)
void
isc__mempool_destroy(isc_mempool_t **restrict mpctxp _ISC_MEM_FLARG);
/*%<
 * Destroy a memory pool.
 *
 * Requires:
 *\li	mpctxp != NULL && *mpctxp is a valid pool.
 *\li	The pool has no un"put" allocations outstanding
 */

/*
 * The following functions get/set various parameters.  Note that due to
 * the unlocked nature of pools these are potentially random values
 *unless the imposed externally provided locking protocols are followed.
 *
 * Also note that the quota limits will not always take immediate
 * effect.
 *
 * All functions require (in addition to other requirements):
 *	mpctx is a valid memory pool
 */

unsigned int
isc_mempool_getfreemax(isc_mempool_t *restrict mpctx);
/*%<
 * Returns the maximum allowed size of the free list.
 */

void
isc_mempool_setfreemax(isc_mempool_t *restrict mpctx, const unsigned int limit);
/*%<
 * Sets the maximum allowed size of the free list.
 */

unsigned int
isc_mempool_getfreecount(isc_mempool_t *restrict mpctx);
/*%<
 * Returns current size of the free list.
 */

unsigned int
isc_mempool_getallocated(isc_mempool_t *restrict mpctx);
/*%<
 * Returns the number of items allocated from this pool.
 */

unsigned int
isc_mempool_getfillcount(isc_mempool_t *restrict mpctx);
/*%<
 * Returns the number of items allocated as a block from the parent
 * memory context when the free list is empty.
 */

void
isc_mempool_setfillcount(isc_mempool_t *restrict mpctx,
			 const unsigned int limit);
/*%<
 * Sets the fillcount.
 *
 * Additional requirements:
 *\li	limit > 0
 */

#if defined(UNIT_TESTING) && defined(malloc)
/*
 * cmocka.h redefined malloc as a macro, we #undef it
 * to avoid replacing ISC_ATTR_MALLOC with garbage.
 */
#pragma push_macro("malloc")
#undef malloc
#define POP_MALLOC_MACRO 1
#endif

/*
 * Pseudo-private functions for use via macros.  Do not call directly.
 */
void
isc__mem_putanddetach(isc_mem_t **, void *, size_t, int _ISC_MEM_FLARG);
void
isc__mem_put(isc_mem_t *, void *, size_t, int _ISC_MEM_FLARG);
void
isc__mem_free(isc_mem_t *, void *, int _ISC_MEM_FLARG);

ISC_ATTR_MALLOC_DEALLOCATOR_IDX(isc__mem_put, 2)
void *
isc__mem_get(isc_mem_t *, size_t, int _ISC_MEM_FLARG);

ISC_ATTR_DEALLOCATOR_IDX(isc__mem_put, 2)
void *
isc__mem_reget(isc_mem_t *, void *, size_t, size_t, int _ISC_MEM_FLARG);

ISC_ATTR_MALLOC_DEALLOCATOR_IDX(isc__mem_free, 2)
void *
isc__mem_allocate(isc_mem_t *, size_t, int _ISC_MEM_FLARG);

ISC_ATTR_DEALLOCATOR_IDX(isc__mem_free, 2)
void *
isc__mem_reallocate(isc_mem_t *, void *, size_t, int _ISC_MEM_FLARG);

ISC_ATTR_RETURNS_NONNULL
ISC_ATTR_MALLOC_DEALLOCATOR_IDX(isc__mem_free, 2)
char *
isc__mem_strdup(isc_mem_t *, const char *_ISC_MEM_FLARG);

ISC_ATTR_RETURNS_NONNULL
ISC_ATTR_MALLOC_DEALLOCATOR_IDX(isc__mem_free, 2)
char *
isc__mem_strndup(isc_mem_t *, const char *, size_t _ISC_MEM_FLARG);

ISC_ATTR_MALLOC_DEALLOCATOR_IDX(isc__mempool_put, 2)
void *
isc__mempool_get(isc_mempool_t *_ISC_MEM_FLARG);

void
isc__mempool_put(isc_mempool_t *, void *_ISC_MEM_FLARG);

#ifdef POP_MALLOC_MACRO
/*
 * Restore cmocka.h macro for malloc.
 */
#pragma pop_macro("malloc")
#endif
