/*
 * Copyright (C) 1997, 1998, 1999, 2000  Internet Software Consortium.
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

#ifndef ISC_MEM_H
#define ISC_MEM_H 1

#include <stdio.h>

#include <isc/lang.h>
#include <isc/mutex.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

typedef void * (*isc_memalloc_t)(void *, size_t);
typedef void (*isc_memfree_t)(void *, void *);

#define ISC_MEM_DEBUG
extern isc_boolean_t isc_mem_debugging;

#ifdef ISC_MEM_DEBUG
#define isc_mem_get(c, s)	isc__mem_getdebug(c, s, __FILE__, __LINE__)
#define isc_mem_put(c, p, s)	isc__mem_putdebug(c, p, s, __FILE__, __LINE__)
#define isc_mem_allocate(c, s)	isc__mem_allocatedebug(c, s, \
							    __FILE__, __LINE__)
#define isc_mem_free(c, p)	isc__mem_freedebug(c, p, __FILE__, __LINE__)
#define isc_mem_strdup(c, p)	isc__mem_strdupdebug(c, p, \
						      __FILE__, __LINE__)
#define isc_mempool_get(c)	isc__mempool_getdebug(c, __FILE__, __LINE__)
#define isc_mempool_put(c, p)	isc__mempool_putdebug(c, p, \
						       __FILE__, __LINE__)
#else
#define isc_mem_get		isc__mem_get
#define isc_mem_put		isc__mem_put
#define isc_mem_allocate	isc__mem_allocate
#define isc_mem_free		isc__mem_free
#define isc_mem_strdup		isc__mem_strdup
#define isc_mempool_get		isc__mempool_get
#define isc_mempool_put		isc__mempool_put
#endif /* ISC_MEM_DEBUG */

isc_result_t			isc_mem_create(size_t, size_t, isc_mem_t **);
void				isc_mem_attach(isc_mem_t *, isc_mem_t **);
void				isc_mem_detach(isc_mem_t **);
void				isc_mem_destroy(isc_mem_t **);
isc_result_t			isc_mem_ondestroy(isc_mem_t *ctx,
						  isc_task_t *task,
						  isc_event_t **event);
void *				isc__mem_get(isc_mem_t *, size_t);
void 				isc__mem_put(isc_mem_t *, void *, size_t);
void *				isc__mem_getdebug(isc_mem_t *, size_t,
						  const char *, int);
void 				isc__mem_putdebug(isc_mem_t *, void *,
						  size_t, const char *, int);
isc_result_t			isc_mem_preallocate(isc_mem_t *);
void 				isc_mem_stats(isc_mem_t *, FILE *);
isc_boolean_t			isc_mem_valid(isc_mem_t *, void *);
void *				isc__mem_allocate(isc_mem_t *, size_t);
void *				isc__mem_allocatedebug(isc_mem_t *, size_t,
						       const char *, int);
void				isc__mem_free(isc_mem_t *, void *);
void				isc__mem_freedebug(isc_mem_t *, void *,
						   const char *, int);
char *				isc__mem_strdup(isc_mem_t *, const char *);
char *				isc__mem_strdupdebug(isc_mem_t *,
						     const char *,
						     const char *, int);
void				isc_mem_setdestroycheck(isc_mem_t *,
							isc_boolean_t);
void				isc_mem_setsplit(isc_mem_t *, isc_boolean_t);
void				isc_mem_setquota(isc_mem_t *, size_t);
size_t				isc_mem_getquota(isc_mem_t *);
size_t				isc_mem_inuse(isc_mem_t *);

isc_result_t			isc_mem_createx(size_t, size_t,
						isc_memalloc_t memalloc,
						isc_memfree_t memfree,
						void *arg, isc_mem_t **);
isc_result_t			isc_mem_restore(isc_mem_t *);

#ifdef ISC_MEMCLUSTER_LEGACY

/*
 * Legacy.
 */

#define meminit			isc__legacy_meminit
#define mem_default_context	isc__legacy_mem_default_context
#ifdef MEMCLUSTER_DEBUG
#define memget(s)		isc__legacy_memget_debug(s, __FILE__, __LINE__)
#define memput(p, s)		isc__legacy_memput_debug(p, s, \
							 __FILE__, __LINE__)
#else
#define memget			isc__legacy_memget
#define memput			isc__legacy_memput
#endif
#define memvalid		isc__legacy_memvalid
#define memstats		isc__legacy_memstats

int				meminit(size_t, size_t);
isc_mem_t *			mem_default_context(void);
void *				isc__legacy_memget(size_t);
void 				isc__legacy_memput(void *, size_t);
void *				isc__legacy_memget_debug(size_t, const char *,
							 int);
void				isc__legacy_memput_debug(void *, size_t,
							 const char *, int);
int				memvalid(void *);
void 				memstats(FILE *);

#endif /* ISC_MEMCLUSTER_LEGACY */

/*
 * Memory pools
 */

/*
 * Internal (but public) functions.  Don't call these from application
 * code.  Use isc_mempool_get() and isc_mempool_put() instead.
 */
void *		isc__mempool_get(isc_mempool_t *);
void 		isc__mempool_put(isc_mempool_t *, void *);
void *		isc__mempool_getdebug(isc_mempool_t *, const char *, int);
void 		isc__mempool_putdebug(isc_mempool_t *, void *,
				      const char *, int);

isc_result_t
isc_mempool_create(isc_mem_t *mctx, size_t size, isc_mempool_t **mpctxp);
/*
 * Create a memory pool.
 *
 * Requires:
 *	mctx is a valid memory context.
 *	size > 0
 *	mpctxp != NULL and *mpctxp == NULL
 *
 * Defaults:
 *	maxalloc = UINT_MAX
 *	freemax = 1
 *	fillcount = 1
 *
 * Returns:
 *	ISC_R_NOMEMORY		-- not enough memory to create pool
 *	ISC_R_SUCCESS		-- all is well.
 */

void
isc_mempool_destroy(isc_mempool_t **mpctxp);
/*
 * Destroy a memory pool.
 *
 * Requires:
 *	mpctxp != NULL && *mpctxp is a valid pool.
 *	The pool has no un"put" allocations outstanding
 */

void
isc_mempool_setname(isc_mempool_t *mpctx, const char *name);
/*
 * Associate a name with a memory pool.  At most 15 characters may be used.
 *
 * Requires:
 *	mpctx is a valid pool.
 *	name != NULL;
 */

void
isc_mempool_associatelock(isc_mempool_t *mpctx, isc_mutex_t *lock);
/*
 * Associate a lock with this memory pool.
 *
 * This lock is used when getting or putting items using this memory pool,
 * and it is also used to set or get internal state via the isc_mempool_get*()
 * and isc_mempool_set*() set of functions.
 *
 * Mutiple pools can each share a single lock.  For instance, if "manager"
 * type object contained pools for various sizes of events, and each of
 * these pools used a common lock.  Note that this lock must NEVER be used
 * by other than mempool routines once it is given to a pool, since that can
 * easily cause double locking.
 *
 * Requires:
 *
 *	mpctpx is a valid pool.
 *
 *	lock != NULL.
 *
 *	No previous lock is assigned to this pool.
 *
 *	The lock is initialized before calling this function via the normal
 *	means of doing that.
 */

/*
 * The following functions get/set various parameters.  Note that due to
 * the unlocked nature of pools these are potentially random values unless
 * the imposed externally provided locking protocols are followed.
 *
 * Also note that the quota limits will not always take immediate effect.
 * For instance, setting "maxalloc" to a number smaller than the currently
 * allocated count is permitted.  New allocations will be refused until
 * the count drops below this threshold.
 *
 * All functions require (in addition to other requirements):
 *	mpctx is a valid memory pool
 */

unsigned int
isc_mempool_getfreemax(isc_mempool_t *mpctx);
/*
 * Returns the maximum allowed size of the free list.
 */

void
isc_mempool_setfreemax(isc_mempool_t *mpctx, unsigned int limit);
/*
 * Sets the maximum allowed size of the free list.
 */

unsigned int
isc_mempool_getfreecount(isc_mempool_t *mpctx);
/*
 * Returns current size of the free list.
 */

unsigned int
isc_mempool_getmaxalloc(isc_mempool_t *mpctx);
/*
 * Returns the maximum allowed number of allocations.
 */

void
isc_mempool_setmaxalloc(isc_mempool_t *mpctx, unsigned int limit);
/*
 * Sets the maximum allowed number of allocations.
 *
 * Additional requirements:
 *	limit > 0
 */

unsigned int
isc_mempool_getallocated(isc_mempool_t *mpctx);
/*
 * Returns the number of items allocated from this pool.
 */

unsigned int
isc_mempool_getfillcount(isc_mempool_t *mpctx);
/*
 * Returns the number of items allocated as a block from the parent memory
 * context when the free list is empty.
 */

void
isc_mempool_setfillcount(isc_mempool_t *mpctx, unsigned int limit);
/*
 * Sets the fillcount.
 *
 * Additional requirements:
 *	limit > 0
 */

ISC_LANG_ENDDECLS

#endif /* ISC_MEM_H */
