#ifndef ISC_REFERENCE_H
#define ISC_REFERENCE_H 1

#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>
#include <isc/util.h>

/*
 * Implements a locked reference counter.  These functions may actually be
 * implemented using macros, and implementations of these macros are below.
 * The isc_refcount_t type should not be accessed directly, as its contents
 * depend on the implementation.
 */

ISC_LANG_BEGINDECLS

/*
 * Function prototypes
 */

/*
 * void
 * isc_refcount_init(isc_refcount_t *ref, unsigned int n);
 *
 * Initialize the reference counter.  There will be 'n' initial references.
 *
 * Requires:
 *	ref != NULL
 */

/*
 * void
 * isc_refcount_destroy(isc_refcount_t *ref);
 *
 * Destroys a reference counter.
 *
 * Requires:
 *	ref != NULL
 *	The number of references is 0.
 */

/*
 * void
 * isc_refcount_increment(isc_refcount_t *ref, unsigned int *targetp);
 *
 * Increments the reference count, returning the new value in targetp if it's
 * not NULL.
 *
 * Requires:
 *	ref != NULL.
 */

/*
 * void
 * isc_refcount_decrement(isc_refcount_t *ref, unsigned int *targetp);
 *
 * Decrements the reference count,  returning the new value in targetp if it's
 * not NULL.
 *
 * Requires:
 *	ref != NULL.
 */


/*
 * Sample implementations
 */
#ifdef ISC_PLATFORM_USETHREADS

typedef struct isc_refcount {
	int refs;
	isc_mutex_t lock;
} isc_refcount_t;

#define isc_refcount_init(rp, n) 			\
	do {						\
		isc_result_t _r;			\
		(rp)->refs = (n);			\
		_r = isc_mutex_init(&(rp)->lock);	\
		RUNTIME_CHECK(_r == ISC_R_SUCCESS);	\
	} while (0)

#define isc_refcount_destroy(rp)			\
	do {						\
		REQUIRE((rp)->refs == 0);		\
		DESTROYLOCK(&(rp)->lock);		\
	} while (0)

#define isc_refcount_current(rp) ((unsigned int)((rp)->refs))

#define isc_refcount_increment(rp, tp)				\
	do {							\
		LOCK(&(rp)->lock);				\
		REQUIRE((rp)->refs > 0);			\
		++((rp)->refs);					\
		if ((tp) != NULL)				\
			*(unsigned int *)(tp) = ((rp)->refs);	\
		UNLOCK(&(rp)->lock);				\
	} while (0)

#define isc_refcount_decrement(rp, tp)				\
	do {							\
		LOCK(&(rp)->lock);				\
		REQUIRE((rp)->refs > 0);			\
		--((rp)->refs);					\
		if ((tp) != NULL)				\
			*(unsigned int *)(tp) = ((rp)->refs);	\
		UNLOCK(&(rp)->lock);				\
	} while (0)

#else

typedef struct isc_refcount {
	int refs;
} isc_refcount_t;

#define isc_refcount_init(rp, n) ((rp)->refs = (n))
#define isc_refcount_destroy(rp) (REQUIRE((rp)->refs == 0))
#define isc_refcount_current(rp) ((unsigned int)((rp)->refs))

#define isc_refcount_increment(rp, tp)					\
	do {								\
		int _n = ++(rp)->refs;					\
		if ((tp) != NULL)					\
			*(unsigned int *)(tp) = (unsigned int)(_n);	\
	} while (0)

#define isc_refcount_decrement(rp, tp)					\
	do {								\
		int _n = --(rp)->refs;					\
		if ((tp) != NULL)					\
			*(unsigned int *)(tp) = (unsigned int)(_n);	\
	} while (0)

#endif

ISC_LANG_ENDDECLS

#endif /* ISC_REFCOUNT_H */
