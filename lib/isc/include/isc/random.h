/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#ifndef ISC_RANDOM_H
#define ISC_RANDOM_H 1

#include <isc/lang.h>
#include <isc/types.h>

/*
 * Implements a random state pool which will let the caller return a
 * series of possibly non-reproducable random values.  Note that the
 * strength of these numbers is not all that high, and should not be
 * used in cryptography functions.
 */

ISC_LANG_BEGINDECLS

struct isc_random {
	unsigned int	magic;
#if 0
	isc_mutex_t	lock;
#endif
};

#define ISC_RANDOM_MAGIC	0x52416e64	/* RAnd. */
#define ISC_RANDOM_VALID(x)	((x) != NULL && (x->magic) == ISC_RANDOM_MAGIC)

isc_result_t
isc_random_init(isc_random_t *r);
/*
 * Initialize a random state.
 *
 * This function must be called before using any of the following functions.
 *
 * Requires:
 *	r != NULL.
 */

isc_result_t
isc_random_invalidate(isc_random_t *r);
/*
 * Invalidate a random state.  This will wipe any information contained in
 * the state and make it unusable.
 *
 * Requires:
 *	r be a valid pool.
 */

void
isc_random_seed(isc_random_t *r, isc_uint32_t seed);
/*
 * Set the initial seed of the random state.  Note that on some systems
 * the private state isn't all that private, and setting the seed may
 * alter numbers returned to other state pools.
 *
 * Requires:
 *	r be a valid pool.
 */

void
isc_random_get(isc_random_t *r, isc_uint32_t *val);
/*
 * Get a random value.  Note that on some systems the private state isn't
 * all that private, and getting a value may alter what other state pools
 * would have returned.
 *
 * Requires:
 *	r be a valid pool.
 *	val != NULL.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_RANDOM_H */
