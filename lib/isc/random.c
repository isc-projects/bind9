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

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/random.h>
#include <isc/util.h>

static isc_once_t once = ISC_ONCE_INIT;
static isc_mutex_t rand_lock;

static void
initialize_rand(void)
{
	RUNTIME_CHECK(isc_mutex_init(&rand_lock) == ISC_R_SUCCESS);
}

static void
initialize(void)
{
	RUNTIME_CHECK(isc_once_do(&once, initialize_rand) == ISC_R_SUCCESS);
}

isc_result_t
isc_random_init(isc_random_t *r)
{
	REQUIRE(r != NULL);

	r->magic = ISC_RANDOM_MAGIC;
#if 0
	return (isc_mutex_init(&r->lock));
#else
	return (ISC_R_SUCCESS);
#endif
}

isc_result_t
isc_random_invalidate(isc_random_t *r)
{
	isc_result_t result;

	REQUIRE(ISC_RANDOM_VALID(r));

#if 0
	result = isc_mutex_destroy(&r->lock);
#else
	result = ISC_R_SUCCESS;
#endif

	memset(r, 0, sizeof(isc_random_t));

	return (result);
}

void
isc_random_seed(isc_random_t *r, isc_uint32_t seed)
{
	REQUIRE(ISC_RANDOM_VALID(r));

	initialize();

#if 0
	LOCK(&r->lock);
#endif
	LOCK(&rand_lock);
	srand(seed);
	UNLOCK(&rand_lock);
#if 0
	UNLOCK(&r->lock);
#endif
}

void
isc_random_get(isc_random_t *r, isc_uint32_t *val)
{
	REQUIRE(ISC_RANDOM_VALID(r));
	REQUIRE(val != NULL);

	initialize();

#if 0
	LOCK(&r->lock);
#endif
	LOCK(&rand_lock);
	*val = rand();
	UNLOCK(&rand_lock);
#if 0
	UNLOCK(&r->lock);
#endif
}
