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
/*
 * Portions of isc_random_uniform():
 *
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * rotl() and next() written in 2018 by David Blackman and
 * Sebastiano Vigna (vigna@acm.org)
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <config.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/random.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isc/once.h>

#include "entropy.h"

static isc_once_t isc_random_once = ISC_ONCE_INIT;

/*
 * This is xoshiro128+ 1.0, our best and fastest 32-bit generator for
 * 32-bit floating-point numbers. We suggest to use its upper bits for
 * floating-point generation, as it is slightly faster than xoshiro128**.
 * It passes all tests we are aware of except for linearity tests, as the
 * lowest four bits have low linear complexity, so if low linear complexity
 * is not considered an issue (as it is usually the case) it can be used to
 * generate 32-bit outputs, too.
 *
 * We suggest to use a sign test to extract a random Boolean value, and
 * right shifts to extract subsets of bits.
 *
 * The state must be seeded so that it is not everywhere zero.
 */

static uint32_t seed[4];

static inline uint32_t rotl(const uint32_t x, int k) {
	return (x << k) | (x >> (32 - k));
}

static uint32_t next(void) {
	const uint32_t result_plus = seed[0] + seed[3];

	const uint32_t t = seed[1] << 9;

	seed[2] ^= seed[0];
	seed[3] ^= seed[1];
	seed[1] ^= seed[2];
	seed[0] ^= seed[3];

	seed[2] ^= t;

	seed[3] = rotl(seed[3], 11);

	return (result_plus);
}

/*
 * Seed the PRNG using entropy from the crypto provider.
 */
static void
isc_random_initialize(void) {
	isc_entropy_get(seed, sizeof(seed));
}

uint32_t
isc_random(void) {
	RUNTIME_CHECK(isc_once_do(&isc_random_once,
				  isc_random_initialize) == ISC_R_SUCCESS);
	return (next());
}

void
isc_random_buf(void *buf, size_t buflen) {
	REQUIRE(buf);
	REQUIRE(buflen > 0);

	RUNTIME_CHECK(isc_once_do(&isc_random_once,
				  isc_random_initialize) == ISC_R_SUCCESS);

	int i;
	uint32_t r;

	for (i = 0; i + sizeof(r) <= buflen; i += sizeof(r)) {
		r = next();
		memmove((uint8_t *)buf + i, &r, sizeof(r));
	}
	r = next();
	memmove((uint8_t *)buf + i, &r, buflen % sizeof(r));
	return;
}

uint32_t
isc_random_uniform(uint32_t upper_bound)
{
	/* Copy of arc4random_uniform from OpenBSD */
	uint32_t r, min;

	RUNTIME_CHECK(isc_once_do(&isc_random_once,
				  isc_random_initialize) == ISC_R_SUCCESS);

	if (upper_bound < 2) {
		return (0);
	}

#if (ULONG_MAX > 0xffffffffUL)
	min = 0x100000000UL % upper_bound;
#else  /* if (ULONG_MAX > 0xffffffffUL) */
	/* Calculate (2**32 % upper_bound) avoiding 64-bit math */
	if (upper_bound > 0x80000000) {
		min = 1 + ~upper_bound;         /* 2**32 - upper_bound */
	} else {
		/* (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31 */
		min = ((0xffffffff - (upper_bound * 2)) + 1) % upper_bound;
	}
#endif /* if (ULONG_MAX > 0xffffffffUL) */

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = next();
		if (r >= min) {
			break;
		}
	}

	return (r % upper_bound);
}
