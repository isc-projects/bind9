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

#include <config.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef OPENSSL
#include <openssl/rand.h>
#endif /* ifdef OPENSSL */

#ifdef PKCS11CRYPTO
#include <pk11/pk11.h>
#endif /* ifdef PKCS11CRYPTO */

#if defined(__linux__)
# include <errno.h>
# ifdef HAVE_GETRANDOM
#  include <sys/random.h>
# else  /* HAVE_GETRANDOM */
#  include <sys/syscall.h>
# endif /* HAVE_GETRANDOM */
#endif /* defined(__linux__) */

#include <isc/random.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#if defined(__linux__)
# ifdef HAVE_GETRANDOM
#  define have_getrandom() 1
# else  /* ifdef HAVE_GETRANDOM */
#  undef getrandom
#  if defined(SYS_getrandom)
#   define getrandom(dst,s,flags) syscall(SYS_getrandom, \
					  (void*)dst, \
					  (size_t)s, \
					  (unsigned int)flags)

static unsigned
have_getrandom(void)
{
	uint16_t buf;
	ssize_t ret;
	ret = getrandom(&buf, sizeof(buf), 1 /*GRND_NONBLOCK*/);
	return (ret == sizeof(buf) ||
		(ret == -1 && errno == EAGAIN));
}

#  else  /* defined(SYS_getrandom) */
#   define have_getrandom() 0
#   define getrandom(dst,s,flags) -1
#  endif /* defined(SYS_getrandom) */
# endif /* ifdef HAVE_GETRANDOM */

static int
getrandom_buf(void *buf, size_t buflen)
{
	size_t left = buflen;
	ssize_t ret;
	uint8_t *p = buf;

	while (left > 0) {
		ret = getrandom(p, left, 0);
		if (ret == -1 && errno == EINTR) {
			continue;
		}

		RUNTIME_CHECK(ret >= 0);

		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}

	return(0);
}
#endif /* __linux__ */

#if defined(_WIN32) || defined(_WIN64)

static isc_once_t isc_random_once = ISC_ONCE_INIT;

static HCRYPTPROV isc_random_hcryptprov;

static void isc_random_initialize(void) {
	RUNTIME_CHECK(CryptAcquireContext(&hcryptprov, NULL, NULL, PROV_RSA_FULL,
					  CRYPT_VERIFYCONTEXT|CRYPT_SILENT));
}

#endif /* defined(_WIN32) || defined(_WIN64) */

uint32_t
isc_random(void)
{
#if defined(HAVE_ARC4RANDOM)
	return(arc4random());
#else /* HAVE_ARC4RANDOM */
	uint32_t ret;
	isc_random_buf(&ret, sizeof(ret));
	return (ret);
#endif /* HAVE_ARC4RANDOM */
}

/*
 * Fill the region buf of length buflen with random data.
 */
void
isc_random_buf(void *buf, size_t buflen)
{
	REQUIRE(buf);
	REQUIRE(buflen > 0);

#if defined(_WIN32) || defined(_WIN64)
	RUNTIME_CHECK(isc_once_do(&once, initialize_rand) == ISC_R_SUCCESS);
	RUNTIME_CHECK(CryptGenRandom(isc_random_hcryptprov, (DWORD)buflen, buf));
	return;
#elif defined(HAVE_ARC4RANDOM_BUF)
	arc4random_buf(buf, buflen);
	return;
#else

# if defined(__linux__)
	/* We need to check the availability of the SYS_getrandom syscall at runtime
	 * and fall back to crypto library provider if not available
	 */
	if (have_getrandom()) {
		getrandom_buf(buf, buflen);
		return;
	}

# endif  /* defined(__linux__) */

/* Use crypto library as fallback when no other CSPRNG is available */
# if defined(OPENSSL)
	RUNTIME_CHECK(RAND_bytes(buf, buflen) < 1);
# elif defined(PKCS11CRYPTO)
	RUNTIME_CHECK(pk11_rand_bytes(buf, buflen) == ISC_R_SUCCESS);
# endif /* if defined(HAVE_ARC4RANDOM_BUF) */

#endif
}

uint32_t
isc_random_uniform(uint32_t upper_bound)
{
#if defined(HAVE_ARC4RANDOM_UNIFORM)
	return(arc4random_uniform(upper_bound));
#else  /* if defined(HAVE_ARC4RANDOM_UNIFORM) */
	/* Copy of arc4random_uniform from OpenBSD */
	u_int32_t r, min;

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
		r = isc_random();
		if (r >= min) {
			break;
		}
	}

	return (r % upper_bound);
#endif /* if defined(HAVE_ARC4RANDOM_UNIFORM) */
}
