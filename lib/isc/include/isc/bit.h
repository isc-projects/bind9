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

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include <isc/attributes.h>
#include <isc/util.h>

#if __has_header(<stdbit.h>)

#include <stdbit.h>

#else /* __has_header(<stdbit.h>) */

#ifdef HAVE_BUILTIN_POPCOUNTG
#define stdc_count_ones(x) __builtin_popcountg(x)
#else /* HAVE_BUILTIN_POPCOUNTG */
#define stdc_count_ones(x)                          \
	_Generic((x),                               \
		unsigned int: __builtin_popcount,   \
		unsigned long: __builtin_popcountl, \
		unsigned long long: __builtin_popcountll)(x)
#endif /* HAVE_BUILTIN_POPCOUNTG */

#ifdef HAVE_BUILTIN_CLZG
#define stdc_leading_zeros(x) __builtin_clzg(x, (int)(sizeof(x) * 8))
#else /* HAVE_BUILTIN_CLZG */
#define stdc_leading_zeros(x)                           \
	(((x) == 0) ? (sizeof(x) * 8)                   \
		    : _Generic((x),                     \
			 unsigned int: __builtin_clz,   \
			 unsigned long: __builtin_clzl, \
			 unsigned long long: __builtin_clzll)(x))
#endif /* HAVE_BUILTIN_CLZG */

#ifdef HAVE_BUILTIN_CTZG
#define stdc_trailing_zeros(x) __builtin_ctzg(x, (int)sizeof(x) * 8)
#else /* HAVE_BUILTIN_CTZG */
#define stdc_trailing_zeros(x)                          \
	(((x) == 0) ? (sizeof(x) * 8)                   \
		    : _Generic((x),                     \
			 unsigned int: __builtin_ctz,   \
			 unsigned long: __builtin_ctzl, \
			 unsigned long long: __builtin_ctzll)(x))
#endif /* HAVE_BUILTIN_CTZG */

#define stdc_leading_ones(x)  stdc_leading_zeros(~(x))
#define stdc_trailing_ones(x) stdc_trailing_zeros(~(x))

#endif /* __has_header(<stdbit.h>) */

#if HAVE_BUILTIN_STD_ROTATE_LEFT && HAVE_BUILTIN_STD_ROTATE_RIGHT
#define ISC_ROTATE_LEFT(x, n)  __builtin_stdc_rotate_left(x, n)
#define ISC_ROTATE_RIGHT(x, n) __builtin_stdc_rotate_right(x, n)
#else /* HAVE_BUILTIN_STD_ROTATE_LEFT && HAVE_BUILTIN_STD_ROTATE_RIGHT */

static inline uint8_t
isc_rotate_left8(const uint8_t x, uint32_t n) {
	return (x << n) | (x >> (8 - n));
}

static inline uint16_t
isc_rotate_left16(const uint16_t x, uint32_t n) {
	return (x << n) | (x >> (16 - n));
}

static inline uint32_t
isc_rotate_left32(const uint32_t x, uint32_t n) {
	return (x << n) | (x >> (32 - n));
}

static inline uint64_t
isc_rotate_left64(const uint64_t x, uint32_t n) {
	return (x << n) | (x >> (64 - n));
}

static inline uint8_t
isc_rotate_right8(const uint8_t x, uint32_t n) {
	return (x >> n) | (x << (8 - n));
}

static inline uint16_t
isc_rotate_right16(const uint16_t x, uint32_t n) {
	return (x >> n) | (x << (16 - n));
}

static inline uint32_t
isc_rotate_right32(const uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

static inline uint64_t
isc_rotate_right64(const uint64_t x, uint32_t n) {
	return (x >> n) | (x << (64 - n));
}

#if __APPLE_CC__ || (defined(__OpenBSD__) && defined(__clang__))

/*
 * Apple compiler doesn't recognize size_t and uintXX_t types as same,
 * so we need to add kludges for size_t below.
 */

#if SIZE_MAX == UINT64_MAX
#define EXTRA_ROTATE_LEFT  , size_t : isc_rotate_left64
#define EXTRA_ROTATE_RIGHT , size_t : isc_rotate_right64
#elif SIZE_MAX == UINT32_MAX
#define EXTRA_ROTATE_LEFT  , size_t : isc_rotate_left32
#define EXTRA_ROTATE_RIGHT , size_t : isc_rotate_right32
#else
#error "size_t must be either 32 or 64-bits"
#endif
#else
#define EXTRA_ROTATE_LEFT
#define EXTRA_ROTATE_RIGHT
#endif

#define ISC_ROTATE_LEFT(x, n)                \
	_Generic((x),                        \
		uint8_t: isc_rotate_left8,   \
		uint16_t: isc_rotate_left16, \
		uint32_t: isc_rotate_left32, \
		uint64_t: isc_rotate_left64 EXTRA_ROTATE_LEFT)(x, n)

#define ISC_ROTATE_RIGHT(x, n)                \
	_Generic((x),                         \
		uint8_t: isc_rotate_right8,   \
		uint16_t: isc_rotate_right16, \
		uint32_t: isc_rotate_right32, \
		uint64_t: isc_rotate_right64 EXTRA_ROTATE_RIGHT)(x, n)

#endif /* HAVE_BUILTIN_STD_ROTATE_LEFT && HAVE_BUILTIN_STD_ROTATE_RIGHT */
