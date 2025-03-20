#pragma once

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The constant K from Rust's fxhash */
#define K 0x9e3779b97f4a7c15ull

static inline size_t
rotate_left(size_t x, unsigned int n) {
	return (x << n) | (x >> (sizeof(size_t) * 8 - n));
}

static inline size_t
fx_add_to_hash(size_t hash, size_t i) {
	return rotate_left(hash, 5) ^ i * K;
}

/*
 * Beware: this implementation will use an approximate conversion to lowercase.
 * This is ok as fxhash is already not hash-flooding resistant and we use it
 * only for config parsing.
 */
static inline size_t
fx_hash_bytes(size_t initial_hash, const uint8_t *restrict bytes, size_t len,
	      bool case_sensitive) {
	size_t hash = initial_hash;
	size_t case_mask = case_sensitive
				   ? -1ull
				   : (0b11011111 * 0x0101010101010101ull);

	while (len >= sizeof(size_t)) {
		size_t value;
		memmove(&value, bytes, sizeof(size_t));
		hash = fx_add_to_hash(hash, value & case_mask);
		bytes += sizeof(size_t);
		len -= sizeof(size_t);
	}

	/* Will be ignored if sizeof(size_t) <= 4 */
	if (len >= 4) {
		uint32_t value;
		memmove(&value, bytes, sizeof(uint32_t));
		hash = fx_add_to_hash(hash, value & case_mask);
		bytes += 4;
		len -= 4;
	}

	/* Will be ignored if sizeof(size_t) <= 2 */
	if (len >= 2) {
		uint16_t value;
		memmove(&value, bytes, sizeof(uint16_t));
		hash = fx_add_to_hash(hash, value & case_mask);
		bytes += 2;
		len -= 2;
	}

	if (len >= 1) {
		hash = fx_add_to_hash(hash, bytes[0] & case_mask);
	}

	return hash;
}
