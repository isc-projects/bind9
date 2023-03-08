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

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/histo.h>
#include <isc/magic.h>
#include <isc/mem.h>

/*
 * XXXFANF to be added to isc/util.h by a commmit in a qp-trie
 * feature branch
 */
#define STRUCT_FLEX_SIZE(pointer, member, count) \
	(sizeof(*(pointer)) + sizeof(*(pointer)->member) * (count))

#define HISTO_MAGIC    ISC_MAGIC('H', 's', 't', 'o')
#define HISTO_VALID(p) ISC_MAGIC_VALID(p, HISTO_MAGIC)

/*
 * Natural logarithms of 2 and 10 for converting precisions between
 * binary and decimal significant figures
 */
#define LN_2  0.693147180559945309
#define LN_10 2.302585092994045684

/*
 * The chunks array has a static size for simplicity, fixed as the
 * number of bits in a value. That means we waste a little extra space
 * that could be saved by omitting the exponents that are covered by
 * `sigbits`. The following macros calculate (at run time) the exact
 * number of buckets when we need to do accurate bounds checks.
 *
 * For a discussion of the floating point terminology, see the
 * commmentary on `value_to_key()` below.
 *
 * We often use the variable names `c` for chunk and `b` for bucket.
 */
#define CHUNKS 64

#define DENORMALS(hg) ((hg)->sigbits - 1)
#define MANTISSAS(hg) (1 << (hg)->sigbits)
#define EXPONENTS(hg) (CHUNKS - DENORMALS(hg))
#define BUCKETS(hg)   (EXPONENTS(hg) * MANTISSAS(hg))

#define MAXCHUNK(hg)   EXPONENTS(hg)
#define CHUNKSIZE(hg)  MANTISSAS(hg)
#define CHUNKBYTES(hg) (CHUNKSIZE(hg) * sizeof(hg_bucket_t))

typedef atomic_uint_fast64_t hg_bucket_t;
typedef atomic_ptr(hg_bucket_t) hg_chunk_t;

#define ISC_HISTO_FIELDS \
	uint magic;      \
	uint sigbits;    \
	isc_mem_t *mctx

struct isc_histo {
	ISC_HISTO_FIELDS;
	/* chunk array must be first after common fields */
	hg_chunk_t chunk[CHUNKS];
};

/*
 * To convert between ranks and values, we scan the histogram to find the
 * required rank. Each per-chunk total contains the sum of all the buckets
 * in that chunk, so we can scan a chunk at a time rather than a bucket at
 * a time.
 *
 * XXXFANF When `sigbits` is large, the chunks get large and slow to scan.
 * If this turns out to be a problem, we could store ranks as well as
 * values in the summary, and use a binary search.
 */
struct isc_histosummary {
	ISC_HISTO_FIELDS;
	/* chunk array must be first after common fields */
	uint64_t *chunk[CHUNKS];
	uint64_t total[CHUNKS];
	uint64_t population;
	uint64_t maximum;
	size_t size;
	uint64_t buckets[];
};

/**********************************************************************/

#define OUTARG(ptr, val)                \
	({                              \
		if ((ptr) != NULL) {    \
			*(ptr) = (val); \
		}                       \
	})

static inline uint64_t
interpolate(uint64_t span, uint64_t mul, uint64_t div) {
	double frac = div > 0 ? (double)mul / (double)div : mul > 0 ? 1 : 0;
	return ((uint64_t)round(span * frac));
}

/**********************************************************************/

void
isc_histo_create(isc_mem_t *mctx, uint sigbits, isc_histo_t **hgp) {
	REQUIRE(sigbits >= ISC_HISTO_MINBITS);
	REQUIRE(sigbits <= ISC_HISTO_MAXBITS);
	REQUIRE(hgp != NULL);
	REQUIRE(*hgp == NULL);

	isc_histo_t *hg = isc_mem_get(mctx, sizeof(*hg));
	*hg = (isc_histo_t){
		.magic = HISTO_MAGIC,
		.sigbits = sigbits,
	};
	isc_mem_attach(mctx, &hg->mctx);

	*hgp = hg;
}

void
isc_histo_destroy(isc_histo_t **hgp) {
	REQUIRE(hgp != NULL);
	REQUIRE(HISTO_VALID(*hgp));

	isc_histo_t *hg = *hgp;
	*hgp = NULL;

	for (uint c = 0; c < CHUNKS; c++) {
		if (hg->chunk[c] != NULL) {
			isc_mem_put(hg->mctx, hg->chunk[c], CHUNKBYTES(hg));
		}
	}
	isc_mem_putanddetach(&hg->mctx, hg, sizeof(*hg));
}

/**********************************************************************/

uint
isc_histo_sigbits(isc_historead_t hr) {
	REQUIRE(HISTO_VALID(hr.hg));
	return (hr.hg->sigbits);
}

/*
 * use precomputed logs and builtins to avoid linking with libm
 */

uint
isc_histo_bits_to_digits(uint bits) {
	REQUIRE(bits >= ISC_HISTO_MINBITS);
	REQUIRE(bits <= ISC_HISTO_MAXBITS);
	return (floor(1.0 - (1.0 - bits) * LN_2 / LN_10));
}

uint
isc_histo_digits_to_bits(uint digits) {
	REQUIRE(digits >= ISC_HISTO_MINDIGITS);
	REQUIRE(digits <= ISC_HISTO_MAXDIGITS);
	return (ceil(1.0 - (1.0 - digits) * LN_10 / LN_2));
}

/**********************************************************************/

/*
 * The way we map buckets to keys is what gives the histogram a
 * consistent relative error across the whole range of `uint64_t`.
 * The mapping is log-linear: a chunk key is the logarithm of part
 * of the value (in other words, chunks are spaced exponentially);
 * and a bucket within a chunk is a linear function of another part
 * of the value.
 *
 * This log-linear spacing is similar to the size classes used by
 * jemalloc. It is also the way floating point numbers work: the
 * exponent is the log part, and the mantissa is the linear part.
 *
 * So, a chunk number is the log (base 2) of a `uint64_t`, which is
 * between 0 and 63, which is why there are up to 64 chunks. In
 * floating point terms the chunk number is the exponent. The
 * histogram's number of significant bits is the size of the
 * mantissa, which indexes buckets within each chunk.
 *
 * A fast way to get the logarithm of a positive integer is CLZ,
 * count leading zeroes.
 *
 * Chunk zero is special. Chunk 1 covers values between `CHUNKSIZE`
 * and `CHUNKSIZE * 2 - 1`, where `CHUNKSIZE == exponent << sigbits
 * == 1 << sigbits`. Each chunk has CHUNKSIZE buckets, so chunk 1 has
 * one value per bucket. There are CHUNKSIZE values before chunk 1
 * which map to chunk 0, so it also has one value per bucket. (Hence
 * the first two chunks have one value per bucket.) The values in
 * chunk 0 correspond to denormal nubers in floating point terms.
 * They are also the values where `63 - sigbits - clz` would be less
 * than one if denormals were not handled specially.
 *
 * This branchless conversion is due to Paul Khuong: see bin_down_of() in
 * https://pvk.ca/Blog/2015/06/27/linear-log-bucketing-fast-versatile-simple/
 */
static inline uint
value_to_key(isc_historead_t hr, uint64_t value) {
	/* fast path */
	const isc_histo_t *hg = hr.hg;
	/* ensure that denormal numbers are all in chunk zero */
	uint64_t chunked = value | CHUNKSIZE(hg);
	int clz = __builtin_clzll((unsigned long long)(chunked));
	/* actually 1 less than the exponent except for denormals */
	uint exponent = 63 - hg->sigbits - clz;
	/* mantissa has leading bit set except for denormals */
	uint mantissa = value >> exponent;
	/* leading bit of mantissa adds one to exponent */
	return ((exponent << hg->sigbits) + mantissa);
}

/*
 * Inverse functions of `value_to_key()`, to get the minimum and
 * maximum values that map to a particular key.
 *
 * We must not cause undefined behaviour by hitting integer limits,
 * which is a risk when we aim to cover the entire range of `uint64_t`.
 *
 * The maximum value in the last bucket is UINT64_MAX, which
 * `key_to_maxval()` gets by deliberately subtracting `0 - 1`,
 * undeflowing a `uint64_t`. That is OK when unsigned.
 *
 * We must take care not to shift too much in `key_to_minval()`.
 * The largest key passed by `key_to_maxval()` is `BUCKETS(hg)`, so
 *	`exponent == EXPONENTS(hg) - 1 == 64 - sigbits`
 * which is always less than 64, so the size of the shift is OK.
 *
 * The `mantissa` in this edge case is just `chunksize`, which when
 * shifted becomes `1 << 64` which overflows `uint64_t` Again this is
 * OK when unsigned, so the return value is zero.
 */

static inline uint64_t
key_to_minval(isc_historead_t hr, uint key) {
	uint chunksize = CHUNKSIZE(hr.hg);
	uint exponent = (key / chunksize) - 1;
	uint64_t mantissa = (key % chunksize) + chunksize;
	return (key < chunksize ? key : mantissa << exponent);
}

static inline uint64_t
key_to_maxval(isc_historead_t hr, uint key) {
	return (key_to_minval(hr, key + 1) - 1);
}

/**********************************************************************/

static hg_bucket_t *
key_to_new_bucket(isc_histo_t *hg, uint key) {
	/* slow path */
	uint chunksize = CHUNKSIZE(hg);
	uint chunk = key / chunksize;
	uint bucket = key % chunksize;
	size_t bytes = CHUNKBYTES(hg);
	hg_bucket_t *old_cp = NULL;
	hg_bucket_t *new_cp = isc_mem_getx(hg->mctx, bytes, ISC_MEM_ZERO);
	hg_chunk_t *cpp = &hg->chunk[chunk];
	if (atomic_compare_exchange_strong_acq_rel(cpp, &old_cp, new_cp)) {
		return (&new_cp[bucket]);
	} else {
		/* lost the race, so use the winner's chunk */
		isc_mem_put(hg->mctx, new_cp, bytes);
		return (&old_cp[bucket]);
	}
}

static hg_bucket_t *
get_chunk(isc_historead_t hr, uint chunk) {
	const hg_chunk_t *cpp = &hr.hg->chunk[chunk];
	return (atomic_load_acquire(cpp));
}

static inline hg_bucket_t *
key_to_bucket(isc_historead_t hr, uint key) {
	/* fast path */
	uint chunksize = CHUNKSIZE(hr.hg);
	uint chunk = key / chunksize;
	uint bucket = key % chunksize;
	hg_bucket_t *cp = get_chunk(hr, chunk);
	return (cp == NULL ? NULL : &cp[bucket]);
}

static inline uint64_t
get_key_count(isc_historead_t hr, uint key) {
	hg_bucket_t *bp = key_to_bucket(hr, key);
	return (bp == NULL ? 0 : atomic_load_relaxed(bp));
}

static inline void
add_key_count(isc_histo_t *hg, uint key, uint64_t inc) {
	if (inc > 0) {
		hg_bucket_t *bp = key_to_bucket(hg, key);
		bp = bp != NULL ? bp : key_to_new_bucket(hg, key);
		atomic_fetch_add_relaxed(bp, inc);
	}
}

/**********************************************************************/

void
isc_histo_add(isc_histo_t *hg, uint64_t value, uint64_t inc) {
	REQUIRE(HISTO_VALID(hg));
	add_key_count(hg, value_to_key(hg, value), inc);
}

void
isc_histo_inc(isc_histo_t *hg, uint64_t value) {
	isc_histo_add(hg, value, 1);
}

void
isc_histo_put(isc_histo_t *hg, uint64_t min, uint64_t max, uint64_t count) {
	REQUIRE(HISTO_VALID(hg));

	uint kmin = value_to_key(hg, min);
	uint kmax = value_to_key(hg, max);

	for (uint key = kmin; key <= kmax; key++) {
		uint64_t mid = ISC_MIN(max, key_to_maxval(hg, key));
		double in_bucket = mid - min + 1;
		double remaining = max - min + 1;
		uint64_t inc = ceil(count * in_bucket / remaining);
		add_key_count(hg, key, inc);
		count -= inc;
		min = mid + 1;
	}
}

isc_result_t
isc_histo_get(isc_historead_t hr, uint key, uint64_t *minp, uint64_t *maxp,
	      uint64_t *countp) {
	REQUIRE(HISTO_VALID(hr.hg));

	if (key < BUCKETS(hr.hg)) {
		OUTARG(minp, key_to_minval(hr, key));
		OUTARG(maxp, key_to_maxval(hr, key));
		OUTARG(countp, get_key_count(hr, key));
		return (ISC_R_SUCCESS);
	} else {
		return (ISC_R_RANGE);
	}
}

void
isc_histo_next(isc_historead_t hr, uint *keyp) {
	const isc_histo_t *hg = hr.hg;

	REQUIRE(HISTO_VALID(hg));
	REQUIRE(keyp != NULL);

	uint chunksize = CHUNKSIZE(hg);
	uint buckets = BUCKETS(hg);
	uint key = *keyp;

	key++;
	while (key < buckets && key % chunksize == 0 &&
	       key_to_bucket(hr, key) == NULL)
	{
		key += chunksize;
	}
	*keyp = key;
}

void
isc_histo_merge(isc_histo_t **targetp, isc_historead_t source) {
	REQUIRE(HISTO_VALID(source.hg));
	REQUIRE(targetp != NULL);

	if (*targetp != NULL) {
		REQUIRE(HISTO_VALID(*targetp));
	} else {
		isc_histo_create(source.hg->mctx, source.hg->sigbits, targetp);
	}

	uint64_t min, max, count;
	for (uint key = 0;
	     isc_histo_get(source, key, &min, &max, &count) == ISC_R_SUCCESS;
	     isc_histo_next(source, &key))
	{
		isc_histo_put(*targetp, min, max, count);
	}
}

/**********************************************************************/

/*
 * https://fanf2.user.srcf.net/hermes/doc/antiforgery/stats.pdf
 * equation 4 (incremental mean) and equation 44 (incremental variance)
 */
void
isc_histo_moments(isc_historead_t hr, double *pm0, double *pm1, double *pm2) {
	REQUIRE(HISTO_VALID(hr.hg));

	double pop = 0.0;
	double mean = 0.0;
	double sigma = 0.0;

	uint64_t min, max, count;
	for (uint key = 0;
	     isc_histo_get(hr, key, &min, &max, &count) == ISC_R_SUCCESS;
	     isc_histo_next(hr, &key))
	{
		if (count == 0) { /* avoid division by zero */
			continue;
		}
		double value = min / 2.0 + max / 2.0;
		double delta = value - mean;
		pop += count;
		mean += count * delta / pop;
		sigma += count * delta * (value - mean);
	}

	OUTARG(pm0, pop);
	OUTARG(pm1, mean);
	OUTARG(pm2, sqrt(sigma / pop));
}

/**********************************************************************/

void
isc_histosummary_create(isc_historead_t hr, isc_histosummary_t **hsp) {
	const isc_histo_t *hg = hr.hg;

	REQUIRE(HISTO_VALID(hg));
	REQUIRE(hsp != NULL);
	REQUIRE(*hsp == NULL);

	uint chunksize = CHUNKSIZE(hg);
	hg_bucket_t *chunk[CHUNKS] = { NULL };

	/*
	 * First, find out which chunks we will copy across and how much
	 * space they need. We take a copy of the chunk pointers because
	 * concurrent threads may add new chunks before we have finished.
	 */
	uint size = 0;
	for (uint c = 0; c < CHUNKS; c++) {
		chunk[c] = get_chunk(hg, c);
		if (chunk[c] != NULL) {
			size += chunksize;
		}
	}

	isc_histosummary_t *hs =
		isc_mem_get(hg->mctx, STRUCT_FLEX_SIZE(hs, buckets, size));
	*hs = (isc_histosummary_t){
		.magic = HISTO_MAGIC,
		.sigbits = hg->sigbits,
		.size = size,
	};
	isc_mem_attach(hg->mctx, &hs->mctx);

	/*
	 * Second, copy the contents of the buckets. The copied pointers
	 * are faster than get_key_count() because get_chunk()'s atomics
	 * would require re-fetching the chunk pointer for every bucket.
	 */
	uint maxkey = 0;
	uint chunkbase = 0;
	for (uint c = 0; c < CHUNKS; c++) {
		if (chunk[c] == NULL) {
			continue;
		}
		hs->chunk[c] = &hs->buckets[chunkbase];
		chunkbase += chunksize;
		for (uint b = 0; b < chunksize; b++) {
			uint64_t count = atomic_load_relaxed(&chunk[c][b]);
			hs->chunk[c][b] = count;
			hs->total[c] += count;
			hs->population += count;
			maxkey = (count == 0) ? maxkey : chunksize * c + b;
		}
	}
	hs->maximum = key_to_maxval(hs, maxkey);

	*hsp = hs;
}

void
isc_histosummary_destroy(isc_histosummary_t **hsp) {
	REQUIRE(hsp != NULL);
	REQUIRE(HISTO_VALID(*hsp));

	isc_histosummary_t *hs = *hsp;
	*hsp = NULL;

	isc_mem_putanddetach(&hs->mctx, hs,
			     STRUCT_FLEX_SIZE(hs, buckets, hs->size));
}

/**********************************************************************/

isc_result_t
isc_histo_value_at_rank(const isc_histosummary_t *hs, uint64_t rank,
			uint64_t *valuep) {
	REQUIRE(HISTO_VALID(hs));
	REQUIRE(valuep != NULL);

	uint maxchunk = MAXCHUNK(hs);
	uint chunksize = CHUNKSIZE(hs);
	uint64_t count = 0;
	uint b, c;

	if (rank > hs->population) {
		return (ISC_R_RANGE);
	}
	if (rank == hs->population) {
		*valuep = hs->maximum;
		return (ISC_R_SUCCESS);
	}

	for (c = 0; c < maxchunk; c++) {
		count = hs->total[c];
		if (rank < count) {
			break;
		}
		rank -= count;
	}
	INSIST(c < maxchunk);

	for (b = 0; b < chunksize; b++) {
		count = hs->chunk[c][b];
		if (rank < count) {
			break;
		}
		rank -= count;
	}
	INSIST(b < chunksize);

	uint key = chunksize * c + b;
	uint64_t min = key_to_minval(hs, key);
	uint64_t max = key_to_maxval(hs, key);
	*valuep = min + interpolate(max - min, rank, count);

	return (ISC_R_SUCCESS);
}

void
isc_histo_rank_of_value(const isc_histosummary_t *hs, uint64_t value,
			uint64_t *rankp) {
	REQUIRE(HISTO_VALID(hs));
	REQUIRE(rankp != NULL);

	uint key = value_to_key(hs, value);
	uint chunksize = CHUNKSIZE(hs);
	uint kc = key / chunksize;
	uint kb = key % chunksize;
	uint64_t rank = 0;

	for (uint c = 0; c < kc; c++) {
		rank += hs->total[c];
	}
	for (uint b = 0; b < kb; b++) {
		rank += hs->chunk[kc][b];
	}

	uint64_t count = hs->chunk[kc][kb];
	uint64_t min = key_to_minval(hs, key);
	uint64_t max = key_to_maxval(hs, key);

	*rankp = rank + interpolate(count, value - min, max - min);
}

isc_result_t
isc_histo_quantile(const isc_histosummary_t *hs, double p, uint64_t *valuep) {
	if (p < 0.0 || p > 1.0) {
		return (ISC_R_RANGE);
	}
	double rank = round(hs->population * p);
	return (isc_histo_value_at_rank(hs, (uint64_t)rank, valuep));
}

void
isc_histo_cdf(const isc_histosummary_t *hs, uint64_t value, double *pp) {
	uint64_t rank;
	isc_histo_rank_of_value(hs, value, &rank);
	*pp = (double)rank / (double)hs->population;
}

/**********************************************************************/
