/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#include <stdio.h>

#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/sha1.h>
#include <isc/string.h>
#include <isc/util.h>

/*
 * Much of this code is modeled after the NetBSD /dev/random implementation,
 * written by Michael Graff <explorer@netbsd.org>.
 */

/***
 *** "constants."  Do not change these unless you _really_ know what
 *** you are doing.
 ***/

/*
 * size of entropy pool in 32-bit words.  This _MUST_ be a power of 2.
 */
#define RND_POOLWORDS	128
#define RND_POOLBITS     (RND_POOLWORDS * 32)

/*
 * Number of bytes returned per hash.  This must be true:
 *	threshold * 2 <= digest_size_in_bytes
 */
#define RND_ENTROPY_THRESHOLD	10

/*
 * Size of the input event queue in samples.
 */
#define RND_EVENTQSIZE	32

typedef struct {
	isc_uint32_t	cursor;		/* current add point in the pool */
	isc_uint32_t	entropy;	/* current entropy estimate in bits */
	isc_uint32_t	rotate;		/* how many bits to rotate by */
	isc_uint32_t	pool[RND_POOLWORDS];	/* random pool data */
} isc_entropypool_t;

struct isc_entropy {
	isc_mutex_t			lock;
	isc_mem_t		       *mctx;
	isc_entropypool_t		pool;
	ISC_LIST(isc_entropysource_t)	sources;
};

typedef struct {
	isc_uint32_t	last_time;	/* last time recorded */
	isc_uint32_t	last_delta;	/* last delta value */
	isc_uint32_t	last_delta2;	/* last delta2 value */
	isc_uint32_t	entropy;	/* entropy believed to be in samples */
	isc_uint32_t	nsamples;	/* number of samples filled in */
	isc_uint32_t   *samples;	/* the samples */
	isc_uint32_t   *extra;		/* extra samples added in */
} isc_entropysamplesource_t ;

typedef struct {
	int		fd;		/* fd for the file, or -1 if closed */
} isc_entropyfilesource_t;

struct isc_entropysource {
	unsigned int	type;
	unsigned int	flags;		/* flags */
	isc_uint32_t	total;		/* entropy from this source */
	char		name[32];
	union {
		isc_entropysamplesource_t	samplesource;
		isc_entropyfilesource_t		filesource;
	} sources;
};

#define RND_TYPE_SAMPLE		1	/* Type is a sample source */
#define RND_TYPE_FILE		2	/* Type is a file source */

/*
 * The random pool "taps"
 */
#define TAP1	99
#define TAP2	59
#define TAP3	31
#define TAP4	 9
#define TAP5	 7

static inline void
entropypool_add_word(isc_entropypool_t *, isc_uint32_t);

/*
 * Add one word to the pool, rotating the input as needed.
 */
static inline void
entropypool_add_word(isc_entropypool_t *rp, isc_uint32_t val)
{
	/*
	 * Steal some values out of the pool, and xor them into the
	 * word we were given.
	 *
	 * Mix the new value into the pool using xor.  This will
	 * prevent the actual values from being known to the caller
	 * since the previous values are assumed to be unknown as well.
	 */
	val ^= rp->pool[(rp->cursor + TAP1) & (RND_POOLWORDS - 1)];
	val ^= rp->pool[(rp->cursor + TAP2) & (RND_POOLWORDS - 1)];
	val ^= rp->pool[(rp->cursor + TAP3) & (RND_POOLWORDS - 1)];
	val ^= rp->pool[(rp->cursor + TAP4) & (RND_POOLWORDS - 1)];
	val ^= rp->pool[(rp->cursor + TAP5) & (RND_POOLWORDS - 1)];
	rp->pool[rp->cursor++] ^=
	  ((val << rp->rotate) | (val >> (32 - rp->rotate)));

	/*
	 * If we have looped around the pool, increment the rotate
	 * variable so the next value will get xored in rotated to
	 * a different position.
	 * Increment by a value that is relativly prime to the word size
	 * to try to spread the bits throughout the pool quickly when the
	 * pool is empty.
	 */
	if (rp->cursor == RND_POOLWORDS) {
		rp->cursor = 0;
		rp->rotate = (rp->rotate + 7) & 31;
	}
}

/*
 * add a buffer's worth of data to the pool.
 */
void
entropypool_adddata(isc_entropypool_t *rp, void *p, unsigned int len,
		    isc_uint32_t entropy)
{
	isc_uint32_t val;
	isc_uint32_t addr;
	isc_uint8_t *buf;

	addr = (isc_uint32_t)p;
	buf = p;

	if ((addr & 0x03) != 0) {
		val = 0;
		switch (len) {
		case 3:
			val = *buf++;
			len--;
		case 2:
			val = val << 8 | *buf++;
			len--;
		case 1:
			val = val << 8 | *buf++;
			len--;
		}

		entropypool_add_word(rp, val);
	}

	for (; len > 3 ; len -= 4) {
		val = *((isc_uint32_t *)buf);

		entropypool_add_word(rp, val);
		buf += 4;
	}

	if (len != 0) {
		val = 0;
		switch (len) {
		case 3:
			val = *buf++;
		case 2:
			val = val << 8 | *buf++;
		case 1:
			val = val << 8 | *buf++;
		}

		entropypool_add_word(rp, val);
	}

	rp->entropy += entropy;

	if (rp->entropy > RND_POOLBITS)
		rp->entropy = RND_POOLBITS;
}

/*
 * Extract some number of bytes from the random pool, decreasing the
 * estimate of randomness as each byte is extracted.
 *
 * Do this by stiring the pool and returning a part of hash as randomness.
 * Note that no secrets are given away here since parts of the hash are
 * xored together before returned.
 *
 * Honor the request from the caller to only return good data, any data,
 * etc.  Note that we must have at least 80 bits of entropy in the pool
 * before we return anything in the high-quality modes.
 */
int
entropypool_extract(isc_entropypool_t *rp, void *p, unsigned int len,
		    unsigned int mode)
{
	unsigned int i;
	isc_sha1_t hash;
	unsigned char digest[ISC_SHA1_DIGESTLENGTH];
	isc_uint32_t remain, deltae, count;
	isc_uint8_t *buf;
	int good;

	buf = p;
	remain = len;

	if ((mode & ISC_ENTROPY_GOODONLY) == 0)
		good = 1;
	else
		good = (rp->entropy >= (8 * RND_ENTROPY_THRESHOLD));

	while (good && (remain != 0)) {
		/*
		 * While bytes are requested, compute the hash of the pool,
		 * and then "fold" the hash in half with XOR, keeping the
		 * exact hash value secret, as it will be stirred back into
		 * the pool.
		 *
		 * XXX this approach needs examination by competant
		 * cryptographers!  It's rather expensive per bit but
		 * also involves every bit of the pool in the
		 * computation of every output bit..
		 */
		isc_sha1_init(&hash);
		isc_sha1_update(&hash, (unsigned char *)rp->pool,
				RND_POOLWORDS * 4);
		isc_sha1_final(&hash, digest);
    
		/*
		 * Stir the hash back into the pool.  This guarantees
		 * that the next hash will generate a different value
		 * if no new values were added to the pool.
		 */
		for (i = 0 ; i < 5 ; i++) {
			isc_uint32_t word;
			memcpy(&word, &digest[i * 4], 4);
			entropypool_add_word(rp, word);
		}

		count = ISC_MIN(remain, RND_ENTROPY_THRESHOLD);

		for (i = 0; i < count; i++)
			buf[i] = digest[i] ^ digest[ i +RND_ENTROPY_THRESHOLD];

		buf += count;
		deltae = count * 8;
		remain -= count;

		deltae = ISC_MIN(deltae, rp->entropy);

		rp->entropy -= deltae;

		if ((mode & ISC_ENTROPY_GOODONLY) == 0)
			good = (rp->entropy >= (8 * RND_ENTROPY_THRESHOLD));
	}
	
	memset(&hash, 0, sizeof(hash));
	memset(digest, 0, sizeof(digest));

	return (len - remain);
}

static void
isc_entropypool_init(isc_entropypool_t *pool) {
	pool->cursor = RND_POOLWORDS - 1;
	pool->entropy = 0;
	pool->rotate = 0;
	memset(pool->pool, 0, RND_POOLWORDS);
}

static void
isc_entropypool_invalidate(isc_entropypool_t *pool) {
	pool->cursor = 0;
	pool->entropy = 0;
	pool->rotate = 0;
	memset(pool->pool, 0, RND_POOLWORDS);
}

isc_result_t
isc_entropy_create(isc_mem_t *mctx, isc_entropy_t **entp) {
	isc_result_t ret;
	isc_entropy_t *ent;

	REQUIRE(mctx != NULL);
	REQUIRE(entp != NULL && *entp == NULL);

	ent = isc_mem_get(mctx, sizeof(isc_entropy_t));
	if (ent == NULL)
		return (ISC_R_NOMEMORY);

	/*
	 * We need a lock.
	 */
	if (isc_mutex_init(&ent->lock) != ISC_R_SUCCESS) {
		ret = ISC_R_UNEXPECTED;
		goto errout;
	}

	/*
	 * From here down, no failures will/can occur.
	 */
	ISC_LIST_INIT(ent->sources);
	ent->mctx = mctx;

	isc_entropypool_init(&ent->pool);

	*entp = ent;
	return (ISC_R_SUCCESS);

 errout:
	isc_mem_put(mctx, ent, sizeof(isc_entropy_t));

	return (ret);
}

void
isc_entropy_destroy(isc_entropy_t **entp) {
	isc_entropy_t *ent;

	REQUIRE(entp != NULL && *entp != NULL);

	ent = *entp;
	*entp = NULL;

	LOCK(&ent->lock);
	REQUIRE(ISC_LIST_EMPTY(ent->sources));

	isc_entropypool_invalidate(&ent->pool);

	UNLOCK(&ent->lock);

	isc_mutex_destroy(&ent->lock);

	memset(ent, 0, sizeof(isc_entropy_t));
}

isc_result_t
isc_entropy_createfilesource(isc_entropy_t *ent, const char *fname,
			     unsigned int flags,
			     isc_entropysource_t **sourcep)
{

	return (ISC_R_NOTIMPLEMENTED);
}

void
isc_entropy_destroysource(isc_entropysource_t **sourcep) {
}

isc_result_t
isc_entropy_createsamplesource(isc_entropy_t *ent,
			       isc_entropysource_t **sourcep)
{

	return (ISC_R_NOTIMPLEMENTED);
}

void
isc_entropy_addsample(isc_entropysource_t *source, isc_uint32_t sample,
		      isc_uint32_t extra, isc_boolean_t has_entropy)
{
}

isc_result_t
isc_entropy_getdata(isc_entropy_t *ent, void *data, unsigned int length,
		    unsigned int *returned, unsigned int flags)
{

	return (ISC_R_NOTIMPLEMENTED);
}
