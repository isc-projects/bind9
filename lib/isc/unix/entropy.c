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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

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

#define ISC_ENTROPY_MAGIC	ISC_MAGIC('E', 'n', 't', 

#define VALID_ENTROPY(e)	ISC_MAGIC_VALID(e, ISC_ENTROPY_MAGIC)
#define VALID_SOURCE(s)		((s) != NULL)

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
	isc_uint32_t	magic;
	isc_uint32_t	cursor;		/* current add point in the pool */
	isc_uint32_t	entropy;	/* current entropy estimate in bits */
	isc_uint32_t	pseudo;		/* bits extracted in pseudorandom */
	isc_uint32_t	rotate;		/* how many bits to rotate by */
	isc_uint32_t	pool[RND_POOLWORDS];	/* random pool data */
} isc_entropypool_t;

struct isc_entropy {
	isc_uint32_t			magic;
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
	isc_uint32_t	magic;
	unsigned int	type;
	isc_entropy_t  *ent;
	unsigned int	flags;		/* flags */
	isc_uint32_t	total;		/* entropy from this source */
	ISC_LINK(isc_entropysource_t)	link;
	char		name[32];
	union {
		isc_entropysamplesource_t	sample;
		isc_entropyfilesource_t		file;
	} sources;
};

#define ENTROPY_SOURCETYPE_SAMPLE	1	/* Type is a sample source */
#define ENTROPY_SOURCETYPE_FILE		2	/* Type is a file source */

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

static void
fillpool(isc_entropy_t *, unsigned int, isc_boolean_t);

#define ENTROPY(ent)	((ent)->pool.entropy)

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
 * Add a buffer's worth of data to the pool.
 *
 * Requires that the lock is held on the entropy pool.
 */
static void
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

	rp->entropy = ISC_MAX(rp->entropy + entropy, RND_POOLBITS);
}

static isc_uint32_t
get_from_filesource(isc_entropysource_t *source, isc_uint32_t desired) {
	isc_entropypool_t *pool = &source->ent->pool;
	unsigned char buf[128];
	int fd = source->sources.file.fd;
	ssize_t n, ndesired;
	u_int32_t added = 0;

	if (fd == -1)
		return (0);

	desired = desired / 8 + (((desired & 0x07) > 0) ? 1 : 0);

	while (desired > 0) {
		ndesired = ISC_MIN(desired, sizeof(buf));
		n = read(fd, buf, ndesired);
		if (n < 0) {
			if (errno == EAGAIN)
				goto out;
			close(fd);
			source->sources.file.fd = -1;
		}
		if (n == 0)
			goto out;

		entropypool_adddata(pool, buf, n, n * 8);
		added += n * 8;
		desired -= n;
	}

 out:
	return (added);
}

/*
 * Poll each source, trying to get data from it to stuff into the entropy
 * pool.
 */
static void
fillpool(isc_entropy_t *ent, unsigned int needed, isc_boolean_t blocking) {
	isc_uint32_t added, desired;
	isc_entropysource_t *source;

	REQUIRE(VALID_ENTROPY(ent));

	/*
	 * The best we can do is fill the pool.  Clamp to that.
	 */
	if (needed == 0 || (needed <= ent->pool.entropy)) {
		if ((ent->pool.entropy >= RND_POOLBITS / 4)
		    && (ent->pool.pseudo <= RND_POOLBITS / 4))
			return;
	}
	needed = ISC_MAX(needed, RND_ENTROPY_THRESHOLD * 8);
	needed = ISC_MIN(needed, RND_POOLBITS);
	if (!blocking)
		needed = ISC_MAX(needed, RND_POOLBITS / 4);

	/*
	 * Poll each file source to see if we can read anything useful from
	 * it.  XXXMLG When where are multiple sources, we should keep a
	 * record of which one we last used so we can start from it (or the
	 * next one) to avoid letting some sources build up entropy while
	 * others are always drained.
	 */

	source = ISC_LIST_HEAD(ent->sources);
	added = 0;
	while (source != NULL) {
		desired = ISC_MIN(needed, RND_POOLBITS - ent->pool.entropy);
		if (source->type == ENTROPY_SOURCETYPE_FILE)
			added += get_from_filesource(source, desired);

		if (added > needed)
			break;

		source = ISC_LIST_NEXT(source, link);
	}

	isc_entropy_stats(ent, stderr);
	fprintf(stderr, "fillpool:  needed %u, added %u\n",
		needed, added);
	isc_entropy_stats(ent, stderr);

	/*
	 * If we added any data, decrement the pseudo variable by
	 * how much we added.
	 */
	if (ent->pool.pseudo <= added)
		ent->pool.pseudo -= added;
	else
		ent->pool.pseudo = 0;

	/*
	 * Increment the amount of entropy we have in the pool.
	 */
	ent->pool.entropy = ISC_MIN(ent->pool.entropy + added, RND_POOLBITS);
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
 * etc.
 */
isc_result_t
isc_entropy_getdata(isc_entropy_t *ent, void *data, unsigned int length,
		    unsigned int *returned, unsigned int flags)
{
	unsigned int i;
	isc_sha1_t hash;
	unsigned char digest[ISC_SHA1_DIGESTLENGTH];
	isc_uint32_t remain, deltae, count, total;
	isc_uint8_t *buf;
	isc_boolean_t goodonly, partial, blocking;

	REQUIRE(VALID_ENTROPY(ent));
	REQUIRE(data != NULL);
	REQUIRE(length > 0);

	goodonly = ISC_TF((flags & ISC_ENTROPY_GOODONLY) != 0);
	partial = ISC_TF((flags & ISC_ENTROPY_PARTIAL) != 0);
	blocking = ISC_TF((flags & ISC_ENTROPY_BLOCKING) != 0);

	LOCK(&ent->lock);

	/*
	 * If we are blocking, we will block when actually extracting data.
	 * Otherwise, if we cannot block, there is a limit on how much data
	 * we can actually extract if good data is required.
	 *
	 * Here, clamp length to be the amount of data we can extract
	 * if goodonly and partial are both set, otherwise return an
	 * error.
	 */
	if (goodonly && !blocking) {
		fillpool(ent, length * 8, ISC_FALSE);

		/*
		 * To extract good data, we need to have at least
		 * enough entropy to fill our digest.
		 */
		if (ENTROPY(ent) < RND_ENTROPY_THRESHOLD * 8) {
			UNLOCK(&ent->lock);
			return (ISC_R_NOENTROPY);
		}
	}

	remain = length;
	buf = data;
	total = 0;
	while (remain != 0) {
		count = ISC_MIN(remain, RND_ENTROPY_THRESHOLD);

		/*
		 * If we are extracting good data only, make certain we
		 * have enough data in our pool for this pass.  If we don't,
		 * get some, and fail if we can't, and partial returns
		 * are not ok.
		 */
		if (goodonly) {
			fillpool(ent, (length - remain) * 8, blocking);
			if (!partial
			    && ((ENTROPY(ent) < count * 8)
				|| (ENTROPY(ent) < RND_ENTROPY_THRESHOLD * 8)))
				goto zeroize;
		} else {
			/*
			 * If we've extracted half our pool size in bits
			 * since the last refresh, try to refresh here.
			 */
			fillpool(ent, 0, ISC_FALSE);
		}

		isc_sha1_init(&hash);
		isc_sha1_update(&hash, (void *)(ent->pool.pool),
				RND_POOLWORDS * 4);
		isc_sha1_final(&hash, digest);
    
		/*
		 * Stir the extracted data (all of it) back into the pool.
		 */
		entropypool_adddata(&ent->pool, digest, ISC_SHA1_DIGESTLENGTH,
				    0);

		for (i = 0; i < count; i++)
			buf[i] = digest[i] ^ digest[i + RND_ENTROPY_THRESHOLD];

		buf += count;
		remain -= count;

		deltae = count * 8;
		deltae = ISC_MIN(deltae, ENTROPY(ent));
		ent->pool.entropy -= deltae;
		total += deltae;
	}

	ent->pool.pseudo = ISC_MIN(ent->pool.pseudo + total,
				   RND_POOLBITS * 16);

	memset(digest, 0, sizeof(digest));

	if (returned != NULL)
		*returned = (length - remain);

	UNLOCK(&ent->lock);
	isc_entropy_stats(ent, stderr);

	return (ISC_R_SUCCESS);

 zeroize:
	/* put the entropy we almost extracted back */
	ent->pool.entropy = ISC_MIN(ent->pool.entropy + total, RND_POOLBITS);
	memset(data, 0, length);
	memset(digest, 0, sizeof(digest));
	if (returned != NULL)
		*returned = 0;

	UNLOCK(&ent->lock);

	return (ISC_R_NOENTROPY);
}

static void
isc_entropypool_init(isc_entropypool_t *pool) {
	pool->cursor = RND_POOLWORDS - 1;
	pool->entropy = 0;
	pool->pseudo = 0;
	pool->rotate = 0;
	memset(pool->pool, 0, RND_POOLWORDS);
}

static void
isc_entropypool_invalidate(isc_entropypool_t *pool) {
	pool->cursor = 0;
	pool->entropy = 0;
	pool->pseudo = 0;
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
	ent->magic = ISC_ENTROPY_MAGIC;

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
	isc_mem_t *mctx;

	REQUIRE(entp != NULL && *entp != NULL);

	ent = *entp;
	*entp = NULL;

	LOCK(&ent->lock);
	REQUIRE(ISC_LIST_EMPTY(ent->sources));
	mctx = ent->mctx;

	isc_entropypool_invalidate(&ent->pool);

	UNLOCK(&ent->lock);

	isc_mutex_destroy(&ent->lock);

	memset(ent, 0, sizeof(isc_entropy_t));
	isc_mem_put(mctx, ent, sizeof(isc_entropy_t));
}

/*
 * Make a fd non-blocking
 */
static isc_result_t
make_nonblock(int fd) {
	int ret;
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);

	if (ret == -1) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "fcntl(%d, F_SETFL, %d): %s",
				 fd, flags, strerror(errno));

		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_entropy_createfilesource(isc_entropy_t *ent, const char *fname,
			     unsigned int flags,
			     isc_entropysource_t **sourcep)
{
	int fd;
	isc_result_t ret;
	isc_entropysource_t *source;

	REQUIRE(VALID_ENTROPY(ent));
	REQUIRE(fname != NULL);
	REQUIRE(sourcep != NULL && *sourcep == NULL);

	LOCK(&ent->lock);

	source = NULL;
	fd = -1;

	fd = open(fname, O_RDONLY | O_NONBLOCK, 0);
	if (fd < 0) {
		ret = ISC_R_IOERROR;
		goto errout;
	}

	ret = make_nonblock(fd);
	if (ret != ISC_R_SUCCESS)
		goto errout;

	source = isc_mem_get(ent->mctx, sizeof(isc_entropysource_t));
	if (source == NULL) {
		ret = ISC_R_NOMEMORY;
		goto errout;
	}

	/*
	 * From here down, no failures can occur.
	 */
	source->type = ENTROPY_SOURCETYPE_FILE;
	source->ent = ent;
	source->flags = flags;
	source->total = 0;
	memset(source->name, 0, sizeof(source->name));
	ISC_LINK_INIT(source, link);
	source->sources.file.fd = fd;

	/*
	 * Hook it into the entropy system.
	 */
	ISC_LIST_APPEND(ent->sources, source, link);

	*sourcep = source;

	UNLOCK(&ent->lock);
	return (ISC_R_SUCCESS);

 errout:
	if (source != NULL)
		isc_mem_put(ent->mctx, source, sizeof(isc_entropysource_t));
	if (fd >= 0)
		close(fd);

	UNLOCK(&ent->lock);

	return (ret);
}

void
isc_entropy_destroysource(isc_entropysource_t **sourcep) {
	isc_entropysource_t *source;
	isc_entropy_t *ent;
	void *ptr;
	int fd;

	REQUIRE(sourcep != NULL);
	REQUIRE(VALID_SOURCE(*sourcep));

	source = *sourcep;
	*sourcep = NULL;

	ent = source->ent;
	REQUIRE(VALID_ENTROPY(ent));

	LOCK(&ent->lock);

	ISC_LIST_UNLINK(ent->sources, source, link);

	switch (source->type) {
	case ENTROPY_SOURCETYPE_FILE:
		fd = source->sources.file.fd;
		if (fd >= 0)
			close(fd);
		break;
	case ENTROPY_SOURCETYPE_SAMPLE:
		ptr = source->sources.sample.samples;
		if (ptr != NULL)
			isc_mem_put(ent->mctx, ptr, RND_EVENTQSIZE * 4);
		ptr = source->sources.sample.extra;
		if (ptr != NULL)
			isc_mem_put(ent->mctx, ptr, RND_EVENTQSIZE * 4);
		break;
	}

	memset(source, 0, sizeof(isc_entropysource_t));

	isc_mem_put(ent->mctx, source, sizeof(isc_entropysource_t));

	UNLOCK(&ent->lock);
}

isc_result_t
isc_entropy_createsamplesource(isc_entropy_t *ent,
			       isc_entropysource_t **sourcep)
{

	return (ISC_R_NOTIMPLEMENTED);
}

void
isc_entropy_addsample(isc_entropysource_t *source, isc_uint32_t sample,
		      isc_uint32_t extra)
{
}

void
isc_entropy_stats(isc_entropy_t *ent, FILE *out) {
	fprintf(out, "Dump of entropy stats for pool %p\n", ent);
	fprintf(out, "\tcursor %u, rotate %u\n",
		ent->pool.cursor, ent->pool.rotate);
	fprintf(out, "\tentropy %u, pseudo %u\n",
		ent->pool.entropy, ent->pool.pseudo);
}
