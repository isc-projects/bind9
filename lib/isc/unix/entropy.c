/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: entropy.c,v 1.54.2.4 2001/06/14 13:37:47 gson Exp $ */

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/list.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/msgs.h>
#include <isc/mutex.h>
#include <isc/platform.h>
#include <isc/region.h>
#include <isc/sha1.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#ifdef ISC_PLATFORM_NEEDSYSSELECTH
#include <sys/select.h>
#endif

/*
 * Much of this code is modeled after the NetBSD /dev/random implementation,
 * written by Michael Graff <explorer@netbsd.org>.
 */

#define ENTROPY_MAGIC		ISC_MAGIC('E', 'n', 't', 'e')
#define SOURCE_MAGIC		ISC_MAGIC('E', 'n', 't', 's')

#define VALID_ENTROPY(e)	ISC_MAGIC_VALID(e, ENTROPY_MAGIC)
#define VALID_SOURCE(s)		ISC_MAGIC_VALID(s, SOURCE_MAGIC)

/***
 *** "constants."  Do not change these unless you _really_ know what
 *** you are doing.
 ***/

/*
 * size of entropy pool in 32-bit words.  This _MUST_ be a power of 2.
 */
#define RND_POOLWORDS	128
#define RND_POOLBYTES	(RND_POOLWORDS * 4)
#define RND_POOLBITS	(RND_POOLWORDS * 32)

/*
 * Number of bytes returned per hash.  This must be true:
 *	threshold * 2 <= digest_size_in_bytes
 */
#define RND_ENTROPY_THRESHOLD	10
#define THRESHOLD_BITS		(RND_ENTROPY_THRESHOLD * 8)

/*
 * Size of the input event queue in samples.
 */
#define RND_EVENTQSIZE	32

/*
 * The number of times we'll "reseed" for pseudorandom seeds.  This is an
 * extremely weak pseudorandom seed.  If the caller is using lots of
 * pseudorandom data and they cannot provide a stronger random source,
 * there is little we can do other than hope they're smart enough to
 * call _adddata() with something better than we can come up with.
 */
#define RND_INITIALIZE	128

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
	isc_mem_t		       *mctx;
	isc_mutex_t			lock;
	unsigned int			refcnt;
	isc_uint32_t			initialized;
	isc_uint32_t			initcount;
	isc_entropypool_t		pool;
	unsigned int			nsources;
	isc_entropysource_t	       *nextsource;
	ISC_LIST(isc_entropysource_t)	sources;
};

typedef struct {
	isc_uint32_t	last_time;	/* last time recorded */
	isc_uint32_t	last_delta;	/* last delta value */
	isc_uint32_t	last_delta2;	/* last delta2 value */
	isc_uint32_t	nsamples;	/* number of samples filled in */
	isc_uint32_t   *samples;	/* the samples */
	isc_uint32_t   *extra;		/* extra samples added in */
} sample_queue_t;

typedef struct {
	sample_queue_t	samplequeue;
} isc_entropysamplesource_t;

typedef struct {
	isc_boolean_t		start_called;
	isc_entropystart_t	startfunc;
	isc_entropyget_t	getfunc;
	isc_entropystop_t	stopfunc;
	void		       *arg;
	sample_queue_t		samplequeue;
} isc_cbsource_t;

typedef struct {
	int		fd;		/* fd for the file, or -1 if closed */
} isc_entropyfilesource_t;

struct isc_entropysource {
	isc_uint32_t	magic;
	unsigned int	type;
	isc_entropy_t  *ent;
	isc_uint32_t	total;		/* entropy from this source */
	ISC_LINK(isc_entropysource_t)	link;
	char		name[32];
	isc_boolean_t	bad;
	union {
		isc_entropysamplesource_t	sample;
		isc_entropyfilesource_t		file;
		isc_cbsource_t			callback;
	} sources;
};

#define ENTROPY_SOURCETYPE_SAMPLE	1	/* Type is a sample source */
#define ENTROPY_SOURCETYPE_FILE		2	/* Type is a file source */
#define ENTROPY_SOURCETYPE_CALLBACK	3	/* Type is a callback source */

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

static int
wait_for_sources(isc_entropy_t *);

static unsigned int
crunchsamples(isc_entropy_t *, sample_queue_t *sq);

static inline void
reseed(isc_entropy_t *ent);

static void
samplequeue_release(isc_entropy_t *ent, sample_queue_t *sq) {
	REQUIRE(sq->samples != NULL);
	REQUIRE(sq->extra != NULL);

	isc_mem_put(ent->mctx, sq->samples, RND_EVENTQSIZE * 4);
	isc_mem_put(ent->mctx, sq->extra, RND_EVENTQSIZE * 4);
	sq->samples = NULL;
	sq->extra = NULL;
}

static isc_result_t
samplesource_allocate(isc_entropy_t *ent, sample_queue_t *sq) {
	sq->samples = isc_mem_get(ent->mctx, RND_EVENTQSIZE * 4);
	if (sq->samples == NULL)
		return (ISC_R_NOMEMORY);

	sq->extra = isc_mem_get(ent->mctx, RND_EVENTQSIZE * 4);
	if (sq->extra == NULL) {
		isc_mem_put(ent->mctx, sq->samples, RND_EVENTQSIZE * 4);
		sq->samples = NULL;
		return (ISC_R_NOMEMORY);
	}

	sq->nsamples = 0;

	return (ISC_R_SUCCESS);
}

/*
 * Add in entropy, even when the value we're adding in could be
 * very large.
 */
static inline void
add_entropy(isc_entropy_t *ent, isc_uint32_t entropy) {
	/* clamp input.  Yes, this must be done. */
	entropy = ISC_MIN(entropy, RND_POOLBITS);
	/* Add in the entropy we already have. */
	entropy += ent->pool.entropy;
	/* Clamp. */
	ent->pool.entropy = ISC_MIN(entropy, RND_POOLBITS);
}

/*
 * Decrement the amount of entropy the pool has.
 */
static inline void
subtract_entropy(isc_entropy_t *ent, isc_uint32_t entropy) {
	entropy = ISC_MIN(entropy, ent->pool.entropy);
	ent->pool.entropy -= entropy;
}

/*
 * Add in entropy, even when the value we're adding in could be
 * very large.
 */
static inline void
add_pseudo(isc_entropy_t *ent, isc_uint32_t pseudo) {
	/* clamp input.  Yes, this must be done. */
	pseudo = ISC_MIN(pseudo, RND_POOLBITS * 8);
	/* Add in the pseudo we already have. */
	pseudo += ent->pool.pseudo;
	/* Clamp. */
	ent->pool.pseudo = ISC_MIN(pseudo, RND_POOLBITS * 8);
}

/*
 * Decrement the amount of pseudo the pool has.
 */
static inline void
subtract_pseudo(isc_entropy_t *ent, isc_uint32_t pseudo) {
	pseudo = ISC_MIN(pseudo, ent->pool.pseudo);
	ent->pool.pseudo -= pseudo;
}

/*
 * Add one word to the pool, rotating the input as needed.
 */
static inline void
entropypool_add_word(isc_entropypool_t *rp, isc_uint32_t val) {
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
entropypool_adddata(isc_entropy_t *ent, void *p, unsigned int len,
		    isc_uint32_t entropy)
{
	isc_uint32_t val;
	unsigned long addr;
	isc_uint8_t *buf;

	addr = (unsigned long)p;
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

		entropypool_add_word(&ent->pool, val);
	}

	for (; len > 3 ; len -= 4) {
		val = *((isc_uint32_t *)buf);

		entropypool_add_word(&ent->pool, val);
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

		entropypool_add_word(&ent->pool, val);
	}

	add_entropy(ent, entropy);
	subtract_pseudo(ent, entropy);
}

static inline void
reseed(isc_entropy_t *ent) {
	isc_result_t result;
	isc_time_t t;
	pid_t pid;

	if (ent->initcount == 0) {
		pid = getpid();
		entropypool_adddata(ent, &pid, sizeof pid, 0);
		pid = getppid();
		entropypool_adddata(ent, &pid, sizeof pid, 0);
	}

	/*
	 * After we've reseeded 100 times, only add new timing info every
	 * 50 requests.  This will keep us from using lots and lots of
	 * CPU just to return bad pseudorandom data anyway.
	 */
	if (ent->initcount > 100)
		if ((ent->initcount % 50) != 0)
			return;

	result = isc_time_now(&t);
	if (result == ISC_R_SUCCESS) {
		entropypool_adddata(ent, &t, sizeof t, 0);
		ent->initcount++;
	}
}

static unsigned int
get_from_filesource(isc_entropysource_t *source, isc_uint32_t desired) {
	isc_entropy_t *ent = source->ent;
	unsigned char buf[128];
	int fd = source->sources.file.fd;
	ssize_t n, ndesired;
	unsigned int added;

	if (source->bad)
		return (0);

	desired = desired / 8 + (((desired & 0x07) > 0) ? 1 : 0);

	added = 0;
	while (desired > 0) {
		ndesired = ISC_MIN(desired, sizeof(buf));
		n = read(fd, buf, ndesired);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				goto out;
			close(fd);
			source->bad = ISC_TRUE;
			goto out;
		}
		if (n == 0) {
			close(fd);
			source->bad = ISC_TRUE;
			goto out;
		}

		entropypool_adddata(ent, buf, n, n * 8);
		added += n * 8;
		desired -= n;
	}

 out:
	return (added);
}

static unsigned int
get_from_callback(isc_entropysource_t *source, unsigned int desired,
		  isc_boolean_t blocking)
{
	isc_entropy_t *ent = source->ent;
	isc_cbsource_t *cbs = &source->sources.callback;
	unsigned int added;
	unsigned int got;
	isc_result_t result;

	if (desired == 0)
		return (0);

	if (source->bad)
		return (0);

	if (!cbs->start_called && cbs->startfunc != NULL) {
		result = cbs->startfunc(source, cbs->arg, blocking);
		if (result != ISC_R_SUCCESS)
			return (0);
		cbs->start_called = ISC_TRUE;
	}

	added = 0;
	result = ISC_R_SUCCESS;
	while (desired > 0 && result == ISC_R_SUCCESS) {
		result = cbs->getfunc(source, cbs->arg, blocking);
		if (result == ISC_R_QUEUEFULL) {
			got = crunchsamples(ent, &cbs->samplequeue);
			added += got;
			desired -= ISC_MIN(got, desired);
			result = ISC_R_SUCCESS;
		} else if (result != ISC_R_SUCCESS &&
			   result != ISC_R_NOTBLOCKING)
			source->bad = ISC_TRUE;

	}

	return (added);
}

/*
 * Poll each source, trying to get data from it to stuff into the entropy
 * pool.
 */
static void
fillpool(isc_entropy_t *ent, unsigned int desired, isc_boolean_t blocking) {
	unsigned int added;
	unsigned int remaining;
	unsigned int needed;
	unsigned int nsource;
	isc_entropysource_t *source;

	REQUIRE(VALID_ENTROPY(ent));

	needed = desired;

	/*
	 * This logic is a little strange, so an explanation is in order.
	 *
	 * If needed is 0, it means we are being asked to "fill to whatever
	 * we think is best."  This means that if we have at least a
	 * partially full pool (say, > 1/4th of the pool) we probably don't
	 * need to add anything.
	 *
	 * Also, we will check to see if the "pseudo" count is too high.
	 * If it is, try to mix in better data.  Too high is currently
	 * defined as 1/4th of the pool.
	 *
	 * Next, if we are asked to add a specific bit of entropy, make
	 * certain that we will do so.  Clamp how much we try to add to
	 * (DIGEST_SIZE * 8 < needed < POOLBITS - entropy).
	 *
	 * Note that if we are in a blocking mode, we will only try to
	 * get as much data as we need, not as much as we might want
	 * to build up.
	 */
	if (needed == 0) {
		REQUIRE(!blocking);

		if ((ent->pool.entropy >= RND_POOLBITS / 4)
		    && (ent->pool.pseudo <= RND_POOLBITS / 4))
			return;

		needed = THRESHOLD_BITS * 4;
	} else {
		needed = ISC_MAX(needed, THRESHOLD_BITS);
		needed = ISC_MIN(needed, RND_POOLBITS);
	}

	/*
	 * In any case, clamp how much we need to how much we can add.
	 */
	needed = ISC_MIN(needed, RND_POOLBITS - ent->pool.entropy);

	/*
	 * But wait!  If we're not yet initialized, we need at least
	 *	THRESHOLD_BITS
	 * of randomness.
	 */
	if (ent->initialized < THRESHOLD_BITS)
		needed = ISC_MAX(needed, THRESHOLD_BITS - ent->initialized);

	/*
	 * Poll each file source to see if we can read anything useful from
	 * it.  XXXMLG When where are multiple sources, we should keep a
	 * record of which one we last used so we can start from it (or the
	 * next one) to avoid letting some sources build up entropy while
	 * others are always drained.
	 */

	added = 0;
	remaining = needed;
	if (ent->nextsource == NULL) {
		ent->nextsource = ISC_LIST_HEAD(ent->sources);
		if (ent->nextsource == NULL)
			return;
	}
	source = ent->nextsource;
 again_file:
	for (nsource = 0 ; nsource < ent->nsources ; nsource++) {
		unsigned int got;

		if (remaining == 0)
			break;

		got = 0;

		if (source->type == ENTROPY_SOURCETYPE_FILE)
			got = get_from_filesource(source, remaining);

		added += got;

		remaining -= ISC_MIN(remaining, got);

		source = ISC_LIST_NEXT(source, link);
		if (source == NULL)
			source = ISC_LIST_HEAD(ent->sources);

#if 0
		if (added >= needed)
			break;
#endif
	}
	ent->nextsource = source;

	if (blocking && remaining != 0) {
		int fds;
		fds = wait_for_sources(ent);
		if (fds > 0)
			goto again_file;
	}

	/*
	 * Here, if there are bits remaining to be had and we can block,
	 * check to see if we have a callback source.  If so, call them.
	 */
	source = ISC_LIST_HEAD(ent->sources);
	while ((remaining != 0) && (source != NULL)) {
		unsigned int got;

		got = 0;

		if (source->type == ENTROPY_SOURCETYPE_CALLBACK)
			got = get_from_callback(source, remaining, blocking);

		added += got;
		remaining -= ISC_MIN(remaining, got);

		if (added >= needed)
			break;

		source = ISC_LIST_NEXT(source, link);
	}

	/*
	 * Mark as initialized if we've added enough data.
	 */
	if (ent->initialized < THRESHOLD_BITS)
		ent->initialized += added;
}

static int
wait_for_sources(isc_entropy_t *ent) {
	isc_entropysource_t *source;
	int maxfd, fd;
	int cc;
	fd_set reads;

	maxfd = -1;
	FD_ZERO(&reads);

	source = ISC_LIST_HEAD(ent->sources);
	while (source != NULL) {
		if (source->type == ENTROPY_SOURCETYPE_FILE) {
			fd = source->sources.file.fd;
			if (fd >= 0) {
				maxfd = ISC_MAX(maxfd, fd);
				FD_SET(fd, &reads);
			}
		}
		source = ISC_LIST_NEXT(source, link);
	}

	if (maxfd < 0)
		return (-1);

	cc = select(maxfd + 1, &reads, NULL, NULL, NULL);
	if (cc < 0)
		return (-1);

	return (cc);
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

	REQUIRE(!partial || returned != NULL);

	LOCK(&ent->lock);

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
			unsigned int fillcount;

			fillcount = ISC_MAX(remain * 8, count * 8);

			/*
			 * If, however, we have at least THRESHOLD_BITS
			 * of entropy in the pool, don't block here.  It is
			 * better to drain the pool once in a while and
			 * then refill it than it is to constantly keep the
			 * pool full.
			 */
			if (ent->pool.entropy >= THRESHOLD_BITS)
				fillpool(ent, fillcount, ISC_FALSE);
			else
				fillpool(ent, fillcount, blocking);

			/*
			 * Verify that we got enough entropy to do one
			 * extraction.  If we didn't, bail.
			 */
			if (ent->pool.entropy < THRESHOLD_BITS) {
				if (!partial)
					goto zeroize;
				else
					goto partial_output;
			}
		} else {
			/*
			 * If we've extracted half our pool size in bits
			 * since the last refresh, try to refresh here.
			 */
			if (ent->initialized < THRESHOLD_BITS)
				fillpool(ent, THRESHOLD_BITS, blocking);
			else
				fillpool(ent, 0, ISC_FALSE);

			/*
			 * If we've not initialized with enough good random
			 * data, seed with our crappy code.
			 */
			if (ent->initialized < THRESHOLD_BITS)
				reseed(ent);
		}

		isc_sha1_init(&hash);
		isc_sha1_update(&hash, (void *)(ent->pool.pool),
				RND_POOLBYTES);
		isc_sha1_final(&hash, digest);

		/*
		 * Stir the extracted data (all of it) back into the pool.
		 */
		entropypool_adddata(ent, digest, ISC_SHA1_DIGESTLENGTH, 0);

		for (i = 0; i < count; i++)
			buf[i] = digest[i] ^ digest[i + RND_ENTROPY_THRESHOLD];

		buf += count;
		remain -= count;

		deltae = count * 8;
		deltae = ISC_MIN(deltae, ent->pool.entropy);
		total += deltae;
		subtract_entropy(ent, deltae);
		add_pseudo(ent, count * 8);
	}

 partial_output:
	memset(digest, 0, sizeof(digest));

	if (returned != NULL)
		*returned = (length - remain);

	UNLOCK(&ent->lock);

	return (ISC_R_SUCCESS);

 zeroize:
	/* put the entropy we almost extracted back */
	add_entropy(ent, total);
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
	memset(pool->pool, 0, RND_POOLBYTES);
}

static void
isc_entropypool_invalidate(isc_entropypool_t *pool) {
	pool->cursor = 0;
	pool->entropy = 0;
	pool->pseudo = 0;
	pool->rotate = 0;
	memset(pool->pool, 0, RND_POOLBYTES);
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
	ent->nextsource = NULL;
	ent->nsources = 0;
	ent->mctx = NULL;
	isc_mem_attach(mctx, &ent->mctx);
	ent->refcnt = 1;
	ent->initialized = 0;
	ent->initcount = 0;
	ent->magic = ENTROPY_MAGIC;

	isc_entropypool_init(&ent->pool);

	*entp = ent;
	return (ISC_R_SUCCESS);

 errout:
	isc_mem_put(mctx, ent, sizeof(isc_entropy_t));

	return (ret);
}

/*
 * Requires "ent" be locked.
 */
static void
destroysource(isc_entropysource_t **sourcep) {
	isc_entropysource_t *source;
	isc_entropy_t *ent;
	isc_cbsource_t *cbs;
	int fd;

	source = *sourcep;
	*sourcep = NULL;
	ent = source->ent;

	ISC_LIST_UNLINK(ent->sources, source, link);
	ent->nextsource = NULL;
	REQUIRE(ent->nsources > 0);
	ent->nsources--;

	switch (source->type) {
	case ENTROPY_SOURCETYPE_FILE:
		fd = source->sources.file.fd;
		if (!source->bad)
			close(fd);
		break;
	case ENTROPY_SOURCETYPE_SAMPLE:
		samplequeue_release(ent, &source->sources.sample.samplequeue);
		break;
	case ENTROPY_SOURCETYPE_CALLBACK:
		cbs = &source->sources.callback;
		if (cbs->start_called && cbs->stopfunc != NULL) {
			cbs->stopfunc(source, cbs->arg);
			cbs->start_called = ISC_FALSE;
		}
		samplequeue_release(ent, &cbs->samplequeue);
		break;
	}

	memset(source, 0, sizeof(isc_entropysource_t));

	isc_mem_put(ent->mctx, source, sizeof(isc_entropysource_t));
}

static inline isc_boolean_t
destroy_check(isc_entropy_t *ent) {
	isc_entropysource_t *source;

	if (ent->refcnt > 0)
		return (ISC_FALSE);

	source = ISC_LIST_HEAD(ent->sources);
	while (source != NULL) {
		switch (source->type) {
		case ENTROPY_SOURCETYPE_FILE:
			break;
		default:
			return (ISC_FALSE);
		}
		source = ISC_LIST_NEXT(source, link);
	}

	return (ISC_TRUE);
}

static void
destroy(isc_entropy_t **entp) {
	isc_entropy_t *ent;
	isc_entropysource_t *source;
	isc_mem_t *mctx;

	REQUIRE(entp != NULL && *entp != NULL);
	ent = *entp;
	*entp = NULL;

	LOCK(&ent->lock);

	REQUIRE(ent->refcnt == 0);

	/*
	 * Here, detach non-sample sources.
	 */
	source = ISC_LIST_HEAD(ent->sources);
	while (source != NULL) {
		switch(source->type) {
		case ENTROPY_SOURCETYPE_FILE:
			destroysource(&source);
			break;
		}
		source = ISC_LIST_HEAD(ent->sources);
	}

	/*
	 * If there are other types of sources, we've found a bug.
	 */
	REQUIRE(ISC_LIST_EMPTY(ent->sources));

	mctx = ent->mctx;

	isc_entropypool_invalidate(&ent->pool);

	UNLOCK(&ent->lock);

	DESTROYLOCK(&ent->lock);

	memset(ent, 0, sizeof(isc_entropy_t));
	isc_mem_put(mctx, ent, sizeof(isc_entropy_t));
	isc_mem_detach(&mctx);
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
isc_entropy_createfilesource(isc_entropy_t *ent, const char *fname) {
	int fd;
	isc_result_t ret;
	isc_entropysource_t *source;

	REQUIRE(VALID_ENTROPY(ent));
	REQUIRE(fname != NULL);

	LOCK(&ent->lock);

	source = NULL;

	fd = open(fname, O_RDONLY | O_NONBLOCK, 0);
	if (fd < 0) {
		ret = ISC_R_IOERROR;
		goto errout;
	}
	ret = make_nonblock(fd);
	if (ret != ISC_R_SUCCESS)
		goto closefd;

	source = isc_mem_get(ent->mctx, sizeof(isc_entropysource_t));
	if (source == NULL) {
		ret = ISC_R_NOMEMORY;
		goto closefd;
	}

	/*
	 * From here down, no failures can occur.
	 */
	source->magic = SOURCE_MAGIC;
	source->type = ENTROPY_SOURCETYPE_FILE;
	source->ent = ent;
	source->total = 0;
	source->bad = ISC_FALSE;
	memset(source->name, 0, sizeof(source->name));
	ISC_LINK_INIT(source, link);
	source->sources.file.fd = fd;

	/*
	 * Hook it into the entropy system.
	 */
	ISC_LIST_APPEND(ent->sources, source, link);
	ent->nsources++;

	UNLOCK(&ent->lock);
	return (ISC_R_SUCCESS);

 closefd:
	close(fd);

 errout:
	if (source != NULL)
		isc_mem_put(ent->mctx, source, sizeof(isc_entropysource_t));

	UNLOCK(&ent->lock);

	return (ret);
}

void
isc_entropy_destroysource(isc_entropysource_t **sourcep) {
	isc_entropysource_t *source;
	isc_entropy_t *ent;
	isc_boolean_t killit;

	REQUIRE(sourcep != NULL);
	REQUIRE(VALID_SOURCE(*sourcep));

	source = *sourcep;
	*sourcep = NULL;

	ent = source->ent;
	REQUIRE(VALID_ENTROPY(ent));

	LOCK(&ent->lock);

	destroysource(&source);

	killit = destroy_check(ent);

	UNLOCK(&ent->lock);

	if (killit)
		destroy(&ent);
}

isc_result_t
isc_entropy_createcallbacksource(isc_entropy_t *ent,
				 isc_entropystart_t start,
				 isc_entropyget_t get,
				 isc_entropystop_t stop,
				 void *arg,
				 isc_entropysource_t **sourcep)
{
	isc_result_t ret;
	isc_entropysource_t *source;
	isc_cbsource_t *cbs;

	REQUIRE(VALID_ENTROPY(ent));
	REQUIRE(get != NULL);
	REQUIRE(sourcep != NULL && *sourcep == NULL);

	LOCK(&ent->lock);

	source = isc_mem_get(ent->mctx, sizeof(isc_entropysource_t));
	if (source == NULL) {
		ret = ISC_R_NOMEMORY;
		goto errout;
	}
	source->bad = ISC_FALSE;

	cbs = &source->sources.callback;

	ret = samplesource_allocate(ent, &cbs->samplequeue);
	if (ret != ISC_R_SUCCESS)
		goto errout;

	cbs->start_called = ISC_FALSE;
	cbs->startfunc = start;
	cbs->getfunc = get;
	cbs->stopfunc = stop;
	cbs->arg = arg;

	/*
	 * From here down, no failures can occur.
	 */
	source->magic = SOURCE_MAGIC;
	source->type = ENTROPY_SOURCETYPE_CALLBACK;
	source->ent = ent;
	source->total = 0;
	memset(source->name, 0, sizeof(source->name));
	ISC_LINK_INIT(source, link);

	/*
	 * Hook it into the entropy system.
	 */
	ISC_LIST_APPEND(ent->sources, source, link);
	ent->nsources++;

	*sourcep = source;

	UNLOCK(&ent->lock);
	return (ISC_R_SUCCESS);

 errout:
	if (source != NULL)
		isc_mem_put(ent->mctx, source, sizeof(isc_entropysource_t));

	UNLOCK(&ent->lock);

	return (ret);
}

void
isc_entropy_stopcallbacksources(isc_entropy_t *ent) {
	isc_entropysource_t *source;
	isc_cbsource_t *cbs;

	REQUIRE(VALID_ENTROPY(ent));

	LOCK(&ent->lock);

	source = ISC_LIST_HEAD(ent->sources);
	while (source != NULL) {
		if (source->type == ENTROPY_SOURCETYPE_CALLBACK) {
			cbs = &source->sources.callback;
			if (cbs->start_called && cbs->stopfunc != NULL) {
				cbs->stopfunc(source, cbs->arg);
				cbs->start_called = ISC_FALSE;
			}
		}

		source = ISC_LIST_NEXT(source, link);
	}

	UNLOCK(&ent->lock);
}

isc_result_t
isc_entropy_createsamplesource(isc_entropy_t *ent,
			       isc_entropysource_t **sourcep)
{
	isc_result_t ret;
	isc_entropysource_t *source;
	sample_queue_t *sq;

	REQUIRE(VALID_ENTROPY(ent));
	REQUIRE(sourcep != NULL && *sourcep == NULL);

	LOCK(&ent->lock);

	source = isc_mem_get(ent->mctx, sizeof(isc_entropysource_t));
	if (source == NULL) {
		ret = ISC_R_NOMEMORY;
		goto errout;
	}

	sq = &source->sources.sample.samplequeue;
	ret = samplesource_allocate(ent, sq);
	if (ret != ISC_R_SUCCESS)
		goto errout;

	/*
	 * From here down, no failures can occur.
	 */
	source->magic = SOURCE_MAGIC;
	source->type = ENTROPY_SOURCETYPE_SAMPLE;
	source->ent = ent;
	source->total = 0;
	memset(source->name, 0, sizeof(source->name));
	ISC_LINK_INIT(source, link);

	/*
	 * Hook it into the entropy system.
	 */
	ISC_LIST_APPEND(ent->sources, source, link);
	ent->nsources++;

	*sourcep = source;

	UNLOCK(&ent->lock);
	return (ISC_R_SUCCESS);

 errout:
	if (source != NULL)
		isc_mem_put(ent->mctx, source, sizeof(isc_entropysource_t));

	UNLOCK(&ent->lock);

	return (ret);
}

static inline unsigned int
estimate_entropy(sample_queue_t *sq, isc_uint32_t t)
{
	isc_int32_t		delta;
	isc_int32_t		delta2;
	isc_int32_t		delta3;

	/*
	 * If the time counter has overflowed, calculate the real difference.
	 * If it has not, it is simplier.
	 */
	if (t < sq->last_time)
		delta = UINT_MAX - sq->last_time + t;
	else
		delta = sq->last_time - t;

	if (delta < 0)
		delta = -delta;

	/*
	 * Calculate the second and third order differentials
	 */
	delta2 = sq->last_delta - delta;
	if (delta2 < 0)
		delta2 = -delta2;

	delta3 = sq->last_delta2 - delta2;
	if (delta3 < 0)
		delta3 = -delta3;

	sq->last_time = t;
	sq->last_delta = delta;
	sq->last_delta2 = delta2;

	/*
	 * If any delta is 0, we got no entropy.  If all are non-zero, we
	 * might have something.
	 */
	if (delta == 0 || delta2 == 0 || delta3 == 0)
		return 0;

	/*
	 * We could find the smallest delta and claim we got log2(delta)
	 * bits, but for now return that we found 1 bit.
	 */
	return 1;
}

static unsigned int
crunchsamples(isc_entropy_t *ent, sample_queue_t *sq) {
	unsigned int ns;
	unsigned int added;

	if (sq->nsamples < 6)
		return (0);

	added = 0;
	sq->last_time = sq->samples[0];
	sq->last_delta = 0;
	sq->last_delta2 = 0;

	/*
	 * Prime the values by adding in the first 4 samples in.  This
	 * should completely initialize the delta calculations.
	 */
	for (ns = 0 ; ns < 4 ; ns++)
		(void)estimate_entropy(sq, sq->samples[ns]);

	for (ns = 4 ; ns < sq->nsamples ; ns++)
		added += estimate_entropy(sq, sq->samples[ns]);

	entropypool_adddata(ent, sq->samples, sq->nsamples * 4, added);
	entropypool_adddata(ent, sq->extra, sq->nsamples * 4, 0);

	/*
	 * Move the last 4 samples into the first 4 positions, and start
	 * adding new samples from that point.
	 */
	for (ns = 0 ; ns < 4 ; ns++) {
		sq->samples[ns] = sq->samples[sq->nsamples - 4 + ns];
		sq->extra[ns] = sq->extra[sq->nsamples - 4 + ns];
	}

	sq->nsamples = 4;

	return (added);
}

/*
 * Add a sample, and return ISC_R_SUCCESS if the queue has become full,
 * ISC_R_NOENTROPY if it has space remaining, and ISC_R_NOMORE if the
 * queue was full when this function was called.
 */
static isc_result_t
addsample(sample_queue_t *sq, isc_uint32_t sample, isc_uint32_t extra) {
	if (sq->nsamples >= RND_EVENTQSIZE)
		return (ISC_R_NOMORE);

	sq->samples[sq->nsamples] = sample;
	sq->extra[sq->nsamples] = extra;
	sq->nsamples++;

	if (sq->nsamples >= RND_EVENTQSIZE)
		return (ISC_R_QUEUEFULL);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_entropy_addsample(isc_entropysource_t *source, isc_uint32_t sample,
		      isc_uint32_t extra)
{
	isc_entropy_t *ent;
	sample_queue_t *sq;
	unsigned int entropy;
	isc_result_t result;

	REQUIRE(VALID_SOURCE(source));

	ent = source->ent;

	LOCK(&ent->lock);

	sq = &source->sources.sample.samplequeue;
	result = addsample(sq, sample, extra);
	if (result == ISC_R_QUEUEFULL) {
		entropy = crunchsamples(ent, sq);
		add_entropy(ent, entropy);
	}

	UNLOCK(&ent->lock);

	return (result);
}

isc_result_t
isc_entropy_addcallbacksample(isc_entropysource_t *source, isc_uint32_t sample,
			      isc_uint32_t extra)
{
	sample_queue_t *sq;
	isc_result_t result;

	REQUIRE(VALID_SOURCE(source));
	REQUIRE(source->type == ENTROPY_SOURCETYPE_CALLBACK);

	sq = &source->sources.callback.samplequeue;
	result = addsample(sq, sample, extra);

	return (result);
}

void
isc_entropy_putdata(isc_entropy_t *ent, void *data, unsigned int length,
		    isc_uint32_t entropy)
{
	REQUIRE(VALID_ENTROPY(ent));

	LOCK(&ent->lock);

	entropypool_adddata(ent, data, length, entropy);

	if (ent->initialized < THRESHOLD_BITS)
		ent->initialized = THRESHOLD_BITS;

	UNLOCK(&ent->lock);
}

static void
dumpstats(isc_entropy_t *ent, FILE *out) {
	fprintf(out,
		isc_msgcat_get(isc_msgcat, ISC_MSGSET_ENTROPY,
			       ISC_MSG_ENTROPYSTATS,
			       "Entropy pool %p:  refcnt %u cursor %u,"
			       " rotate %u entropy %u pseudo %u nsources %u"
			       " nextsource %p initialized %u initcount %u\n"),
		ent, ent->refcnt,
		ent->pool.cursor, ent->pool.rotate,
		ent->pool.entropy, ent->pool.pseudo,
		ent->nsources, ent->nextsource, ent->initialized,
		ent->initcount);
}

/*
 * This function ignores locking.  Use at your own risk.
 */
void
isc_entropy_stats(isc_entropy_t *ent, FILE *out) {
	REQUIRE(VALID_ENTROPY(ent));

	LOCK(&ent->lock);
	dumpstats(ent, out);
	UNLOCK(&ent->lock);
}

void
isc_entropy_attach(isc_entropy_t *ent, isc_entropy_t **entp) {
	REQUIRE(VALID_ENTROPY(ent));
	REQUIRE(entp != NULL && *entp == NULL);

	LOCK(&ent->lock);

	ent->refcnt++;
	*entp = ent;

	UNLOCK(&ent->lock);
}

void
isc_entropy_detach(isc_entropy_t **entp) {
	isc_entropy_t *ent;
	isc_boolean_t killit;

	REQUIRE(entp != NULL && VALID_ENTROPY(*entp));
	ent = *entp;
	*entp = NULL;

	LOCK(&ent->lock);

	REQUIRE(ent->refcnt > 0);
	ent->refcnt--;

	killit = destroy_check(ent);

	UNLOCK(&ent->lock);

	if (killit)
		destroy(&ent);
}
