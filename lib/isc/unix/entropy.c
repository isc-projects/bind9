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
#include <isc/region.h>
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
 * Number of bytes returned per hash.
 */
#define RND_ENTROPY_THRESHOLD	12

/*
 * Size of the input event queue.
 */
#define RND_EVENTQSIZE	128

typedef struct {
	isc_uint32_t	cursor;		/* current add point in the pool */
	isc_uint32_t	entropy;	/* current entropy estimate in bits */
	isc_uint32_t	rotate;		/* how many bits to rotate by */
	isc_uint32_t	pool[RND_POOLWORDS];	/* random pool data */
} isc_rndpool_t;

typedef struct {
	isc_uint32_t	last_time;	/* last time recorded */
	isc_uint32_t	last_delta;	/* last delta value */
	isc_uint32_t	last_delta2;	/* last delta2 value */
	isc_uint32_t	entropy;	/* entropy believed to be in samples */
	isc_uint32_t	nsamples;	/* number of samples filled in */
	isc_uint32_t   *samples;	/* the samples */
	isc_uint32_t   *extra;		/* extra samples added in */
} isc_rndsamplesource_t;

typedef struct {
	int		fd;		/* fd for the file, or -1 if closed */
} isc_rndfilesource_t;

typedef struct {
	unsigned int	type;
	unsigned int	flags;		/* flags */
	isc_uint32_t	total;		/* entropy from this source */
	char		name[32];
	union {
		isc_rndsamplesource_t	samplesource;
		isc_rndfilesource_t	filesource;
	} sources;
} isc_rndsource_t;

#define RND_TYPE_SAMPLE		1	/* Type is a sample source */
#define RND_TYPE_FILE		2	/* Type is a file source */

isc_result_t
isc_entropy_create(isc_mem_t *mctx, isc_entropy_t **entp) {
}

isc_result_t
isc_entropy_destroy(isc_entropy_t **entp) {
}

isc_result_t
isc_entropy_createfilesource(isc_entropy_t *ent, const char *fname,
			     unsigned int flags,
			     isc_entropysource_t **sourcep)
{
}

isc_result_t
isc_entropy_destroysource(isc_entropysource_t **sourcep) {
}

isc_result_t
isc_entropy_createsamplesource(isc_entropy_t *ent,
			       isc_entropysource_t **sourcep)
{
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
}
