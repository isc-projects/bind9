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
 * Size of the input event queue.  This _MUST_ be a power of 2.
 */
#define RND_EVENTQSIZE	128

typedef struct {
	isc_uint32_t	cursor;		/* current add point in the pool */
	isc_uint32_t	entropy;	/* current entropy estimate in bits */
	isc_uint32_t	rotate;		/* how many bits to rotate by */
	isc_uint32_t	pool[RND_POOLWORDS];	/* random pool data */
} isc_rndpool_t;

typedef struct {
	char            name[16];	/* device name */
	isc_uint32_t	last_time;	/* last time recorded */
	isc_uint32_t	last_delta;	/* last delta value */
	isc_uint32_t	last_delta2;	/* last delta2 value */
	isc_uint32_t	total;		/* entropy from this source */
	isc_uint32_t	type;		/* type */
	isc_uint32_t	flags;		/* flags */
	void	       *state;		/* state informaiton */
} isc_rndsource_t;

/*
 * Flags to control the source.  Low byte is type, upper bits are flags.
 */
#define RND_FLAG_NO_ESTIMATE	0x00000100	/* don't estimate entropy */
#define RND_FLAG_NO_COLLECT	0x00000200	/* don't collect entropy */

#define RND_TYPE_UNKNOWN	0	/* unknown source */
#define RND_TYPE_DISK		1	/* source is physical disk */
#define RND_TYPE_NET		2	/* source is a network device */
#define RND_TYPE_TAPE		3	/* source is a tape drive */
#define RND_TYPE_TTY		4	/* source is a tty device */
#define RND_TYPE_MAX		4	/* last type id used */

/*
 * Select "good" randomness or any at all (pseudorandom).
 */
#define RND_EXTRACT_ANY      0  /* Extract anything, even if no entropy */
#define RND_EXTRACT_GOOD     1  /* Return only good data */
