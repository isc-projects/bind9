/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#ifndef DNS_COMPRESS_H
#define DNS_COMPRESS_H 1

#include <isc/mem.h>
#include <isc/lang.h>

#include <dns/types.h>
#include <dns/rbt.h>

ISC_LANG_BEGINDECLS

#define DNS_COMPRESS_NONE		0x00	/* no compression */
#define DNS_COMPRESS_GLOBAL14		0x01	/* "normal" compression. */
#define DNS_COMPRESS_GLOBAL16		0x02	/* 16-bit edns global comp. */
#define DNS_COMPRESS_GLOBAL		0x03	/* all global comp. */
/*
 * Synonymous with DNS_COMPRESS_GLOBAL.  A genuine difference existed when
 * local compression was an IETF draft, but that draft has been retired without
 * becoming a standard.  Numerous bits of code referred to DNS_COMPRESS_ALL
 * already, and rather than change them all, the DNS_COMPRESS_ALL definition
 * was left in, but no longer refers to local compression.
 */
#define DNS_COMPRESS_ALL		0x03	/* all compression. */


/*
 * XXX  An API for manipulating these structures will be forthcoming.
 *	Also magic numbers, _init() and _invalidate(), etc.  At that time,
 *	direct manipulation of the structures will be strongly discouraged.
 */

struct dns_compress {
	unsigned int	magic;			/* Magic number. */
	unsigned int	allowed;		/* Allowed methods. */
	unsigned int	rdata;			/* Start of local rdata. */
	isc_boolean_t	global16;		/* 16 bit offsets allowed. */
	int		edns;			/* Edns version or -1. */
	dns_rbt_t	*global;		/* Global RBT. */
	isc_mem_t	*mctx;			/* Memeory context. */
};

struct dns_decompress {
	unsigned int	magic;			/* Magic number. */
	unsigned int	allowed;		/* Allowed methods. */
	unsigned int	rdata;			/* Start of local rdata. */
	int		edns;			/* Edns version or -1. */
	isc_boolean_t	strict;			/* Strict checking */
};

isc_result_t dns_compress_init(dns_compress_t *cctx, int edns,
			       isc_mem_t *mctx);
/*
 *	Inialise the compression context structure pointed to by 'cctx'.
 *
 *	Requires:
 *		'cctx' is a valid dns_compress_t structure.
 *		'mctx' is a initalised memory context.
 *	Ensures:
 *		cctx->global is initalised.
 *
 *	Returns:
 *		DNS_R_SUCCESS
 *		failures from dns_rbt_create()
 */

void
dns_compress_invalidate(dns_compress_t *cctx);

/*
 *	Invalidate the compression structure pointed to by cctx.
 *	Destroys 'cctx->glocal' and 'cctx->local' RBT.
 *
 *	Requires:
 *		'cctx' to be initalised.
 */

void
dns_compress_setmethods(dns_compress_t *cctx, unsigned int allowed);

/*
 *	Sets allowed compression methods.
 *
 *	Requires:
 *		'cctx' to be initalised.
 */

unsigned int
dns_compress_getmethods(dns_compress_t *cctx);

/*
 *	Gets allowed compression methods.
 *
 *	Requires:
 *		'cctx' to be initalised.
 *
 *	Returns:
 *		allowed compression bitmap.
 */

int
dns_compress_getedns(dns_compress_t *cctx);

/*
 *	Gets edns value.
 *
 *	Requires:
 *		'cctx' to be initalised.
 *
 *	Returns:
 *		-1 .. 255
 */

isc_boolean_t
dns_compress_findglobal(dns_compress_t *cctx, dns_name_t *name,
			dns_name_t *prefix, dns_name_t *suffix,
			isc_uint16_t *offset, isc_buffer_t *workspace);
/*
 *	Finds longest possible match of 'name' in the global compression
 *	RBT.  Workspace needs to be large enough to hold 'name' when split
 *	in two (length->name + 3).
 *
 *	Requires:
 *		'cctx' to be initalised.
 *		'name' to be a absolute name.
 *		'prefix' to be initalised.
 *		'suffix' to be initalised.
 *		'offset' to point it a isc_uint16_t.
 *		'workspace' to be initalised.
 *
 *	Ensures:
 *		'prefix', 'suffix' and 'offset' are valid if ISC_TRUE is
 *		returned.
 *
 *	Returns:
 *		ISC_TRUE / ISC_FALSE
 */

void
dns_compress_add(dns_compress_t *cctx, dns_name_t *prefix,
		 dns_name_t *suffix, isc_uint16_t offset);
/*
 *	Add compression pointers for labels in prefix to RBT's.
 *	If 'prefix' is absolute 'suffix' must be NULL otherwise
 *	suffix must be absolute.
 *
 *	Requires:
 *		'cctx' initalised
 *		'prefix' to be initalised
 *		'suffix' to be initalised or NULL
 */

void
dns_compress_rollback(dns_compress_t *cctx, isc_uint16_t offset);

/*
 *	Remove any compression pointers from global RBT >= offset.
 *
 *	Requires:
 *		'cctx' is initalised.
 */

void
dns_decompress_init(dns_decompress_t *dctx, int edns, isc_boolean_t strict);

/*
 *	Initalises 'dctx'.
 *	Records 'edns' and 'strict' into the structure.
 *
 *	Requires:
 *		'dctx' to be a valid pointer.
 */

void
dns_decompress_invalidate(dns_decompress_t *dctx);

/*
 *	Invalidates 'dctx'.
 *
 *	Requires:
 *		'dctx' to be initalised
 */

void
dns_decompress_setmethods(dns_decompress_t *dctx, unsigned int allowed);

/*
 *	Sets 'dctx->allowed' to 'allowed'.
 *
 *	Requires:
 *		'dctx' to be initalised
 */

unsigned int
dns_decompress_getmethods(dns_decompress_t *dctx);

/*
 *	Returns 'dctx->allowed'
 *
 *	Requires:
 *		'dctx' to be initalised
 */

int
dns_decompress_edns(dns_decompress_t *dctx);

/*
 *	Returns 'dctx->edns'
 *
 *	Requires:
 *		'dctx' to be initalised
 */

isc_boolean_t
dns_decompress_strict(dns_decompress_t *dctx);

/*
 *	Returns 'dctx->strict'
 *
 *	Requires:
 *		'dctx' to be initalised
 */

ISC_LANG_ENDDECLS

#endif /* DNS_COMPRESS_H */
