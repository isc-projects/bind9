/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <dns/types.h>

#define DNS_COMPRESS_GLOBAL14		0x01	/* "normal" compression. */
#define DNS_COMPRESS_GLOBAL16		0x02	/* 16-bit global comp. */
#define DNS_COMPRESS_LOCAL		0x04	/* Local compression. */

/*
 * XXX  An API for manipulating these structures will be forthcoming.
 *	Also magic numbers, _init() and _invalidate(), etc.  At that time,
 *	direct manipulation of the structures will be strongly discouraged.
 */

struct dns_compress {
	unsigned int allowed;			/* Allowed methods. */
	dns_name_t owner_name;			/* For local compression. */
	/* XXX compression table here */
};

struct dns_decompress {
	unsigned int allowed;			/* Allowed methods. */
	dns_name_t owner_name;			/* For local compression. */
};

#endif /* DNS_COMPRESS_H */
