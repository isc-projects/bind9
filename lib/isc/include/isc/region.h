/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#ifndef ISC_REGION_H
#define ISC_REGION_H 1

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

typedef struct isc_region {
	unsigned char *	base;
	unsigned int	length;
} isc_region_t;

typedef struct isc_textregion {
	char *		base;
	unsigned int	length;
} isc_textregion_t;

/*
 * The region structure is not opaque, and is usually directly manipulated.
 * Some macros are defined below for convenience.
 */

#define isc_region_consume(r,l) \
	do { \
		isc_region_t *__r = (r); \
		unsigned int __l = (l); \
		INSIST(__r->length >= __l); \
		__r->base += __l; \
		__r->length -= __l; \
	} while (0)

#define isc_textregion_consume(r,l) \
	do { \
		isc_textregion_t *__r = (r); \
		unsigned int __l = (l); \
		INSIST(__r->length >= __l); \
		__r->base += __l; \
		__r->length -= __l; \
	} while (0)

ISC_LANG_ENDDECLS

#endif /* ISC_REGION_H */
