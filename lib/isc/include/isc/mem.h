/*
 * Copyright (C) 1997, 1998  Internet Software Consortium.
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

#ifndef ISC_MEM_H
#define ISC_MEM_H 1

#include <stdio.h>
#include <stddef.h>

#include <isc/boolean.h>
#include <isc/result.h>

typedef struct isc_mem		isc_mem_t;

#ifdef ISC_MEM_DEBUG
#define isc_mem_get(c, s)	__isc_mem_getdebug(c, s, __FILE__, __LINE__)
#define isc_mem_put(c, p, s)	__isc_mem_putdebug(c, p, s, __FILE__, __LINE__)
#else
#define isc_mem_get		__isc_mem_get
#define isc_mem_put		__isc_mem_put
#endif /* ISC_MEM_DEBUG */

isc_result_t			isc_mem_create(size_t, size_t, isc_mem_t **);
void				isc_mem_destroy(isc_mem_t **);
void *				__isc_mem_get(isc_mem_t *, size_t);
void 				__isc_mem_put(isc_mem_t *, void *, size_t);
void *				__isc_mem_getdebug(isc_mem_t *, size_t,
						   const char *, int);
void 				__isc_mem_putdebug(isc_mem_t *, void *,
						   size_t, const char *, int);
void 				isc_mem_stats(isc_mem_t *, FILE *);
isc_boolean_t			isc_mem_valid(isc_mem_t *, void *);
void *				isc_mem_allocate(isc_mem_t *, size_t);
void				isc_mem_free(isc_mem_t *, void *);
char *				isc_mem_strdup(isc_mem_t *, const char *);

#ifdef ISC_MEMCLUSTER_LEGACY

/*
 * Legacy.
 */

#define meminit			__meminit
#define mem_default_context	__mem_default_context
#ifdef MEMCLUSTER_DEBUG
#define memget(s)		__memget_debug(s, __FILE__, __LINE__)
#define memput(p, s)		__memput_debug(p, s, __FILE__, __LINE__)
#else
#define memget			__memget
#define memput			__memput
#endif
#define memvalid		__memvalid
#define memstats		__memstats

int				meminit(size_t, size_t);
isc_mem_t *			mem_default_context(void);
void *				__memget(size_t);
void 				__memput(void *, size_t);
void *				__memget_debug(size_t, const char *, int);
void				__memput_debug(void *, size_t, const char *,
					       int);
int				memvalid(void *);
void 				memstats(FILE *);

#endif /* ISC_MEMCLUSTER_LEGACY */

#endif /* MEM_H */
