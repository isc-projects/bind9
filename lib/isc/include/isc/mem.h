/*
 * Copyright (C) 1997, 1998, 1999  Internet Software Consortium.
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

#include <isc/lang.h>
#include <isc/types.h>
#include <isc/boolean.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

#ifdef ISC_MEM_DEBUG
#define isc_mem_get(c, s)	__isc_mem_getdebug(c, s, __FILE__, __LINE__)
#define isc_mem_put(c, p, s)	__isc_mem_putdebug(c, p, s, __FILE__, __LINE__)
#define isc_mempool_get(c)	__isc_mempool_getdebug(c, __FILE__, __LINE__)
#define isc_mempool_put(c, p)	__isc_mempool_putdebug(c, p, s, \
						       __FILE__, __LINE__)
#else
#define isc_mem_get		__isc_mem_get
#define isc_mem_put		__isc_mem_put
#define isc_mempool_get		__isc_mempool_get
#define isc_mempool_put		__isc_mempool_put
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
void				isc_mem_setquota(isc_mem_t *, size_t);
size_t				isc_mem_getquota(isc_mem_t *);

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

/*
 * Memory pools
 */
isc_result_t	isc_mempool_create(isc_mem_t *, size_t, isc_mempool_t **);
void		isc_mempool_destroy(isc_mempool_t **);
void *		__isc_mempool_get(isc_mempool_t *);
void 		__isc_mempool_put(isc_mempool_t *, void *);
void *		__isc_mempool_getdebug(isc_mempool_t *, const char *, int);
void 		__isc_mempool_putdebug(isc_mempool_t *, void *,
				       const char *, int);

unsigned int	isc_mempool_getfreemax(isc_mempool_t *);
void		isc_mempool_setfreemax(isc_mempool_t *, unsigned int);
unsigned int	isc_mempool_getfreecount(isc_mempool_t *);
unsigned int	isc_mempool_getmaxalloc(isc_mempool_t *);
void		isc_mempool_setmaxalloc(isc_mempool_t *, unsigned int);
unsigned int	isc_mempool_getallocated(isc_mempool_t *);
unsigned int	isc_mempool_getfillcount(isc_mempool_t *);
void		isc_mempool_setfillcount(isc_mempool_t *, unsigned int);

ISC_LANG_ENDDECLS

#endif /* MEM_H */
