/*
 * Copyright (c) 1997, 1998 by Internet Software Consortium.
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

#ifndef MEMCLUSTER_H
#define MEMCLUSTER_H 1

#include <stdio.h>
#include <stddef.h>

typedef struct mem_context *	mem_context_t;

#define mem_context_create	__mem_context_create
#define mem_context_destroy	__mem_context_destroy
#ifdef MEMCLUSTER_DEBUG
#define mem_get(c, s)		__mem_get_debug(c, s, __FILE__, __LINE__)
#define mem_put(c, p, s)	__mem_put_debug(c, p, s, __FILE__, __LINE__)
#else
#define mem_get			__mem_get
#define mem_put			__mem_put
#endif
#define mem_valid		__mem_valid
#define mem_stats		__mem_stats
#define mem_allocate		__mem_allocate
#define mem_free		__mem_free

int				mem_context_create(size_t, size_t,
						   mem_context_t *);
void				mem_context_destroy(mem_context_t *);
void *				__mem_get(mem_context_t, size_t);
void 				__mem_put(mem_context_t, void *, size_t);
void *				__mem_get_debug(mem_context_t, size_t,
						const char *, int);
void 				__mem_put_debug(mem_context_t, void *, size_t,
						const char *, int);
int				mem_valid(mem_context_t, void *);
void 				mem_stats(mem_context_t, FILE *);
void *				mem_allocate(mem_context_t, size_t);
void				mem_free(mem_context_t, void *);

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
mem_context_t			mem_default_context(void);
void *				__memget(size_t);
void 				__memput(void *, size_t);
void *				__memget_debug(size_t, const char *, int);
void				__memput_debug(void *, size_t, const char *,
					       int);
int				memvalid(void *);
void 				memstats(FILE *);

#endif /* MEMCLUSTER_H */
