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

#include <isc/result.h>
#include <isc/boolean.h>
#include <isc/memcluster.h>

typedef boolean_t (*heap_higher_priority_func)(void *, void *);
typedef void (*heap_index_func)(void *, unsigned int);
typedef void (*heap_for_each_func)(void *, void *);

typedef struct heap_context *heap_t;

#define heap_create	__heap_create
#define heap_destroy	__heap_destroy
#define heap_insert	__heap_insert
#define heap_delete	__heap_delete
#define heap_increased	__heap_increased
#define heap_decreased	__heap_decreased
#define heap_element	__heap_element
#define heap_for_each	__heap_for_each

isc_result	heap_create(mem_context_t, heap_higher_priority_func,
			    heap_index_func, unsigned int, heap_t *);
void		heap_destroy(heap_t *);
isc_result	heap_insert(heap_t, void *);
void		heap_delete(heap_t, unsigned int);
void		heap_increased(heap_t, unsigned int);
void		heap_decreased(heap_t, unsigned int);
void *		heap_element(heap_t, unsigned int);
void		heap_for_each(heap_t, heap_for_each_func, void *);
