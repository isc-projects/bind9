/*
 * Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Provide a simple memory management model for lib/isc/mem.c
 * which hides all the internal storage and memory filling.
 */

#define FLARG , const char * file, unsigned int line
#define FLARG_PASS , file, line

int condition;
void *isc__mem_get(void *mem, unsigned int size FLARG) {
	if (!mem) __coverity_panic__();
	__coverity_negative_sink__(size);
	if (condition)
		return (0);
	return (__coverity_alloc__(size));
}

void isc__mem_put(void *mem, void *ptr, unsigned int size FLARG) {
	if (!mem) __coverity_panic__();
	__coverity_free__(ptr);
}

void isc__mem_putanddetach(void *mem, void *ptr, unsigned int size FLARG) {
	if (!mem) __coverity_panic__();
	__coverity_free__(ptr);
}

void *isc__mem_allocate(void *mem, unsigned int size FLARG) {
	if (!mem) __coverity_panic__();
	__coverity_negative_sink__(size);
	if (condition)
		return (0);
	return (__coverity_alloc__(size));
}

void *memcpy(void *s1, const void *s2, size_t n);

void * isc__mem_reallocate(void *mem, void *ptr, size_t size FLARG) {
	char *p = (char *)0;
	size_t l;

	if (!mem) __coverity_panic__();
	if (size > 0) {
		p = isc__mem_allocate(mem, size FLARG_PASS);
		if (p && ptr) {
			l = (l > size) ? size : l;
			memcpy(p, ptr, l);
			__coverity_free__(ptr);
		}
	} else if (ptr)
		__coverity_free__(ptr);
	return (p);
}

void isc__mem_free(void *mem, void *ptr FLARG) {
	if (!mem) __coverity_panic__();
	__coverity_free__(ptr);
}

unsigned int strlen(const char*);

void *isc__mem_strdup(void *mem, char *s FLARG) {
	void *d;
	if (!mem) __coverity_panic__();
	if (condition)
		return (0);
	d = __coverity_alloc__(strlen(s) + 1);
	__coverity_writeall__(d);
	return (d);
}

void *isc__mempool_get(void *mem FLARG) {
	unsigned int size;
	if (!mem) __coverity_panic__();
	if (condition)
		return (0);
	return (__coverity_alloc__(size));
}

void isc__mempool_put(void *mem, void *ptr FLARG) {
	if (!mem) __coverity_panic__();
	__coverity_free__(ptr);
}
