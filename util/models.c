/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Provide a simple memory management model for lib/isc/mem.c
 * which hides all the internal storage and memory filling.
 *
 * See https://scan.coverity.com/models
 */

#define FLARG	   , const char *file, unsigned int line
#define FLARG_PASS , file, line

int condition;
void *
isc__mem_get(void *mem, unsigned int size FLARG) {
	if (!mem) {
		__coverity_panic__();
	}
	__coverity_negative_sink__(size);
	if (condition) {
		return (0);
	}
	return (__coverity_alloc__(size));
}

void
isc__mem_put(void *mem, void *ptr, unsigned int size FLARG) {
	if (!mem) {
		__coverity_panic__();
	}
	__coverity_free__(ptr);
}

void
isc__mem_putanddetach(void *mem, void *ptr, unsigned int size FLARG) {
	if (!mem) {
		__coverity_panic__();
	}
	__coverity_free__(ptr);
}

void *
isc__mem_allocate(void *mem, unsigned int size FLARG) {
	if (!mem) {
		__coverity_panic__();
	}
	__coverity_negative_sink__(size);
	if (condition) {
		return (0);
	}
	return (__coverity_alloc__(size));
}

void *
memcpy(void *s1, const void *s2, size_t n);

void *
isc__mem_reallocate(void *mem, void *ptr, size_t size FLARG) {
	char *p = (char *)0;
	size_t l;

	if (!mem) {
		__coverity_panic__();
	}
	if (size > 0) {
		p = isc__mem_allocate(mem, size FLARG_PASS);
		if (p && ptr) {
			l = (l > size) ? size : l;
			memcpy(p, ptr, l);
			__coverity_free__(ptr);
		}
	} else if (ptr) {
		__coverity_free__(ptr);
	}
	return (p);
}

void
isc__mem_free(void *mem, void *ptr FLARG) {
	if (!mem) {
		__coverity_panic__();
	}
	__coverity_free__(ptr);
}

unsigned int
strlen(const char *);

void *
isc__mem_strdup(void *mem, char *s FLARG) {
	void *d;
	if (!mem) {
		__coverity_panic__();
	}
	if (condition) {
		return (0);
	}
	d = __coverity_alloc__(strlen(s) + 1);
	__coverity_writeall__(d);
	return (d);
}

void *
isc__mempool_get(void *mem FLARG) {
	unsigned int size;
	if (!mem) {
		__coverity_panic__();
	}
	if (condition) {
		return (0);
	}
	return (__coverity_alloc__(size));
}

void
isc__mempool_put(void *mem, void *ptr FLARG) {
	if (!mem) {
		__coverity_panic__();
	}
	__coverity_free__(ptr);
}

/*
 * Cmocka models.
 */

#define LargestIntegralType unsigned long int

void
_assert_true(const LargestIntegralType result, const char *const expression,
	     const char *const file, const int line) {
	if (!result) {
		__coverity_panic__();
	}
}
