/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#if !defined(HAVE_JEMALLOC)

#include <stddef.h>
#include <string.h>

#include <isc/util.h>

const char *malloc_conf = NULL;

#define MALLOCX_ZERO	    ((int)0x40)
#define MALLOCX_TCACHE_NONE (0)
#define MALLOCX_ARENA(a)    (0)

#if defined(HAVE_MALLOC_SIZE) || defined(HAVE_MALLOC_USABLE_SIZE)

#include <stdlib.h>

#ifdef HAVE_MALLOC_SIZE

#include <malloc/malloc.h>

static inline size_t
sallocx(void *ptr, int flags) {
	UNUSED(flags);

	return (malloc_size(ptr));
}

#elif HAVE_MALLOC_USABLE_SIZE

#ifdef __DragonFly__
/*
 * On DragonFly BSD 'man 3 malloc' advises us to include the following
 * header to have access to malloc_usable_size().
 */
#include <malloc_np.h>
#else
#include <malloc.h>
#endif

static inline size_t
sallocx(void *ptr, int flags) {
	UNUSED(flags);

	return (malloc_usable_size(ptr));
}

#endif /* HAVE_MALLOC_SIZE */

static inline void *
mallocx(size_t size, int flags) {
	void *ptr = malloc(size);
	INSIST(ptr != NULL);

	if ((flags & MALLOCX_ZERO) != 0) {
		memset(ptr, 0, sallocx(ptr, flags));
	}

	return (ptr);
}

static inline void
sdallocx(void *ptr, size_t size, int flags) {
	UNUSED(size);
	UNUSED(flags);

	free(ptr);
}

static inline void *
rallocx(void *ptr, size_t size, int flags) {
	void *new_ptr;
	size_t old_size, new_size;

	REQUIRE(size != 0);

	if ((flags & MALLOCX_ZERO) != 0) {
		old_size = sallocx(ptr, flags);
	}

	new_ptr = realloc(ptr, size);
	INSIST(new_ptr != NULL);

	if ((flags & MALLOCX_ZERO) != 0) {
		new_size = sallocx(new_ptr, flags);
		if (new_size > old_size) {
			memset((uint8_t *)new_ptr + old_size, 0,
			       new_size - old_size);
		}
	}

	return (new_ptr);
}

#else /* defined(HAVE_MALLOC_SIZE) || defined (HAVE_MALLOC_USABLE_SIZE) */

#include <stdlib.h>

typedef union {
	size_t size;
	max_align_t __alignment;
} size_info;

static inline void *
mallocx(size_t size, int flags) {
	void *ptr = NULL;

	size_t bytes = ISC_CHECKED_ADD(size, sizeof(size_info));
	size_info *si = malloc(bytes);
	INSIST(si != NULL);

	si->size = size;
	ptr = &si[1];

	if ((flags & MALLOCX_ZERO) != 0) {
		memset(ptr, 0, size);
	}

	return (ptr);
}

static inline void
sdallocx(void *ptr, size_t size, int flags) {
	size_info *si = &(((size_info *)ptr)[-1]);

	UNUSED(size);
	UNUSED(flags);

	free(si);
}

static inline size_t
sallocx(void *ptr, int flags) {
	size_info *si = &(((size_info *)ptr)[-1]);

	UNUSED(flags);

	return (si[0].size);
}

static inline void *
rallocx(void *ptr, size_t size, int flags) {
	size_info *si = realloc(&(((size_info *)ptr)[-1]), size + sizeof(*si));
	INSIST(si != NULL);

	if ((flags & MALLOCX_ZERO) != 0 && size > si->size) {
		memset((uint8_t *)si + sizeof(*si) + si->size, 0,
		       size - si->size);
	}

	si->size = size;
	ptr = &si[1];

	return (ptr);
}

#endif /* defined(HAVE_MALLOC_SIZE) || defined (HAVE_MALLOC_USABLE_SIZE) */

#endif /* !defined(HAVE_JEMALLOC) */
