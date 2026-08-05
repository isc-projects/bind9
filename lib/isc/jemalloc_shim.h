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

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <isc/overflow.h>
#include <isc/util.h>

const char *malloc_conf = NULL;

static size_t
get_aligned_size(size_t alignment, size_t size) {
	/*
	 * C23 dropped the requirement that size be an integral multiple of
	 * alignment, but some implementations still enforce it at runtime,
	 * so round the size up.
	 */
	return ISC_CHECKED_ADD(size, alignment - 1) & ~(alignment - 1);
}

#ifndef HAVE_FREE_SIZED
static void
free_sized(void *ptr, size_t size ISC_ATTR_UNUSED) {
	free(ptr);
}
#endif

#ifndef HAVE_FREE_ALIGNED_SIZED
static void
free_aligned_sized(void *ptr, size_t alignment ISC_ATTR_UNUSED,
		   size_t size ISC_ATTR_UNUSED) {
	free(ptr);
}
#endif

/*
 * The MALLOCX_ZERO, MALLOCX_ALIGN and MALLOCX_*_GET macros were taken
 * literal from jemalloc_macros.h and jemalloc_internal_types.h headers
 * respectively.
 */

#define MALLOCX_ZERO		((int)0x40)
#define MALLOCX_ZERO_GET(flags) ((bool)(flags & MALLOCX_ZERO))

#define MALLOCX_LG_ALIGN_MASK ((int)0x3f)
#if __SIZEOF_POINTER__ == 4
#define MALLOCX_ALIGN(a) ((int)(ffs((int)(a)) - 1))
#else
#define MALLOCX_ALIGN(a)                       \
	((int)(((size_t)(a) < (size_t)INT_MAX) \
		       ? ffs((int)(a)) - 1     \
		       : ffs((int)(((size_t)(a)) >> 32)) + 31))
#endif
#define MALLOCX_ALIGN_GET(flags) \
	(((size_t)1) << (flags & MALLOCX_LG_ALIGN_MASK))

/*
 * malloc() already guarantees alignment suitable for any fundamental
 * type; only larger alignment requests need the aligned paths below.
 */
#define MALLOCX_NEEDS_ALIGN(flags) \
	(MALLOCX_ALIGN_GET(flags) > _Alignof(max_align_t))

typedef union {
	struct {
		size_t size;
		int flags;
	};
	max_align_t __alignment;
} size_info;

/*
 * The size_info header sits a multiple of the requested alignment before the
 * returned pointer.  The caller passes the matching MALLOCX_ALIGN() flag on
 * deallocation too, so the base address is always recomputable from the flags
 * and nothing needs to be stored.
 */

static inline size_t
get_header_size(int flags) {
	return get_aligned_size(MALLOCX_ALIGN_GET(flags), sizeof(size_info));
}

static inline size_info *
get_size_info(void *ptr, int flags) {
	return (size_info *)((uint8_t *)ptr - get_header_size(flags));
}

static inline void *
mallocx(size_t size, int flags) {
	size_t alignment = MALLOCX_ALIGN_GET(flags);
	size_t header_size = get_header_size(flags);
	size_info *si;

	if (MALLOCX_NEEDS_ALIGN(flags)) {
		size_t bytes = ISC_CHECKED_ADD(
			get_aligned_size(alignment, size), header_size);
		si = aligned_alloc(alignment, bytes);
	} else {
		si = malloc(ISC_CHECKED_ADD(size, header_size));
	}
	if (si == NULL) {
		return NULL;
	}
	si->size = size;
	si->flags = flags;

	void *ptr = (uint8_t *)si + header_size;
	if (MALLOCX_ZERO_GET(flags)) {
		memset(ptr, 0, size);
	}

	return ptr;
}

static inline void
sdallocx(void *ptr, size_t size, int flags) {
	size_info *si = get_size_info(ptr, flags);
	size_t alignment = MALLOCX_ALIGN_GET(flags);
	size_t header_size = get_header_size(flags);

	INSIST((flags & MALLOCX_LG_ALIGN_MASK) ==
	       (si->flags & MALLOCX_LG_ALIGN_MASK));

	if (MALLOCX_NEEDS_ALIGN(flags)) {
		size_t bytes = ISC_CHECKED_ADD(
			get_aligned_size(alignment, size), header_size);
		free_aligned_sized(si, alignment, bytes);
	} else {
		free_sized(si, ISC_CHECKED_ADD(si->size, header_size));
	}
}

static inline size_t
sallocx(void *ptr, int flags) {
	size_info *si = get_size_info(ptr, flags);

	return si[0].size;
}

static inline void *
rallocx(void *ptr, size_t size, int flags) {
	size_t header_size = get_header_size(flags);
	size_info *si = get_size_info(ptr, flags);
	size_t old_size = si->size;

	INSIST((flags & MALLOCX_LG_ALIGN_MASK) ==
	       (si->flags & MALLOCX_LG_ALIGN_MASK));

	if (MALLOCX_NEEDS_ALIGN(flags)) {
		/*
		 * realloc() cannot preserve the requested alignment;
		 * move the data to a fresh aligned allocation.
		 */
		void *new_ptr = mallocx(size, flags & ~MALLOCX_ZERO);
		if (new_ptr == NULL) {
			return NULL;
		}
		memmove(new_ptr, ptr, ISC_MIN(old_size, size));
		if (MALLOCX_ZERO_GET(flags) && size > old_size) {
			memset((uint8_t *)new_ptr + old_size, 0,
			       size - old_size);
		}
		sdallocx(ptr, old_size, flags);

		si = get_size_info(new_ptr, flags);
		si->flags = flags;

		return new_ptr;
	}

	si = realloc(si, ISC_CHECKED_ADD(size, header_size));
	if (si == NULL) {
		return NULL;
	}
	si->size = size;
	si->flags = flags;

	ptr = (uint8_t *)si + header_size;
	if (MALLOCX_ZERO_GET(flags) && size > old_size) {
		memset((uint8_t *)ptr + old_size, 0, size - old_size);
	}

	return ptr;
}

#endif /* !defined(HAVE_JEMALLOC) */
