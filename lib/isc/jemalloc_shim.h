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
#include <stdlib.h>
#include <string.h>

#include <isc/overflow.h>
#include <isc/util.h>

const char *malloc_conf = NULL;

/*
 * The MALLOCX_ZERO and MALLOCX_ZERO_GET macros were taken literal from
 * jemalloc_macros.h and jemalloc_internal_types.h headers respectively.
 */

#define MALLOCX_ZERO		((int)0x40)
#define MALLOCX_ZERO_GET(flags) ((bool)(flags & MALLOCX_ZERO))

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

	if (MALLOCX_ZERO_GET(flags)) {
		memset(ptr, 0, size);
	}

	return ptr;
}

static inline void
sdallocx(void *ptr, size_t size ISC_ATTR_UNUSED, int flags ISC_ATTR_UNUSED) {
	size_info *si = &(((size_info *)ptr)[-1]);

	free(si);
}

static inline size_t
sallocx(void *ptr, int flags ISC_ATTR_UNUSED) {
	size_info *si = &(((size_info *)ptr)[-1]);

	return si[0].size;
}

static inline void *
rallocx(void *ptr, size_t size, int flags) {
	size_info *si = realloc(&(((size_info *)ptr)[-1]), size + sizeof(*si));
	INSIST(si != NULL);

	if (MALLOCX_ZERO_GET(flags) && size > si->size) {
		memset((uint8_t *)si + sizeof(*si) + si->size, 0,
		       size - si->size);
	}

	si->size = size;
	ptr = &si[1];

	return ptr;
}

#endif /* !defined(HAVE_JEMALLOC) */
