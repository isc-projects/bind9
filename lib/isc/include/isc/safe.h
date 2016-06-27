/*
 * Copyright (C) 2013, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

#ifndef ISC_SAFE_H
#define ISC_SAFE_H 1

/*! \file isc/safe.h */

#include <isc/types.h>

ISC_LANG_BEGINDECLS

isc_boolean_t
isc_safe_memequal(const void *s1, const void *s2, size_t n);
/*%<
 * Returns ISC_TRUE iff. two blocks of memory are equal, otherwise
 * ISC_FALSE.
 *
 */

int
isc_safe_memcompare(const void *b1, const void *b2, size_t len);
/*%<
 * Clone of libc memcmp() which is safe to differential timing attacks.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_SAFE_H */
