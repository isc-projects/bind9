/*
 * Copyright (C) 1999-2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: magic.h,v 1.18 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_MAGIC_H
#define ISC_MAGIC_H 1

#include <isc/util.h>

/*! \file isc/magic.h */

typedef struct {
	unsigned int magic;
} isc__magic_t;


/*%
 * To use this macro the magic number MUST be the first thing in the
 * structure, and MUST be of type "unsigned int".
 * The intent of this is to allow magic numbers to be checked even though
 * the object is otherwise opaque.
 */
#define ISC_MAGIC_VALID(a,b)	(ISC_LIKELY((a) != NULL) && \
				 ISC_LIKELY(((const isc__magic_t *)(a))->magic == (b)))

#define ISC_MAGIC(a, b, c, d)	((a) << 24 | (b) << 16 | (c) << 8 | (d))

#endif /* ISC_MAGIC_H */
