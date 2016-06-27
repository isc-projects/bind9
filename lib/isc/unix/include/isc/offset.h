/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2008, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: offset.h,v 1.17 2008/12/01 23:47:45 tbox Exp $ */

#ifndef ISC_OFFSET_H
#define ISC_OFFSET_H 1

/*! \file
 * \brief
 * File offsets are operating-system dependent.
 */
#include <limits.h>             /* Required for CHAR_BIT. */
#include <sys/types.h>
#include <stddef.h>		/* For Linux Standard Base. */

typedef off_t isc_offset_t;

/*%
 * POSIX says "Additionally, blkcnt_t and off_t are extended signed integral
 * types", so the maximum value is all 1s except for the high bit.
 * This definition is more complex than it really needs to be because it was
 * crafted to keep both the SunOS 5.6 and the HP/UX 11 compilers quiet about
 * integer overflow.  For example, though this is equivalent to just left
 * shifting 1 to the high bit and then inverting the bits, the SunOS compiler
 * is unhappy about shifting a positive "1" to negative in a signed integer.
 */
#define ISC_OFFSET_MAXIMUM \
	(~(((off_t)-1 >> (sizeof(off_t) * CHAR_BIT - 1)) \
		      << (sizeof(off_t) * CHAR_BIT - 1)))

#endif /* ISC_OFFSET_H */
