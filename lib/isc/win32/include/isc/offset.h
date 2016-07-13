/*
 * Copyright (C) 2000, 2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: offset.h,v 1.6 2007/06/19 23:47:20 tbox Exp $ */

#ifndef ISC_OFFSET_H
#define ISC_OFFSET_H 1

/*
 * File offsets are operating-system dependent.
 */
#include <limits.h>             /* Required for CHAR_BIT. */
#include <sys/types.h>

typedef _off_t isc_offset_t;

#endif /* ISC_OFFSET_H */
