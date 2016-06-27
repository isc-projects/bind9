/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

#ifndef LWRES_ASSERT_P_H
#define LWRES_ASSERT_P_H 1

/*! \file */

#include <assert.h>		/* Required for assert() prototype. */

#define REQUIRE(x)		assert(x)
#define INSIST(x)		assert(x)

#define UNUSED(x)		((void)(x))
#define POST(x)			((void)(x))

#define SPACE_OK(b, s)		(LWRES_BUFFER_AVAILABLECOUNT(b) >= (s))
#define SPACE_REMAINING(b, s)	(LWRES_BUFFER_REMAINING(b) >= (s))

#endif /* LWRES_ASSERT_P_H */
