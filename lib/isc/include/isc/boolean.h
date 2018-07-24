/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id: boolean.h,v 1.19 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_BOOLEAN_H
#define ISC_BOOLEAN_H 1

/*! \file isc/boolean.h */

#if _WIN32 && _MSC_VER >= 1600
#include <stdbool.h>
#endif

#if HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#if __bool_true_false_are_defined
# define isc_boolean_t bool
#else /* __bool_true_false_are_defined */
typedef enum { isc_boolean_false = 0, isc_boolean_true = 1 } isc_boolean_t;
# define bool isc_boolean_t
# define true isc_boolean_true
# define false isc_boolean_false
#endif /* __bool_true_false_are_defined */

#define ISC_FALSE false
#define ISC_TRUE true
#define ISC_TF(x) (!!(x))

#endif /* ISC_BOOLEAN_H */
