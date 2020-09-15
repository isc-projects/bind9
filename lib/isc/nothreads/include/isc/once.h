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


#ifndef ISC_ONCE_H
#define ISC_ONCE_H 1

#include <stdbool.h>

#include <isc/result.h>

typedef bool isc_once_t;

#define ISC_ONCE_INIT false

#define isc_once_do(op, f) \
	(!*(op) ? (f(), *(op) = true, ISC_R_SUCCESS) : ISC_R_SUCCESS)

#endif /* ISC_ONCE_H */
