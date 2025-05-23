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

/*! \file */

/* XXXDCL this should be moved to lib/isc/include/isc/errno2result.h. */

#include <errno.h> /* Provides errno. */
#include <stdbool.h>

#include <isc/types.h>

#define isc__errno2result(x) isc___errno2result(x, true, __FILE__, __LINE__)

isc_result_t
isc___errno2result(int posixerrno, bool dolog, const char *file,
		   unsigned int line);
