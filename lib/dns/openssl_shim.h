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

#pragma once

#include <openssl/err.h>

#if !HAVE_ERR_GET_ERROR_ALL
unsigned long
ERR_get_error_all(const char **file, int *line, const char **func,
		  const char **data, int *flags);
#endif /* if !HAVE_ERR_GET_ERROR_ALL */
