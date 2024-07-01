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

#include "openssl_shim.h"

#include <isc/util.h>

#if !HAVE_ERR_GET_ERROR_ALL
static const char err_empty_string = '\0';

unsigned long
ERR_get_error_all(const char **file, int *line, const char **func,
		  const char **data, int *flags) {
	SET_IF_NOT_NULL(func, &err_empty_string);
	return (ERR_get_error_line_data(file, line, data, flags));
}
#endif /* if !HAVE_ERR_GET_ERROR_ALL */
