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

#undef DNS_DB_NODETRACE

#if DNS_DB_NODETRACE

#define DNS__DB_FILELINE   , __func__, __FILE__, __LINE__
#define DNS__DB_FLARG_PASS , func, file, line
#define DNS__DB_FLARG                                          \
	, const char	    *func __attribute__((__unused__)), \
		const char  *file __attribute__((__unused__)), \
		unsigned int line __attribute__((__unused__))

#else /* DNS_DB_NODETRACE */

#define DNS__DB_FILELINE
#define DNS__DB_FLARG
#define DNS__DB_FLARG_PASS

#endif /* DNS_DB_NODETRACE */
