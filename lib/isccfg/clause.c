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

#include <stddef.h>

#include <isccfg/clause.h>

/* clang-format off */
const char *cfg_clause_as_string[] = {
	[CFG_CLAUSE__NONE] = NULL,
#define X(name, str) [name] = str,
	CFG_CLAUSES
#undef X
};
/* clang-format on */
