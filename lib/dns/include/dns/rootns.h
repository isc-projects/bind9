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

/*! \file dns/rootns.h */

#include <dns/types.h>

typedef struct dns_delegdb dns_delegdb_t;

isc_result_t
dns_rootns_filldelegdb(isc_mem_t *mctx, const char *filename,
		       dns_delegdb_t *db);

const char *
dns_rootns_gethints(void);
/*%
 * Get built-in root NS hints
 */
