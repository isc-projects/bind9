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

#include <isc/types.h>

/*
 * A zone-owned view name.  Built-in names share static storage; custom names
 * are copied.  Initialize to zero, retain through shutdown, and free only at
 * final zone destruction.  Setters require exclusive access to readers.
 */
typedef struct {
	const char *name;
} dns_viewname_t;

void
dns__viewname_set(dns_viewname_t *name, isc_mem_t *mctx, const char *value);

void
dns__viewname_free(dns_viewname_t *name, isc_mem_t *mctx);

/* Return the full name, or NULL if no view has been assigned. */
const char *
dns__viewname_get(const dns_viewname_t *name);

/* Return the logging suffix name, or NULL for absent/built-in views. */
const char *
dns__viewname_display(const dns_viewname_t *name);
