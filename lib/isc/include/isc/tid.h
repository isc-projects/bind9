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

#include <inttypes.h>

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

#define ISC_TID_UNKNOWN UINT32_MAX

uint32_t
isc_tid(void);
/*%<
 * Returns the thread ID of the currently-running loop.
 */

/* Private */

void
isc__tid_init(uint32_t tid);

ISC_LANG_ENDDECLS
