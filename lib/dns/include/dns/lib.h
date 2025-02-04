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

#include <stdlib.h>

#include <isc/lib.h>
#include <isc/util.h>

void
dns__lib_initialize(void);
void
dns__lib_shutdown(void);

void
dns_lib_initialize(void) __attribute__((__constructor__));
void
dns_lib_shutdown(void) __attribute__((__destructor__));

void
dns_lib_initialize(void) {
	isc__lib_initialize();
	dns__lib_initialize();
}
void
dns_lib_shutdown(void) {
	dns__lib_shutdown();
	isc__lib_shutdown();
}
