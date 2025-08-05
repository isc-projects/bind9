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

#include <isc/thread.h>

/*! \file */

/*
 * The current default stack sizes are as follows:
 * - Linux glibc: 8MB
 * - Linux musl: 128kB
 * - FreeBSD: 2MB
 * - OpenBSD: 512kB
 * - NetBSD: 4MB
 */
#ifndef THREAD_MINSTACKSIZE
#define THREAD_MINSTACKSIZE (1U * 1024 * 1024)
#endif /* ifndef THREAD_MINSTACKSIZE */

extern pthread_attr_t isc__thread_attr;

void
isc__thread_initialize(void);

void
isc__thread_shutdown(void);
