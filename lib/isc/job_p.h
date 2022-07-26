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

#include <isc/job.h>
#include <isc/loop.h>

isc_job_t *
isc__job_new(isc_loop_t *loop, isc_job_cb cb, void *cbarg);

void
isc__job_init(isc_loop_t *loop, isc_job_t *job);

void
isc__job_run(isc_job_t *job);
