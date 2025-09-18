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

#include <isc/region.h>
#include <isc/result.h>

typedef struct dns_rdata_in_deleg dns_rdata_in_delegparam_t;

isc_result_t
dns_rdata_in_delegparam_first(dns_rdata_in_delegparam_t *);

isc_result_t
dns_rdata_in_delegparam_next(dns_rdata_in_delegparam_t *);

void
dns_rdata_in_delegparam_current(dns_rdata_in_delegparam_t *, isc_region_t *);
