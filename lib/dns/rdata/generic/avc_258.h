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

typedef dns_rdata_txt_string_t dns_rdata_avc_string_t;

typedef struct dns_rdata_avc {
	dns_rdatacommon_t common;
	unsigned char *data;
	uint16_t length;
	/* private */
	uint16_t offset;
} dns_rdata_avc_t;
