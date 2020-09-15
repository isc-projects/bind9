/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file */

#include <inttypes.h>

typedef int8_t				isc_int8_t;
typedef	uint8_t				isc_uint8_t;
typedef int16_t				isc_int16_t;
typedef uint16_t			isc_uint16_t;
typedef int32_t				isc_int32_t;
typedef uint32_t			isc_uint32_t;
typedef int64_t				isc_int64_t;
typedef uint64_t			isc_uint64_t;

#define ISC_INT8_MIN	INT8_MIN
#define ISC_INT8_MAX	INT8_MAX
#define ISC_UINT8_MAX	UINT8_MAX

#define ISC_INT16_MIN	INT16_MIN
#define ISC_INT16_MAX	INT16_MAX
#define ISC_UINT16_MAX	UINT16_MAX

#define ISC_INT32_MIN	INT32_MIN
#define ISC_INT32_MAX	INT32_MAX
#define ISC_UINT32_MAX	UINT32_MAX

#define ISC_INT64_MIN	INT64_MIN
#define ISC_INT64_MAX	INT64_MAX
#define ISC_UINT64_MAX	UINT64_MAX
