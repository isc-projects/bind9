/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id: int.h,v 1.16 2007/06/19 23:47:19 tbox Exp $ */

#ifndef ISC_INT_H
#define ISC_INT_H 1

#include <stdint.h>

/*! \file */

#define	isc_int8_t	int8_t
#define isc_uint8_t	uint8_t
#define isc_int16_t	int16_t
#define isc_uint16_t	uint16_t
#define isc_int32_t	int32_t
#define isc_uint32_t	uint32_t
#define isc_int64_t	int64_t
#define isc_uint64_t	uint64_t

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

#endif /* ISC_INT_H */
