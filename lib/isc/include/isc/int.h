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

#ifndef ISC_INT_H
#define ISC_INT_H 1

/*! \file */

#if defined(_WIN32)

#if _MSC_VER >= 1600 //
#include <stdint.h>
#else

#include <limits.h>

typedef signed __int8		int8_t;
typedef signed __int16		int16_t;
typedef signed __int32		int32_t;
typedef unsigned __int8		uint8_t;
typedef unsigned __int16	uint16_t;
typedef unsigned __int32	uint32_t;
typedef signed __int64		int64_t;
typedef unsigned __int64	uint64_t;

#define INT8_MIN	((int8_t)_I8_MIN)
#define INT8_MAX	_I8_MAX
#define INT16_MIN	((int16_t)_I16_MIN)
#define INT16_MAX	_I16_MAX
#define INT32_MIN	((int32_t)_I32_MIN)
#define INT32_MAX	_I32_MAX
#define INT64_MIN	((int64_t)_I64_MIN)
#define INT64_MAX	_I64_MAX
#define UINT8_MAX	_UI8_MAX
#define UINT16_MAX	_UI16_MAX
#define UINT32_MAX	_UI32_MAX
#define UINT64_MAX	_UI64_MAX

#endif /* _MSC_VER >= 1600 */

#else /* defined(_WIN32) */

#if HAVE_INTTYPES_H
# include <inttypes.h>
#elif HAVE_STDINT_H
# include <stdint.h>
#endif

#if !defined(INT8_MAX) && !defined(int8_t)
typedef signed char		int8_t;
#define INT8_MIN		-128
#define INT8_MAX		127
#endif

#if !defined(UINT8_MAX) && !defined(uint8_t)
typedef unsigned char		uint8_t;
#define UINT8_MAX		255
#endif

#if !defined INT16_MAX && !defined int16_t
typedef short			int16_t;
#define INT16_MIN		-32768
#define INT16_MAX		32767
#endif

#if !defined UINT16_MAX && !defined uint16_t
typedef unsigned short		uint16_t;
#define UINT16_MAX		65535
#endif

/*%
 * Note that "int" is 32 bits on all currently supported Unix-like operating
 * systems, but "long" can be either 32 bits or 64 bits, thus the 32 bit
 * constants are not qualified with "L".
 */
#if !defined(INT32_MAX) && !defined(int32_t)
typedef int			int32_t;
#define INT32_MIN		-2147483648
#define INT32_MAX		2147483647
#endif

#if !defined(UINT32_MAX) && !defined(uint32_t)
typedef unsigned int		uint32_t;
#define UINT32_MAX		4294967295U
#endif

#if !defined(INT64_MAX) && !defined(int64_t)
typedef long long		int64_t;
#define INT64_MIN		-9223372036854775808LL
#define INT64_MAX		9223372036854775807LL
#define PRId64			"lld"
#endif

#if !defined(UINT64_MAX) && !defined(uint64_t)
typedef unsigned long long	uint64_t;
#define UINT64_MAX		18446744073709551615ULL
#define PRIu64			"llu"
#define PRIx64			"llx"
#define PRIX64			"llX"
#endif

#endif /* defined(_WIN32) */

typedef int8_t  isc_int8_t;
typedef int16_t isc_int16_t;
typedef int32_t isc_int32_t;
typedef int64_t isc_int64_t;

typedef uint8_t  isc_uint8_t;
typedef uint16_t isc_uint16_t;
typedef uint32_t isc_uint32_t;
typedef uint64_t isc_uint64_t;

#endif /* ISC_INT_H */
