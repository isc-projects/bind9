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

#pragma once

#if defined(__linux__) || defined(__CYGWIN__)

#include <endian.h>

#elif defined __APPLE__

#include <libkern/OSByteOrder.h>

# define htobe16(x) OSSwapHostToBigInt16(x)
# define htole16(x) OSSwapHostToLittleInt16(x)
# define be16toh(x) OSSwapBigToHostInt16(x)
# define le16toh(x) OSSwapLittleToHostInt16(x)

# define htobe32(x) OSSwapHostToBigInt32(x)
# define htole32(x) OSSwapHostToLittleInt32(x)
# define be32toh(x) OSSwapBigToHostInt32(x)
# define le32toh(x) OSSwapLittleToHostInt32(x)

# define htobe64(x) OSSwapHostToBigInt64(x)
# define htole64(x) OSSwapHostToLittleInt64(x)
# define be64toh(x) OSSwapBigToHostInt64(x)
# define le64toh(x) OSSwapLittleToHostInt64(x)

# define __BYTE_ORDER    BYTE_ORDER
# define __BIG_ENDIAN    BIG_ENDIAN
# define __LITTLE_ENDIAN LITTLE_ENDIAN
# define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

# include <sys/endian.h>

# define be16toh(x) betoh16(x)
# define le16toh(x) letoh16(x)

# define be32toh(x) betoh32(x)
# define le32toh(x) letoh32(x)

# define be64toh(x) betoh64(x)
# define le64toh(x) letoh64(x)

#elif defined(_WIN32)
/* Windows is always little endian */

#include <stdlib.h>

# define htobe16(x) _byteswap_ushort(x)
# define htole16(x) (x)
# define be16toh(x) _byteswap_ushort(x)
# define le16toh(x) (x)

# define htobe32(x) _byteswap_ulong(x)
# define htole32(x) (x)
# define be32toh(x) _byteswap_ulong(x)
# define le32toh(x) (x)

# define htobe64(x) _byteswap_uint64(x)
# define htole64(x) (x)
# define be64toh(x) _byteswap_uint64(x)
# define le64toh(x) (x)

# define __BYTE_ORDER    BYTE_ORDER
# define __BIG_ENDIAN    BIG_ENDIAN
# define __LITTLE_ENDIAN LITTLE_ENDIAN
# define __PDP_ENDIAN    PDP_ENDIAN

#else

#error Platform not supported

#endif
