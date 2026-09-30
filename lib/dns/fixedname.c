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

/*! \file */

#include <string.h>

#include <isc/endian.h>
#include <isc/util.h>

#include <dns/fixedname.h>

static const unsigned char base32hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

static inline void
base32hexnp_encode_block(uint64_t block, unsigned char *dst) {
	dst[0] = base32hex[(block >> 59) & 0x1fU];
	dst[1] = base32hex[(block >> 54) & 0x1fU];
	dst[2] = base32hex[(block >> 49) & 0x1fU];
	dst[3] = base32hex[(block >> 44) & 0x1fU];
	dst[4] = base32hex[(block >> 39) & 0x1fU];
	dst[5] = base32hex[(block >> 34) & 0x1fU];
	dst[6] = base32hex[(block >> 29) & 0x1fU];
	dst[7] = base32hex[(block >> 24) & 0x1fU];
}

static isc_result_t
base32hexnp_encode(const dns_nsec3hash_t *hash, isc_buffer_t *target) {
	const unsigned char *src = *hash;
	unsigned char *dst;
	uint64_t block;

	if (isc_buffer_availablelength(target) < 32U) {
		return ISC_R_NOSPACE;
	}
	dst = isc_buffer_used(target);

	for (size_t offset = 0; offset < 15U; offset += 5U) {
		memmove(&block, src, sizeof(block));
		base32hexnp_encode_block(be64toh(block), dst);

		src += 5;
		dst += 8;
	}

	/* Load bytes 12..19, then discard the first three bytes. */
	memmove(&block, (*hash) + 12, sizeof(block));
	base32hexnp_encode_block(be64toh(block) << 24, dst);

	isc_buffer_add(target, 32U);
	return ISC_R_SUCCESS;
}

void
dns_fixedname_init(dns_fixedname_t *fixed) {
	dns_name_init(&fixed->name);
	isc_buffer_init(&fixed->buffer, fixed->data, DNS_NAME_MAXWIRE);
	dns_name_setbuffer(&fixed->name, &fixed->buffer);
}

void
dns_fixedname_invalidate(dns_fixedname_t *fixed) {
	dns_name_invalidate(&fixed->name);
}

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed) {
	return &fixed->name;
}

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return dns_fixedname_name(fixed);
}

isc_result_t
dns_fixedname_fromnsec3hash(dns_fixedname_t *fixed, const dns_nsec3hash_t *hash,
			    const dns_name_t *origin) {
	isc_region_t origin_region;

	REQUIRE(fixed != NULL);
	REQUIRE(hash != NULL);
	REQUIRE(DNS_NAME_VALID(origin));

	isc_buffer_clear(&fixed->buffer);
	isc_buffer_putuint8(&fixed->buffer, 32U);
	RETERR(base32hexnp_encode(hash, &fixed->buffer));

	dns_name_toregion(origin, &origin_region);
	RETERR(isc_buffer_copyregion(&fixed->buffer, &origin_region));

	fixed->name = (dns_name_t){
		.magic = DNS_NAME_MAGIC,
		.attributes = { .absolute = true },
		.ndata = fixed->data,
		.length = (uint8_t)isc_buffer_usedlength(&fixed->buffer),
		.buffer = &fixed->buffer,
		.link = ISC_LINK_INITIALIZER,
		.list = ISC_LIST_INITIALIZER,
	};

	return ISC_R_SUCCESS;
}
