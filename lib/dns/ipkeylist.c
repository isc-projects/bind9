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

#include <inttypes.h>
#include <string.h>

#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/util.h>

#include <dns/ipkeylist.h>
#include <dns/name.h>

void
dns_ipkeylist_init(dns_ipkeylist_t *ipkl) {
	ipkl->count = 0;
	ipkl->allocated = 0;
	ipkl->addrs = NULL;
	ipkl->sources = NULL;
	ipkl->keys = NULL;
	ipkl->tlss = NULL;
	ipkl->labels = NULL;
}

void
dns_ipkeylist_clear(isc_mem_t *mctx, dns_ipkeylist_t *ipkl) {
	uint32_t i;

	REQUIRE(ipkl != NULL);

	if (ipkl->allocated == 0) {
		return;
	}

	if (ipkl->addrs != NULL) {
		isc_mem_cput(mctx, ipkl->addrs, ipkl->allocated,
			     sizeof(isc_sockaddr_t));
	}

	if (ipkl->sources != NULL) {
		isc_mem_cput(mctx, ipkl->sources, ipkl->allocated,
			     sizeof(isc_sockaddr_t));
	}

	if (ipkl->addrs != NULL) {
		isc_mem_cput(mctx, ipkl->addrs, ipkl->allocated,
			     sizeof(isc_sockaddr_t));
	}

	if (ipkl->keys != NULL) {
		for (i = 0; i < ipkl->allocated; i++) {
			if (ipkl->keys[i] == NULL) {
				continue;
			}
			if (dns_name_dynamic(ipkl->keys[i])) {
				dns_name_free(ipkl->keys[i], mctx);
			}
			isc_mem_put(mctx, ipkl->keys[i], sizeof(dns_name_t));
		}
		isc_mem_cput(mctx, ipkl->keys, ipkl->allocated,
			     sizeof(dns_name_t *));
	}

	if (ipkl->tlss != NULL) {
		for (i = 0; i < ipkl->allocated; i++) {
			if (ipkl->tlss[i] == NULL) {
				continue;
			}
			if (dns_name_dynamic(ipkl->tlss[i])) {
				dns_name_free(ipkl->tlss[i], mctx);
			}
			isc_mem_put(mctx, ipkl->tlss[i], sizeof(dns_name_t));
		}
		isc_mem_cput(mctx, ipkl->tlss, ipkl->allocated,
			     sizeof(dns_name_t *));
	}

	if (ipkl->labels != NULL) {
		for (i = 0; i < ipkl->allocated; i++) {
			if (ipkl->labels[i] == NULL) {
				continue;
			}
			if (dns_name_dynamic(ipkl->labels[i])) {
				dns_name_free(ipkl->labels[i], mctx);
			}
			isc_mem_put(mctx, ipkl->labels[i], sizeof(dns_name_t));
		}
		isc_mem_cput(mctx, ipkl->labels, ipkl->allocated,
			     sizeof(dns_name_t *));
	}

	dns_ipkeylist_init(ipkl);
}

isc_result_t
dns_ipkeylist_copy(isc_mem_t *mctx, const dns_ipkeylist_t *src,
		   dns_ipkeylist_t *dst) {
	isc_result_t result = ISC_R_SUCCESS;
	uint32_t i;

	REQUIRE(dst != NULL);
	/* dst might be preallocated, we don't care, but it must be empty */
	REQUIRE(dst->count == 0);

	if (src->count == 0) {
		return (ISC_R_SUCCESS);
	}

	result = dns_ipkeylist_resize(mctx, dst, src->count);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	memmove(dst->addrs, src->addrs, src->count * sizeof(isc_sockaddr_t));

	if (src->sources != NULL) {
		memmove(dst->sources, src->sources,
			src->count * sizeof(isc_sockaddr_t));
	}

	if (src->keys != NULL) {
		for (i = 0; i < src->count; i++) {
			if (src->keys[i] != NULL) {
				dst->keys[i] = isc_mem_get(mctx,
							   sizeof(dns_name_t));
				dns_name_init(dst->keys[i], NULL);
				dns_name_dup(src->keys[i], mctx, dst->keys[i]);
			} else {
				dst->keys[i] = NULL;
			}
		}
	}

	if (src->tlss != NULL) {
		for (i = 0; i < src->count; i++) {
			if (src->tlss[i] != NULL) {
				dst->tlss[i] = isc_mem_get(mctx,
							   sizeof(dns_name_t));
				dns_name_init(dst->tlss[i], NULL);
				dns_name_dup(src->tlss[i], mctx, dst->tlss[i]);
			} else {
				dst->tlss[i] = NULL;
			}
		}
	}

	if (src->labels != NULL) {
		for (i = 0; i < src->count; i++) {
			if (src->labels[i] != NULL) {
				dst->labels[i] =
					isc_mem_get(mctx, sizeof(dns_name_t));
				dns_name_init(dst->labels[i], NULL);
				dns_name_dup(src->labels[i], mctx,
					     dst->labels[i]);
			} else {
				dst->labels[i] = NULL;
			}
		}
	}
	dst->count = src->count;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_ipkeylist_resize(isc_mem_t *mctx, dns_ipkeylist_t *ipkl, unsigned int n) {
	REQUIRE(ipkl != NULL);
	REQUIRE(n > ipkl->count);

	if (n <= ipkl->allocated) {
		return (ISC_R_SUCCESS);
	}

	ipkl->addrs = isc_mem_creget(mctx, ipkl->addrs, ipkl->allocated, n,
				     sizeof(isc_sockaddr_t));
	ipkl->sources = isc_mem_creget(mctx, ipkl->addrs, ipkl->allocated, n,
				       sizeof(isc_sockaddr_t));
	ipkl->keys = isc_mem_creget(mctx, ipkl->addrs, ipkl->allocated, n,
				    sizeof(dns_name_t *));
	ipkl->tlss = isc_mem_creget(mctx, ipkl->addrs, ipkl->allocated, n,
				    sizeof(dns_name_t *));
	ipkl->labels = isc_mem_creget(mctx, ipkl->addrs, ipkl->allocated, n,
				      sizeof(dns_name_t *));

	ipkl->allocated = n;
	return (ISC_R_SUCCESS);
}
