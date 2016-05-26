/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/util.h>

#include <dns/ipkeylist.h>
#include <dns/name.h>

void
dns_ipkeylist_clear(isc_mem_t *mctx, dns_ipkeylist_t *ipkl) {
	isc_uint32_t i;

	REQUIRE(ipkl != NULL);
	REQUIRE(ipkl->addrs != NULL);
	REQUIRE(ipkl->keys != NULL);

	if (ipkl->count == 0)
		return;

	isc_mem_put(mctx, ipkl->addrs, ipkl->count * sizeof(isc_sockaddr_t));
	if (ipkl->dscps != NULL)
		isc_mem_put(mctx, ipkl->dscps,
			    ipkl->count * sizeof(isc_dscp_t));
	for (i = 0; i < ipkl->count; i++) {
		if (ipkl->keys[i] == NULL)
			continue;
		if (dns_name_dynamic(ipkl->keys[i]))
			dns_name_free(ipkl->keys[i], mctx);
		isc_mem_put(mctx, ipkl->keys[i], sizeof(dns_name_t));
	}
	isc_mem_put(mctx, ipkl->keys, ipkl->count * sizeof(dns_name_t *));
	ipkl->count = 0;
	ipkl->addrs = NULL;
	ipkl->dscps = NULL;
	ipkl->keys = NULL;
}

void
dns_ipkeylist_copy(isc_mem_t *mctx, const dns_ipkeylist_t *src,
		   dns_ipkeylist_t *dst)
{
	isc_uint32_t i;

	REQUIRE(dst != NULL);
	REQUIRE(dst->count == 0 &&
		dst->addrs == NULL && dst->keys == NULL && dst->dscps == NULL);

	if (src->count == 0)
		return;

	dst->count = src->count;

	dst->addrs = isc_mem_get(mctx,
				 src->count * sizeof(isc_sockaddr_t));
	memmove(dst->addrs, src->addrs,
		src->count * sizeof(isc_sockaddr_t));

	if (src->dscps != NULL) {
		dst->dscps = isc_mem_get(mctx,
					 src->count * sizeof(isc_dscp_t));
		memmove(dst->dscps, src->dscps,
			src->count * sizeof(isc_dscp_t));
	}

	if (src->keys != NULL) {
		dst->keys = isc_mem_get(mctx, src->count * sizeof(dns_name_t *));
		for (i = 0; i < src->count; i++) {
			if (src->keys[i] != NULL) {
				dst->keys[i] = isc_mem_get(mctx,
							   sizeof(dns_name_t));
				dns_name_dup(src->keys[i], mctx, dst->keys[i]);
			} else {
				dst->keys[i] = NULL;
			}
		}
	}
}
