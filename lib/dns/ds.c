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

#include <isc/buffer.h>
#include <isc/md.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/ds.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>

#include <dst/dst.h>

isc_result_t
dns_ds_fromkeyrdata(const dns_name_t *owner, dns_rdata_t *key,
		    dns_dsdigest_t digest_type, unsigned char *digest,
		    size_t len, dns_rdata_ds_t *dsrdata) {
	isc_result_t result;
	dns_fixedname_t fname;
	dns_name_t *name;
	unsigned int digestlen = 0;
	unsigned int privatelen = 0;
	isc_region_t r;
	isc_md_t *md;
	const isc_md_type_t *md_type = NULL;

	REQUIRE(key != NULL);
	REQUIRE(key->type == dns_rdatatype_dnskey ||
		key->type == dns_rdatatype_cdnskey);
	REQUIRE(digest != NULL);

	if (!dst_ds_digest_supported(digest_type)) {
		return ISC_R_NOTIMPLEMENTED;
	}

	switch (digest_type) {
	case DNS_DSDIGEST_SHA1:
		md_type = ISC_MD_SHA1;
		break;

	case DNS_DSDIGEST_SHA384:
#ifdef DNS_DSDIGEST_SHA384PRIVATE
	case DNS_DSDIGEST_SHA384PRIVATE:
#endif
		md_type = ISC_MD_SHA384;
		break;

	case DNS_DSDIGEST_SHA256:
#ifdef DNS_DSDIGEST_SHA256PRIVATE
	case DNS_DSDIGEST_SHA256PRIVATE:
#endif
		md_type = ISC_MD_SHA256;
		break;

	default:
		UNREACHABLE();
	}

	name = dns_fixedname_initname(&fname);
	(void)dns_name_downcase(owner, name);

	md = isc_md_new();

	result = isc_md_init(md, md_type);
	if (result != ISC_R_SUCCESS) {
		goto end;
	}

	dns_name_toregion(name, &r);

	result = isc_md_update(md, r.base, r.length);
	if (result != ISC_R_SUCCESS) {
		goto end;
	}

	dns_rdata_toregion(key, &r);
	INSIST(r.length >= 4);

	result = isc_md_update(md, r.base, r.length);
	if (result != ISC_R_SUCCESS) {
		goto end;
	}

#if defined(DNS_DSDIGEST_SHA256PRIVATE) && defined(DNS_DSDIGEST_SHA384PRIVATE)
	/*
	 * Insert PRIVATE algorithm identify at start of digest.
	 */
	switch (digest_type) {
	case DNS_DSDIGEST_SHA1:
	case DNS_DSDIGEST_SHA256:
	case DNS_DSDIGEST_SHA384:
		break;
	case DNS_DSDIGEST_SHA256PRIVATE:
	case DNS_DSDIGEST_SHA384PRIVATE:
		switch (r.base[3]) {
		case DNS_KEYALG_PRIVATEDNS: {
			isc_region_t r2 = r;
			INSIST(r2.length >= 5);
			isc_region_consume(&r2, 4);
			dns_name_fromregion(name, &r2);
			dns_name_toregion(name, &r2);
			privatelen = r2.length;
			if (r2.length > len) {
				result = ISC_R_NOSPACE;
				goto end;
			}
			memmove(digest, r2.base, privatelen);
			digest += privatelen;
			len -= privatelen;
			break;
		}
		case DNS_KEYALG_PRIVATEOID: {
			isc_region_t r2 = r;
			INSIST(r2.length >= 5);
			isc_region_consume(&r2, 4);
			privatelen = r2.base[0] + 1;
			if (r2.base[0] > len) {
				result = ISC_R_NOSPACE;
				goto end;
			}
			INSIST(r2.length >= privatelen);
			memmove(digest, r2.base, privatelen);
			digest += privatelen;
			len -= privatelen;
			break;
		}
		default:
			break;
		}
		break;
	default:
		break;
	}
#endif

	size_t mdsize = isc_md_get_size(md);
	if (mdsize > len) {
		result = ISC_R_NOSPACE;
		goto end;
	}

	result = isc_md_final(md, digest, &digestlen);
	if (result != ISC_R_SUCCESS) {
		goto end;
	}

	dsrdata->mctx = NULL;
	dsrdata->common.rdclass = key->rdclass;
	dsrdata->common.rdtype = dns_rdatatype_ds;
	dsrdata->algorithm = r.base[3];
	dsrdata->key_tag = dst_region_computeid(&r);
	dsrdata->digest_type = digest_type;
	dsrdata->digest = digest - privatelen;
	dsrdata->length = digestlen + privatelen;

end:
	isc_md_free(md);
	return result;
}

isc_result_t
dns_ds_buildrdata(dns_name_t *owner, dns_rdata_t *key,
		  dns_dsdigest_t digest_type, unsigned char *buffer, size_t len,
		  dns_rdata_t *rdata) {
	isc_result_t result;
	unsigned char digest[ISC_MAX_MD_SIZE];
	dns_rdata_ds_t ds;
	isc_buffer_t b;

	result = dns_ds_fromkeyrdata(owner, key, digest_type, digest, len, &ds);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	memset(buffer, 0, DNS_DS_BUFFERSIZE);
	isc_buffer_init(&b, buffer, DNS_DS_BUFFERSIZE);
	result = dns_rdata_fromstruct(rdata, key->rdclass, dns_rdatatype_ds,
				      &ds, &b);
	return result;
}
