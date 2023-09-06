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

#include <isc/assertions.h>
#include <isc/mem.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/keystore.h>
#include <dns/keyvalues.h>

isc_result_t
dns_keystore_create(isc_mem_t *mctx, const char *name, const char *engine,
		    dns_keystore_t **kspp) {
	dns_keystore_t *keystore;

	REQUIRE(name != NULL);
	REQUIRE(kspp != NULL && *kspp == NULL);

	keystore = isc_mem_get(mctx, sizeof(*keystore));
	keystore->engine = engine;
	keystore->mctx = NULL;
	isc_mem_attach(mctx, &keystore->mctx);

	keystore->name = isc_mem_strdup(mctx, name);
	isc_mutex_init(&keystore->lock);

	isc_refcount_init(&keystore->references, 1);

	ISC_LINK_INIT(keystore, link);

	keystore->directory = NULL;
	keystore->pkcs11uri = NULL;

	keystore->magic = DNS_KEYSTORE_MAGIC;
	*kspp = keystore;

	return (ISC_R_SUCCESS);
}

void
dns_keystore_attach(dns_keystore_t *source, dns_keystore_t **targetp) {
	REQUIRE(DNS_KEYSTORE_VALID(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);
	*targetp = source;
}

static inline void
destroy(dns_keystore_t *keystore) {
	char *name;

	REQUIRE(!ISC_LINK_LINKED(keystore, link));

	isc_mutex_destroy(&keystore->lock);
	name = UNCONST(keystore->name);
	isc_mem_free(keystore->mctx, name);
	if (keystore->directory != NULL) {
		isc_mem_free(keystore->mctx, keystore->directory);
	}
	if (keystore->pkcs11uri != NULL) {
		isc_mem_free(keystore->mctx, keystore->pkcs11uri);
	}
	isc_mem_putanddetach(&keystore->mctx, keystore, sizeof(*keystore));
}

void
dns_keystore_detach(dns_keystore_t **kspp) {
	REQUIRE(kspp != NULL && DNS_KEYSTORE_VALID(*kspp));

	dns_keystore_t *ks = *kspp;
	*kspp = NULL;

	if (isc_refcount_decrement(&ks->references) == 1) {
		destroy(ks);
	}
}

const char *
dns_keystore_name(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->name);
}

const char *
dns_keystore_engine(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->engine);
}

const char *
dns_keystore_directory(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->directory);
}

void
dns_keystore_setdirectory(dns_keystore_t *keystore, const char *dir) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	if (keystore->directory != NULL) {
		isc_mem_free(keystore->mctx, keystore->directory);
	}
	keystore->directory = (dir == NULL)
				      ? NULL
				      : isc_mem_strdup(keystore->mctx, dir);
}

const char *
dns_keystore_pkcs11uri(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return (keystore->pkcs11uri);
}

void
dns_keystore_setpkcs11uri(dns_keystore_t *keystore, const char *uri) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	if (keystore->pkcs11uri != NULL) {
		isc_mem_free(keystore->mctx, keystore->pkcs11uri);
	}
	keystore->pkcs11uri = (uri == NULL)
				      ? NULL
				      : isc_mem_strdup(keystore->mctx, uri);
}

isc_result_t
dns_keystore_keygen(dns_keystore_t *keystore, const dns_name_t *origin,
		    dns_rdataclass_t rdclass, isc_mem_t *mctx, uint32_t alg,
		    int size, int flags, dst_key_t **dstkey) {
	isc_result_t result;
	dst_key_t *newkey = NULL;
	const char *uri = NULL;

	REQUIRE(DNS_KEYSTORE_VALID(keystore));
	REQUIRE(dns_name_isvalid(origin));
	REQUIRE(mctx != NULL);
	REQUIRE(dstkey != NULL && *dstkey == NULL);

	uri = dns_keystore_pkcs11uri(keystore);
	if (uri != NULL) {
		dst_key_t *key = NULL;
		char *label = NULL;
		size_t len;
		char timebuf[18];
		isc_time_t now = isc_time_now();
		bool ksk = ((flags & DNS_KEYFLAG_KSK) != 0);
		char namebuf[DNS_NAME_FORMATSIZE];
		char object[DNS_NAME_FORMATSIZE + 26];

		/* Create the PKCS11 URI */
		isc_time_formatshorttimestamp(&now, timebuf, sizeof(timebuf));
		dns_name_format(origin, namebuf, sizeof(namebuf));
		snprintf(object, sizeof(object), "%s-%s-%s", namebuf,
			 ksk ? "ksk" : "zsk", timebuf);
		len = strlen(object) + strlen(uri) + 10;
		label = isc_mem_get(mctx, len);
		sprintf(label, "%s;object=%s;", uri, object);

		/* Generate the key */
		result = dst_key_generate(origin, alg, size, 0, flags,
					  DNS_KEYPROTO_DNSSEC, rdclass, label,
					  mctx, &key, NULL);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
				      DNS_LOGMODULE_DNSSEC, ISC_LOG_ERROR,
				      "keystore: failed to generate key "
				      "%s (ret=%d)",
				      object, result);
			return (result);
		}
		dst_key_free(&key);

		/* Retrieve generated key from label */
		result = dst_key_fromlabel(
			origin, alg, flags, DNS_KEYPROTO_DNSSEC,
			dns_rdataclass_in, dns_keystore_engine(keystore), label,
			NULL, mctx, &newkey);

		isc_mem_put(mctx, label, len);

		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
				      DNS_LOGMODULE_DNSSEC, ISC_LOG_ERROR,
				      "keystore: failed to access key "
				      "%s (ret=%d)",
				      object, result);
			return (result);
		}
	} else {
		result = dst_key_generate(origin, alg, size, 0, flags,
					  DNS_KEYPROTO_DNSSEC, rdclass, NULL,
					  mctx, &newkey, NULL);
	}

	if (result == ISC_R_SUCCESS) {
		*dstkey = newkey;
	}
	return (result);
}

isc_result_t
dns_keystorelist_find(dns_keystorelist_t *list, const char *name,
		      dns_keystore_t **kspp) {
	dns_keystore_t *keystore = NULL;

	REQUIRE(kspp != NULL && *kspp == NULL);

	if (list == NULL) {
		return (ISC_R_NOTFOUND);
	}

	for (keystore = ISC_LIST_HEAD(*list); keystore != NULL;
	     keystore = ISC_LIST_NEXT(keystore, link))
	{
		if (strcmp(keystore->name, name) == 0) {
			break;
		}
	}

	if (keystore == NULL) {
		return (ISC_R_NOTFOUND);
	}

	dns_keystore_attach(keystore, kspp);
	return (ISC_R_SUCCESS);
}
