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

/*! \file */

#include <string.h>

#include <isc/assertions.h>
#include <isc/file.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/kasp.h>
#include <dns/keyvalues.h>

isc_result_t
dns_kasp_create(isc_mem_t *mctx, const char *name, dns_kasp_t **kaspp)
{
	dns_kasp_t *kasp;

	REQUIRE(name != NULL);
	REQUIRE(kaspp != NULL && *kaspp == NULL);

	kasp = isc_mem_get(mctx, sizeof(*kasp));
	kasp->mctx = NULL;
	isc_mem_attach(mctx, &kasp->mctx);

	kasp->name = isc_mem_strdup(mctx, name);
	isc_mutex_init(&kasp->lock);
	kasp->frozen = false;

	isc_refcount_init(&kasp->references, 1);

	ISC_LINK_INIT(kasp, link);

	kasp->signatures_refresh = DNS_KASP_SIG_REFRESH;
	kasp->signatures_validity = DNS_KASP_SIG_VALIDITY;
	kasp->signatures_validity_dnskey = DNS_KASP_SIG_VALIDITY_DNSKEY;

	ISC_LIST_INIT(kasp->keys);

	kasp->dnskey_ttl = DNS_KASP_KEY_TTL;
	kasp->publish_safety = DNS_KASP_PUBLISH_SAFETY;
	kasp->retire_safety = DNS_KASP_RETIRE_SAFETY;

	kasp->zone_max_ttl = DNS_KASP_ZONE_MAXTTL;
	kasp->zone_propagation_delay = DNS_KASP_ZONE_PROPDELAY;

	kasp->parent_ds_ttl = DNS_KASP_DS_TTL;
	kasp->parent_propagation_delay = DNS_KASP_PARENT_PROPDELAY;
	kasp->parent_registration_delay = DNS_KASP_PARENT_REGDELAY;

	// TODO: The rest of the KASP configuration

	kasp->magic = DNS_KASP_MAGIC;
	*kaspp = kasp;

	return (ISC_R_SUCCESS);
}

void
dns_kasp_attach(dns_kasp_t *source, dns_kasp_t **targetp) {
	REQUIRE(DNS_KASP_VALID(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);
	*targetp = source;
}

static inline void
destroy(dns_kasp_t *kasp) {
	dns_kasp_key_t *key;
	dns_kasp_key_t *key_next;

	for (key = ISC_LIST_HEAD(kasp->keys); key != NULL; key = key_next) {
		key_next = ISC_LIST_NEXT(key, link);
		ISC_LIST_UNLINK(kasp->keys, key, link);
		dns_kasp_key_destroy(key);
	}
	ISC_INSIST(ISC_LIST_EMPTY(kasp->keys));

	isc_mem_free(kasp->mctx, kasp->name);
	isc_mem_putanddetach(&kasp->mctx, kasp, sizeof(*kasp));
}

void
dns_kasp_detach(dns_kasp_t **kaspp) {
	REQUIRE(kaspp != NULL && DNS_KASP_VALID(*kaspp));
	dns_kasp_t *kasp = *kaspp;
	*kaspp = NULL;

	if (isc_refcount_decrement(&kasp->references) == 1) {
		destroy(kasp);
	}
}

const char*
dns_kasp_getname(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	return kasp->name;
}

void
dns_kasp_freeze(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(!kasp->frozen);
	kasp->frozen = true;
}

void
dns_kasp_thaw(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	kasp->frozen = false;
}

uint32_t
dns_kasp_signdelay(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return (kasp->signatures_validity - kasp->signatures_refresh);
}

uint32_t
dns_kasp_sigrefresh(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->signatures_refresh;
}

uint32_t
dns_kasp_sigvalidity(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->signatures_validity;
}

uint32_t
dns_kasp_sigvalidity_dnskey(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->signatures_validity_dnskey;
}

dns_ttl_t
dns_kasp_dnskeyttl(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->dnskey_ttl;
}

uint32_t
dns_kasp_publishsafety(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->publish_safety;
}

uint32_t
dns_kasp_retiresafety(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->retire_safety;
}

dns_ttl_t
dns_kasp_zonemaxttl(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->zone_max_ttl;
}

uint32_t
dns_kasp_zonepropagationdelay(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->zone_propagation_delay;
}

dns_ttl_t
dns_kasp_dsttl(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->parent_ds_ttl;
}

uint32_t
dns_kasp_parentpropagationdelay(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->parent_propagation_delay;
}

uint32_t
dns_kasp_parentregistrationdelay(dns_kasp_t *kasp) {
	REQUIRE(DNS_KASP_VALID(kasp));
	REQUIRE(kasp->frozen);
	return kasp->parent_registration_delay;
}

isc_result_t
dns_kasplist_find(dns_kasplist_t *list, const char *name, dns_kasp_t **kaspp)
{
	dns_kasp_t *kasp = NULL;

	if (list == NULL) {
		return (ISC_R_NOTFOUND);
	}
	INSIST(list != NULL);

	for (kasp = ISC_LIST_HEAD(*list); kasp != NULL;
	     kasp = ISC_LIST_NEXT(kasp, link))
	{
		if (strcmp(kasp->name, name) == 0) {
			break;
		}
	}
	if (kasp == NULL) {
		return (ISC_R_NOTFOUND);
	}
	dns_kasp_attach(kasp, kaspp);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_kasp_key_create(isc_mem_t* mctx, dns_kasp_key_t **keyp)
{
	dns_kasp_key_t *key;

	REQUIRE(keyp != NULL && *keyp == NULL);

	key = isc_mem_get(mctx, sizeof(*key));
	key->mctx = NULL;
	isc_mem_attach(mctx, &key->mctx);

	ISC_LINK_INIT(key, link);

	key->lifetime = 0;
	key->algorithm = 0;
	key->length = -1;
	key->role = 0;
	*keyp = key;
	return (ISC_R_SUCCESS);
}

void
dns_kasp_key_destroy(dns_kasp_key_t* key)
{
	REQUIRE(key != NULL);
	isc_mem_putanddetach(&key->mctx, key, sizeof(*key));
}

uint32_t
dns_kasp_key_algorithm(dns_kasp_key_t *key) {

	REQUIRE(key != NULL);
	return key->algorithm;
}

unsigned int
dns_kasp_key_size(dns_kasp_key_t *key) {
	unsigned int size = 0;
	unsigned int min = 0;

	REQUIRE(key != NULL);

	switch (key->algorithm) {
	case DNS_KEYALG_RSASHA1:
	case DNS_KEYALG_NSEC3RSASHA1:
	case DNS_KEYALG_RSASHA256:
	case DNS_KEYALG_RSASHA512:
		min = DNS_KEYALG_RSASHA512 ? 1024 : 512;
		if (key->length > -1) {
			size = (unsigned int) key->length;
			if (size < min) {
				size = min;
			}
			if (size > 4096) {
				size = 4096;
			}
		} else if (key->role & DNS_KASP_KEY_ROLE_KSK) {
			size = 2048;
		} else {
			size = 1024;
		}
		break;
	case DNS_KEYALG_ECDSA256:
		size = 256;
		break;
	case DNS_KEYALG_ECDSA384:
		size = 384;
		break;
	case DNS_KEYALG_ED25519:
		size = 32;
		break;
	case DNS_KEYALG_ED448:
		size = 57;
		break;
	default:
		/* unsupported */
		break;
	}
	return size;
}

uint32_t
dns_kasp_key_lifetime(dns_kasp_key_t *key) {

	REQUIRE(key != NULL);
	return (key->lifetime);
}

bool
dns_kasp_key_ksk(dns_kasp_key_t *key) {

	REQUIRE(key != NULL);
	return (key->role & DNS_KASP_KEY_ROLE_KSK);
}

bool
dns_kasp_key_zsk(dns_kasp_key_t *key) {

	REQUIRE(key != NULL);
	return (key->role & DNS_KASP_KEY_ROLE_ZSK);
}
