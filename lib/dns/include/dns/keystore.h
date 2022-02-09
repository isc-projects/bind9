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

#pragma once

/*****
***** Module Info
*****/

/*! \file dns/keystore.h
 * \brief
 * DNSSEC Key Store
 *
 * A key store defines where to store DNSSEC keys.
 */

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/mutex.h>
#include <isc/refcount.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

/* Key store */
struct dns_keystore {
	unsigned int magic;
	isc_mem_t   *mctx;
	const char  *name;
	const char  *engine;

	/* Internals. */
	isc_mutex_t lock;

	/* Locked by themselves. */
	isc_refcount_t references;

	/* Under owner's locking control. */
	ISC_LINK(struct dns_keystore) link;

	/* Configuration values */
	char *directory;
	char *pkcs11uri;
};

#define DNS_KEYSTORE_MAGIC     ISC_MAGIC('K', 'E', 'Y', 'S')
#define DNS_KEYSTORE_VALID(ks) ISC_MAGIC_VALID(ks, DNS_KEYSTORE_MAGIC)

#define DNS_KEYSTORE_KEYDIRECTORY "key-directory"

isc_result_t
dns_keystore_create(isc_mem_t *mctx, const char *name, dns_keystore_t **kspp);
/*%<
 * Create a key store.
 *
 * Requires:
 *
 *\li  'mctx' is a valid memory context.
 *
 *\li  'name' is a valid C string.
 *
 *\li  kspp != NULL && *kspp == NULL
 *
 * Returns:
 *
 *\li  #ISC_R_SUCCESS
 *\li  #ISC_R_NOMEMORY
 *
 *\li  Other errors are possible.
 */

void
dns_keystore_attach(dns_keystore_t *source, dns_keystore_t **targetp);
/*%<
 * Attach '*targetp' to 'source'.
 *
 * Requires:
 *
 *\li   'source' is a valid keystore.
 *
 *\li   'targetp' points to a NULL dns_keystore_t *.
 *
 * Ensures:
 *
 *\li   *targetp is attached to source.
 *
 *\li   While *targetp is attached, the keystore will not shut down.
 */

void
dns_keystore_detach(dns_keystore_t **kspp);
/*%<
 * Detach keystore.
 *
 * Requires:
 *
 *\li   'kspp' points to a valid dns_keystore_t *
 *
 * Ensures:
 *
 *\li   *kspp is NULL.
 */

const char *
dns_keystore_name(dns_keystore_t *keystore);
/*%<
 * Get keystore name.
 *
 * Requires:
 *
 *\li   'keystore' is a valid keystore.
 *
 * Returns:
 *
 *\li   name of 'keystore'.
 */

const char *
dns_keystore_directory(dns_keystore_t *keystore);
/*%<
 * Get keystore directory.
 *
 * Requires:
 *
 *\li   'keystore' is a valid keystore.
 *
 * Returns:
 *
 *\li   directory of 'keystore'.
 */

void
dns_keystore_setdirectory(dns_keystore_t *keystore, const char *dir);
/*%<
 * Set keystore directory.
 *
 * Requires:
 *
 *\li   'keystore' is a valid keystore.
 *
 */

const char *
dns_keystore_pkcs11uri(dns_keystore_t *keystore);
/*%<
 * Get keystore PKCS#11 URI.
 *
 * Requires:
 *
 *\li   'keystore' is a valid keystore.
 *
 * Returns:
 *
 *\li   PKCS#11 URI of 'keystore'.
 */

void
dns_keystore_setpkcs11uri(dns_keystore_t *keystore, const char *uri);
/*%<
 * Set keystore PKCS#11 URI.
 *
 * Requires:
 *
 *\li   'keystore' is a valid keystore.
 *
 */

isc_result_t
dns_keystorelist_find(dns_keystorelist_t *list, const char *name,
		      dns_keystore_t **kspp);
/*%<
 * Search for a keystore with name 'name' in 'list'.
 * If found, '*kspp' is (strongly) attached to it.
 *
 * Requires:
 *
 *\li   'kspp' points to a NULL dns_keystore_t *.
 *
 * Returns:
 *
 *\li   #ISC_R_SUCCESS          A matching keystore was found.
 *\li   #ISC_R_NOTFOUND         No matching keystore was found.
 */

ISC_LANG_ENDDECLS
