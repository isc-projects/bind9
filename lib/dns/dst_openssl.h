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

#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <isc/lang.h>
#include <isc/log.h>
#include <isc/result.h>
#include <isc/tls.h>

ISC_LANG_BEGINDECLS

#define dst__openssl_toresult(fallback) \
	isc__tlserr2result(NULL, NULL, NULL, fallback, __FILE__, __LINE__)
#define dst__openssl_toresult2(funcname, fallback)                        \
	isc__tlserr2result(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO, \
			   funcname, fallback, __FILE__, __LINE__)
#define dst__openssl_toresult3(category, funcname, fallback)                   \
	isc__tlserr2result(category, DNS_LOGMODULE_CRYPTO, funcname, fallback, \
			   __FILE__, __LINE__)

isc_result_t
dst__openssl_fromlabel(int key_base_id, const char *label, const char *pin,
		       EVP_PKEY **ppub, EVP_PKEY **ppriv);

bool
dst__openssl_keypair_compare(const dst_key_t *key1, const dst_key_t *key2);

bool
dst__openssl_keypair_isprivate(const dst_key_t *key);

void
dst__openssl_keypair_destroy(dst_key_t *key);

ISC_LANG_ENDDECLS
