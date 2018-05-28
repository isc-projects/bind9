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

#include <config.h>

#include <isc/entropy.h>
#include <isc/util.h>

#if HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>

void
isc_entropy_get(void *buf, size_t buflen) {
	if (RAND_bytes(buf, buflen) < 1) {
		FATAL_ERROR(__FILE__,
			    __LINE__,
			    "RAND_bytes(): %s",
			    ERR_error_string(ERR_get_error(), NULL));
	}
}

#elif HAVE_PKCS11
#include <pk11/pk11.h>

void
isc_entropy_get(void *buf, size_t buflen) {
	RUNTIME_CHECK(pk11_rand_bytes(buf, buflen) == ISC_R_SUCCESS);
}

#endif /* if HAVE_PKCS11 */
