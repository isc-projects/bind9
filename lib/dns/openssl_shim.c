/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include "openssl_shim.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#if !HAVE_ECDSA_SIG_GET0
/* From OpenSSL 1.1 */
void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
	if (pr != NULL) {
		*pr = sig->r;
	}
	if (ps != NULL) {
		*ps = sig->s;
	}
}

int
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) {
		return (0);
	}

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return (1);
}
#endif /* !HAVE_ECDSA_SIG_GET0 */

#if !HAVE_ERR_GET_ERROR_ALL
static const char err_empty_string = '\0';

unsigned long
ERR_get_error_all(const char **file, int *line, const char **func,
		  const char **data, int *flags) {
	if (func != NULL) {
		*func = &err_empty_string;
	}
	return (ERR_get_error_line_data(file, line, data, flags));
}
#endif /* if !HAVE_ERR_GET_ERROR_ALL */
