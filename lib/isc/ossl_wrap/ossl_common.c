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

#include <openssl/bn.h>
#include <openssl/err.h>

#include <isc/ossl_wrap.h>
#include <isc/util.h>

#include "../openssl_shim.h"

void
isc_ossl_wrap_rsa_components_cleanup(isc_ossl_wrap_rsa_components_t *c) {
	REQUIRE(c != NULL);

	if (!c->needs_cleanup) {
		return;
	}

	/*
	 * NOTE: BN_free() frees the components of the BIGNUM, and if it was
	 * created by BN_new(), also the structure itself. BN_clear_free()
	 * additionally overwrites the data before the memory is returned to the
	 * system. If a is NULL, nothing is done.
	 */
	BN_free(c->e);
	BN_free(c->n);
	BN_clear_free(c->d);
	BN_clear_free(c->p);
	BN_clear_free(c->q);
	BN_clear_free(c->dmp1);
	BN_clear_free(c->dmq1);
	BN_clear_free(c->iqmp);

	c->needs_cleanup = false;
}

bool
isc_ossl_wrap_rsa_exponent_in_range(const BIGNUM *e) {
	int bits;

	REQUIRE(e != NULL);

	/*
	 * The accepted public exponents are the odd numbers in the closed
	 * range [3, 2^32 + 1].  The range is checked by looking at the bits
	 * of the number, so no BIGNUM constants are needed to compare with.
	 */
	if (BN_is_negative(e) || !BN_is_odd(e)) {
		return false;
	}

	bits = BN_num_bits(e);

	/* One bit means e == 1, more than 33 bits mean e >= 2^33. */
	if (bits < 2 || bits > 33) {
		return false;
	}

	/* An odd number with 2 to 32 bits is within [3, 2^32 - 1]. */
	if (bits <= 32) {
		return true;
	}

	/*
	 * That leaves the numbers with exactly 33 bits, [2^32, 2^33 - 1].
	 * Bit 32 is set in all of them, and bit 0 is set because the number
	 * is odd.  The only one still in the range is 2^32 + 1, which is the
	 * one that has none of the bits in between set.
	 */
	for (int bit = 1; bit < 32; bit++) {
		if (BN_is_bit_set(e, bit)) {
			return false;
		}
	}

	return true;
}

isc_result_t
isc_ossl_wrap_toresult(isc_result_t fallback) {
	isc_result_t result = fallback;
	unsigned long err = ERR_peek_error();
#ifdef ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED
	int lib = ERR_GET_LIB(err);
#endif /* ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED */
	int reason = ERR_GET_REASON(err);

	switch (reason) {
	/*
	 * ERR_* errors are globally unique; others
	 * are unique per sublibrary
	 */
	case ERR_R_MALLOC_FAILURE:
		result = ISC_R_NOMEMORY;
		break;
	default:
#ifdef ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED
		if (lib == ERR_R_ECDSA_LIB &&
		    reason == ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
		{
			result = ISC_R_NOENTROPY;
			break;
		}
#endif /* ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED */
		break;
	}

	return result;
}

isc_result_t
isc__ossl_wrap_logged_toresult(isc_logcategory_t category,
			       isc_logmodule_t module, const char *funcname,
			       isc_result_t fallback, const char *file,
			       int line) {
	isc_result_t result = isc_ossl_wrap_toresult(fallback);

	/*
	 * This is an exception - normally, we don't allow this, but the
	 * compatibility shims in dst_openssl.h needs a call that just
	 * translates the error code and don't do any logging.
	 */
	if (category == ISC_LOGCATEGORY_INVALID) {
		goto done;
	}

	isc_log_write(category, module, ISC_LOG_WARNING,
		      "%s (%s:%d) failed (%s)", funcname, file, line,
		      isc_result_totext(result));

	if (result == ISC_R_NOMEMORY) {
		goto done;
	}

	for (;;) {
		const char *func, *data;
		int flags;
		unsigned long err = ERR_get_error_all(&file, &line, &func,
						      &data, &flags);
		if (err == 0U) {
			break;
		}

		char buf[256];
		ERR_error_string_n(err, buf, sizeof(buf));

		isc_log_write(category, module, ISC_LOG_INFO, "%s:%s:%d:%s",
			      buf, file, line,
			      ((flags & ERR_TXT_STRING) != 0) ? data : "");
	}

done:
	ERR_clear_error();
	return result;
}
