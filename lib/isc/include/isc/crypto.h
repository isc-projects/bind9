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

#include <stddef.h>
#include <stdint.h>

#include <isc/md.h>
#include <isc/region.h>
#include <isc/types.h>

isc_result_t
isc_crypto_hkdf_extract(isc_region_t out, isc_md_type_t md,
			isc_constregion_t secret, isc_constregion_t salt);
/**<
 * HKDF-Extract as specified by RFC5869.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `secret.base != NULL` and `secret.length != 0`
 * - `salt.base != NULL` and `sakt.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_hkdf_expand(isc_region_t out, isc_md_type_t md,
		       isc_constregion_t prk, isc_constregion_t info);
/**<
 * HKDF-Expand as specified by RFC5869.
 *
 * Please note that `prk` can't be just substituted with the output of any
 * secret function. Please refer to RFC5869 Section 3.3 for more information on
 * what key values are appropriate for calling HKDF-Expand.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `prk.base != NULL` and `prk.length != 0`
 * - `info.base != NULL` and `info.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_hkdf_expand_label(isc_region_t out, isc_md_type_t md,
			     isc_constregion_t secret, isc_constregion_t label);
/**<
 * \brief
 * HKDF-Expand-Label as specified by RFC 8446 Section 7.1.
 * The context parameter is not supported and is passed as empty.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `secret.base != NULL` and `secret.length != 0`
 * - `label.base != NULL` and `label.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

isc_result_t
isc_crypto_hkdf(isc_region_t out, isc_md_type_t md, isc_constregion_t secret,
		isc_constregion_t salt, isc_constregion_t info);
/**<
 * \brief
 * HKDF-Extract-Expand as specified by RFC5869.
 *
 * Requires:
 * - `out.base != NULL` and `out.length != 0`
 * - `md` must be a valid hash type.
 * - `ikm.base != NULL` and `ikm.length != 0`
 * - `salt.base != NULL` and `ikm.length != 0`
 * - `info.base != NULL` and `info.length != 0`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTIMPLEMENTED if the hash function is not supported
 * \retval ISC_R_CRYPTOFAILURE on libcrypto failure
 */

bool
isc_crypto_fips_mode(void);
/*
 * Return if FIPS mode is currently enabled or not.
 */

isc_result_t
isc_crypto_fips_enable(void);
/*
 * Enable FIPS mode. It cannot be disabled afterwards.
 *
 * This function is NOT thread safe.
 */

/**
 * Private
 */

void
isc__crypto_setdestroycheck(bool check);

void
isc__crypto_initialize(void);

void
isc__crypto_shutdown(void);
