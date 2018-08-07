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

#include <stdbool.h>
#include <stdlib.h>

#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/types.h>

#include <dst/gssapi.h>

isc_result_t
dst_gssapi_acquirecred(const dns_name_t *name, bool initiate,
		       gss_cred_id_t *cred) {
	REQUIRE(cred != NULL && *cred == NULL);

	UNUSED(name);
	UNUSED(initiate);
	UNUSED(cred);

	return (ISC_R_NOTIMPLEMENTED);
}

bool
dst_gssapi_identitymatchesrealmkrb5(const dns_name_t *signer,
				    const dns_name_t *name,
				    const dns_name_t *realm, bool subdomain) {
	UNUSED(signer);
	UNUSED(name);
	UNUSED(realm);
	UNUSED(subdomain);

	return (false);
}

bool
dst_gssapi_identitymatchesrealmms(const dns_name_t *signer,
				  const dns_name_t *name,
				  const dns_name_t *realm, bool subdomain) {
	UNUSED(signer);
	UNUSED(name);
	UNUSED(realm);
	UNUSED(subdomain);

	return (false);
}

isc_result_t
dst_gssapi_releasecred(gss_cred_id_t *cred) {
	UNUSED(cred);

	return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
dst_gssapi_initctx(const dns_name_t *name, isc_buffer_t *intoken,
		   isc_buffer_t *outtoken, gss_ctx_id_t *gssctx,
		   isc_mem_t *mctx, char **err_message) {
	UNUSED(name);
	UNUSED(intoken);
	UNUSED(outtoken);
	UNUSED(gssctx);
	UNUSED(mctx);
	UNUSED(err_message);

	return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
dst_gssapi_acceptctx(gss_cred_id_t cred, const char *gssapi_keytab,
		     isc_region_t *intoken, isc_buffer_t **outtoken,
		     gss_ctx_id_t *ctxout, dns_name_t *principal,
		     isc_mem_t *mctx) {
	UNUSED(cred);
	UNUSED(gssapi_keytab);
	UNUSED(intoken);
	UNUSED(outtoken);
	UNUSED(ctxout);
	UNUSED(principal);
	UNUSED(mctx);

	return (ISC_R_NOTIMPLEMENTED);
}

isc_result_t
dst_gssapi_deletectx(isc_mem_t *mctx, gss_ctx_id_t *gssctx) {
	UNUSED(mctx);
	UNUSED(gssctx);
	return (ISC_R_NOTIMPLEMENTED);
}

/*! \file */
