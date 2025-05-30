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

#include <inttypes.h> /* IWYU pragma: keep */
#include <stdbool.h>
#include <time.h> /* IWYU pragma: keep */

#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif

#if HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#elif HAVE_GSSAPI_KRB5_H
#include <gssapi_krb5.h>
#endif

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dst/gssapi.h>

#include "dst_internal.h"
#include "dst_parse.h"

#define INITIAL_BUFFER_SIZE 1024
#define BUFFER_EXTRA	    1024

#define REGION_TO_GBUFFER(r, gb)          \
	do {                              \
		(gb).length = (r).length; \
		(gb).value = (r).base;    \
	} while (0)

#define GBUFFER_TO_REGION(gb, r)                        \
	do {                                            \
		(r).length = (unsigned int)(gb).length; \
		(r).base = (gb).value;                  \
	} while (0)

struct dst_gssapi_signverifyctx {
	isc_buffer_t *buffer;
};

/*%
 * Allocate a temporary "context" for use in gathering data for signing
 * or verifying.
 */
static isc_result_t
gssapi_create_signverify_ctx(dst_key_t *key, dst_context_t *dctx) {
	dst_gssapi_signverifyctx_t *ctx;

	UNUSED(key);

	ctx = isc_mem_get(dctx->mctx, sizeof(dst_gssapi_signverifyctx_t));
	ctx->buffer = NULL;
	isc_buffer_allocate(dctx->mctx, &ctx->buffer, INITIAL_BUFFER_SIZE);

	dctx->ctxdata.gssctx = ctx;

	return ISC_R_SUCCESS;
}

/*%
 * Destroy the temporary sign/verify context.
 */
static void
gssapi_destroy_signverify_ctx(dst_context_t *dctx) {
	dst_gssapi_signverifyctx_t *ctx = dctx->ctxdata.gssctx;

	if (ctx != NULL) {
		if (ctx->buffer != NULL) {
			isc_buffer_free(&ctx->buffer);
		}
		isc_mem_put(dctx->mctx, ctx,
			    sizeof(dst_gssapi_signverifyctx_t));
		dctx->ctxdata.gssctx = NULL;
	}
}

/*%
 * Add data to our running buffer of data we will be signing or verifying.
 * This code will see if the new data will fit in our existing buffer, and
 * copy it in if it will.  If not, it will attempt to allocate a larger
 * buffer and copy old+new into it, and free the old buffer.
 */
static isc_result_t
gssapi_adddata(dst_context_t *dctx, const isc_region_t *data) {
	dst_gssapi_signverifyctx_t *ctx = dctx->ctxdata.gssctx;
	isc_buffer_t *newbuffer = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;

	result = isc_buffer_copyregion(ctx->buffer, data);
	if (result == ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	length = isc_buffer_length(ctx->buffer) + data->length + BUFFER_EXTRA;

	isc_buffer_allocate(dctx->mctx, &newbuffer, length);

	isc_buffer_usedregion(ctx->buffer, &r);
	(void)isc_buffer_copyregion(newbuffer, &r);
	(void)isc_buffer_copyregion(newbuffer, data);

	isc_buffer_free(&ctx->buffer);
	ctx->buffer = newbuffer;

	return ISC_R_SUCCESS;
}

/*%
 * Sign.
 */
static isc_result_t
gssapi_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	dst_gssapi_signverifyctx_t *ctx = dctx->ctxdata.gssctx;
	isc_region_t message;
	gss_buffer_desc gmessage, gsig;
	OM_uint32 minor, gret;
	gss_ctx_id_t gssctx = dctx->key->keydata.gssctx;
	char buf[1024];

	/*
	 * Convert the data we wish to sign into a structure gssapi can
	 * understand.
	 */
	isc_buffer_usedregion(ctx->buffer, &message);
	REGION_TO_GBUFFER(message, gmessage);

	/*
	 * Generate the signature.
	 */
	gret = gss_get_mic(&minor, gssctx, GSS_C_QOP_DEFAULT, &gmessage, &gsig);

	/*
	 * If it did not complete, we log the result and return a generic
	 * failure code.
	 */
	if (gret != GSS_S_COMPLETE) {
		gss_log(3, "GSS sign error: %s",
			gss_error_tostring(gret, minor, buf, sizeof(buf)));
		return ISC_R_FAILURE;
	}

	/*
	 * If it will not fit in our allocated buffer, return that we need
	 * more space.
	 */
	if (gsig.length > isc_buffer_availablelength(sig)) {
		gss_release_buffer(&minor, &gsig);
		return ISC_R_NOSPACE;
	}

	/*
	 * Copy the output into our buffer space, and release the gssapi
	 * allocated space.
	 */
	isc_buffer_putmem(sig, gsig.value, (unsigned int)gsig.length);
	if (gsig.length != 0U) {
		gss_release_buffer(&minor, &gsig);
	}

	return ISC_R_SUCCESS;
}

/*%
 * Verify.
 */
static isc_result_t
gssapi_verify(dst_context_t *dctx, const isc_region_t *sig) {
	dst_gssapi_signverifyctx_t *ctx = dctx->ctxdata.gssctx;
	isc_region_t message;
	gss_buffer_desc gmessage, gsig;
	OM_uint32 minor, gret;
	gss_ctx_id_t gssctx = dctx->key->keydata.gssctx;
	char err[1024];

	/*
	 * Convert the data we wish to sign into a structure gssapi can
	 * understand.
	 */
	isc_buffer_usedregion(ctx->buffer, &message);
	REGION_TO_GBUFFER(message, gmessage);
	REGION_TO_GBUFFER(*sig, gsig);

	/*
	 * Verify the data.
	 */
	gret = gss_verify_mic(&minor, gssctx, &gmessage, &gsig, NULL);

	/*
	 * Convert return codes into something useful to us.
	 */
	if (gret != GSS_S_COMPLETE) {
		gss_log(3, "GSS verify error: %s",
			gss_error_tostring(gret, minor, err, sizeof(err)));
		if (gret == GSS_S_DEFECTIVE_TOKEN || gret == GSS_S_BAD_SIG ||
		    gret == GSS_S_DUPLICATE_TOKEN || gret == GSS_S_OLD_TOKEN ||
		    gret == GSS_S_UNSEQ_TOKEN || gret == GSS_S_GAP_TOKEN ||
		    gret == GSS_S_CONTEXT_EXPIRED || gret == GSS_S_NO_CONTEXT ||
		    gret == GSS_S_FAILURE)
		{
			return DST_R_VERIFYFAILURE;
		} else {
			return ISC_R_FAILURE;
		}
	}

	return ISC_R_SUCCESS;
}

static bool
gssapi_compare(const dst_key_t *key1, const dst_key_t *key2) {
	gss_ctx_id_t gsskey1 = key1->keydata.gssctx;
	gss_ctx_id_t gsskey2 = key2->keydata.gssctx;

	/* No idea */
	return gsskey1 == gsskey2;
}

static isc_result_t
gssapi_generate(dst_key_t *key, int unused, void (*callback)(int)) {
	UNUSED(key);
	UNUSED(unused);
	UNUSED(callback);

	/* No idea */
	return ISC_R_FAILURE;
}

static bool
gssapi_isprivate(const dst_key_t *key) {
	UNUSED(key);
	return true;
}

static void
gssapi_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	dst_gssapi_deletectx(key->mctx, &key->keydata.gssctx);
	key->keydata.gssctx = NULL;
}

static isc_result_t
gssapi_restore(dst_key_t *key, const char *keystr) {
	OM_uint32 major, minor;
	unsigned int len;
	isc_buffer_t *b = NULL;
	isc_region_t r;
	gss_buffer_desc gssbuffer;
	isc_result_t result;

	len = strlen(keystr);
	if ((len % 4) != 0U) {
		return ISC_R_BADBASE64;
	}

	len = (len / 4) * 3;

	isc_buffer_allocate(key->mctx, &b, len);

	result = isc_base64_decodestring(keystr, b);
	if (result != ISC_R_SUCCESS) {
		isc_buffer_free(&b);
		return result;
	}

	isc_buffer_remainingregion(b, &r);
	REGION_TO_GBUFFER(r, gssbuffer);
	major = gss_import_sec_context(&minor, &gssbuffer,
				       (gss_ctx_id_t *)&key->keydata.gssctx);
	if (major != GSS_S_COMPLETE) {
		isc_buffer_free(&b);
		return ISC_R_FAILURE;
	}

	isc_buffer_free(&b);
	return ISC_R_SUCCESS;
}

static isc_result_t
gssapi_dump(dst_key_t *key, isc_mem_t *mctx, char **buffer, int *length) {
	OM_uint32 major, minor;
	gss_buffer_desc gssbuffer;
	size_t len;
	char *buf;
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;

	major = gss_export_sec_context(
		&minor, (gss_ctx_id_t *)&key->keydata.gssctx, &gssbuffer);
	if (major != GSS_S_COMPLETE) {
		fprintf(stderr, "gss_export_sec_context -> %u, %u\n", major,
			minor);
		return ISC_R_FAILURE;
	}
	if (gssbuffer.length == 0U) {
		return ISC_R_FAILURE;
	}
	len = ((gssbuffer.length + 2) / 3) * 4;
	buf = isc_mem_get(mctx, len);
	isc_buffer_init(&b, buf, (unsigned int)len);
	GBUFFER_TO_REGION(gssbuffer, r);
	result = isc_base64_totext(&r, 0, "", &b);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	gss_release_buffer(&minor, &gssbuffer);
	*buffer = buf;
	*length = (int)len;
	return ISC_R_SUCCESS;
}

static dst_func_t gssapi_functions = {
	.createctx = gssapi_create_signverify_ctx,
	.destroyctx = gssapi_destroy_signverify_ctx,
	.adddata = gssapi_adddata,
	.sign = gssapi_sign,
	.verify = gssapi_verify,
	.compare = gssapi_compare,
	.generate = gssapi_generate,
	.isprivate = gssapi_isprivate,
	.destroy = gssapi_destroy,
	.dump = gssapi_dump,
	.restore = gssapi_restore,
};

void
dst__gssapi_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		*funcp = &gssapi_functions;
	}
}
