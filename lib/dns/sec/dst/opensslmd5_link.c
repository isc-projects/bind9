/*
 * Portions Copyright (c) 1995-1998 by Network Associates, Inc.
 * Portions Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM AND
 * NETWORK ASSOCIATES DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE CONSORTIUM OR NETWORK
 * ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: opensslmd5_link.c,v 1.10 2000/06/06 21:58:13 bwelling Exp $
 */

#if defined(OPENSSL)

#include <config.h>

#include <isc/mem.h>
#include <isc/util.h>

#include "dst_internal.h"

#include <openssl/md5.h>

static isc_result_t
opensslmd5_createctx(dst_key_t *key, dst_context_t *dctx) {
	MD5_CTX *ctx;

	UNUSED(key);

	ctx = isc_mem_get(dctx->mctx, sizeof(MD5_CTX));
	if (ctx == NULL)
		return (ISC_R_NOMEMORY);
	MD5_Init(ctx);
	dctx->opaque = ctx;
	return (ISC_R_SUCCESS);
}

static void
opensslmd5_destroyctx(dst_context_t *dctx) {
	MD5_CTX *ctx = dctx->opaque;
	isc_mem_put(dctx->mctx, ctx, sizeof(MD5_CTX));
}

static isc_result_t
opensslmd5_adddata(dst_context_t *dctx, const isc_region_t *data) {
	MD5_CTX *ctx = dctx->opaque;

	MD5_Update(ctx, data->base, data->length);
	return (ISC_R_SUCCESS);
}

static isc_result_t
opensslmd5_digest(dst_context_t *dctx, isc_buffer_t *digest) {
	MD5_CTX *ctx = dctx->opaque;
	isc_region_t r;
	
	isc_buffer_availableregion(digest, &r);
	if (r.length < MD5_DIGEST_LENGTH)
		return (ISC_R_NOSPACE);

	MD5_Final(r.base, ctx);
	isc_buffer_add(digest, MD5_DIGEST_LENGTH);

	return (ISC_R_SUCCESS);
}

static dst_func_t opensslmd5_functions = {
	opensslmd5_createctx,
	opensslmd5_destroyctx,
	opensslmd5_adddata,
	NULL, /* openssldsa_sign */
	NULL, /* openssldsa_verify */
	opensslmd5_digest,
	NULL, /* computesecret */
	NULL, /* compare */
	NULL, /* paramcompare */
	NULL, /* generate */
	NULL, /* isprivate */
	NULL, /* destroy */
	NULL, /* todns */
	NULL, /* fromdns */
	NULL, /* tofile */
	NULL, /* fromfile */
};

isc_result_t
dst__opensslmd5_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL && *funcp == NULL);
	*funcp = &opensslmd5_functions;
	return (ISC_R_SUCCESS);
}

void
dst__opensslmd5_destroy(void) {
}

#endif /* OPENSSL */
