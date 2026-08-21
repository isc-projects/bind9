/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0 AND ISC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Copyright (C) Network Associates, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NETWORK ASSOCIATES DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>
#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/hmac.h>
#include <isc/lex.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/nonce.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include "dst_internal.h"
#include "dst_parse.h"

#define ISC_MD_md5    ISC_MD_MD5
#define ISC_MD_sha1   ISC_MD_SHA1
#define ISC_MD_sha224 ISC_MD_SHA224
#define ISC_MD_sha256 ISC_MD_SHA256
#define ISC_MD_sha384 ISC_MD_SHA384
#define ISC_MD_sha512 ISC_MD_SHA512

#define hmac_register_algorithm(alg)                                           \
	static isc_result_t hmac##alg##_createctx(dst_key_t *key,              \
						  dst_context_t *dctx) {       \
		return (hmac_createctx(key, dctx));                            \
	}                                                                      \
	static void hmac##alg##_destroyctx(dst_context_t *dctx) {              \
		hmac_destroyctx(dctx);                                         \
	}                                                                      \
	static isc_result_t hmac##alg##_adddata(dst_context_t *dctx,           \
						const isc_region_t *data) {    \
		return (hmac_adddata(dctx, data));                             \
	}                                                                      \
	static isc_result_t hmac##alg##_sign(dst_context_t *dctx,              \
					     isc_buffer_t *sig) {              \
		return (hmac_sign(dctx, sig));                                 \
	}                                                                      \
	static isc_result_t hmac##alg##_verify(dst_context_t *dctx,            \
					       const isc_region_t *sig) {      \
		return (hmac_verify(dctx, sig));                               \
	}                                                                      \
	static bool hmac##alg##_compare(const dst_key_t *key1,                 \
					const dst_key_t *key2) {               \
		return (hmac_compare(key1, key2));                             \
	}                                                                      \
	static isc_result_t hmac##alg##_generate(                              \
		dst_key_t *key, int pseudorandom_ok, void (*callback)(int)) {  \
		UNUSED(pseudorandom_ok);                                       \
		UNUSED(callback);                                              \
		return (hmac_generate(ISC_MD_##alg, key));                     \
	}                                                                      \
	static bool hmac##alg##_isprivate(const dst_key_t *key) {              \
		return (hmac_isprivate(key));                                  \
	}                                                                      \
	static void hmac##alg##_destroy(dst_key_t *key) { hmac_destroy(key); } \
	static isc_result_t hmac##alg##_todns(const dst_key_t *key,            \
					      isc_buffer_t *data) {            \
		return (hmac_todns(key, data));                                \
	}                                                                      \
	static isc_result_t hmac##alg##_fromdns(dst_key_t *key,                \
						isc_buffer_t *data) {          \
		return (hmac_fromdns(ISC_MD_##alg, key, data));                \
	}                                                                      \
	static isc_result_t hmac##alg##_tofile(const dst_key_t *key,           \
					       const char *directory) {        \
		return (hmac_tofile(ISC_MD_##alg, key, directory));            \
	}                                                                      \
	static isc_result_t hmac##alg##_parse(                                 \
		dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {            \
		const char *file = isc_lex_getsourcename(lexer);               \
		isc_result_t result;                                           \
		result = hmac_parse(ISC_MD_##alg, key, lexer, pub);            \
		if (result == ISC_R_SUCCESS && file != NULL) {                 \
			isc_log_write(DNS_LOGCATEGORY_GENERAL,                 \
				      DNS_LOGMODULE_CRYPTO, ISC_LOG_WARNING,   \
				      "%s: Use of K* file pairs for HMAC is "  \
				      "deprecated\n",                          \
				      file);                                   \
		}                                                              \
		return (result);                                               \
	}                                                                      \
	static dst_func_t hmac##alg##_functions = {                            \
		.createctx = hmac##alg##_createctx,                            \
		.destroyctx = hmac##alg##_destroyctx,                          \
		.adddata = hmac##alg##_adddata,                                \
		.sign = hmac##alg##_sign,                                      \
		.verify = hmac##alg##_verify,                                  \
		.compare = hmac##alg##_compare,                                \
		.generate = hmac##alg##_generate,                              \
		.isprivate = hmac##alg##_isprivate,                            \
		.destroy = hmac##alg##_destroy,                                \
		.todns = hmac##alg##_todns,                                    \
		.fromdns = hmac##alg##_fromdns,                                \
		.tofile = hmac##alg##_tofile,                                  \
		.parse = hmac##alg##_parse,                                    \
	};                                                                     \
	void dst__hmac##alg##_init(dst_func_t **funcp) {                       \
		REQUIRE(funcp != NULL);                                        \
		if (*funcp == NULL) {                                          \
			uint8_t data[] = "data";                               \
			uint8_t mac_buffer[ISC_MAX_MD_SIZE];                   \
			unsigned int mac_len = sizeof(mac_buffer);             \
			if (isc_hmac(ISC_MD_##alg, "test", 4, data, 4,         \
				     mac_buffer, &mac_len) == ISC_R_SUCCESS)   \
			{                                                      \
				*funcp = &hmac##alg##_functions;               \
			}                                                      \
		}                                                              \
	}

static isc_result_t
hmac_fromdns(isc_md_type_t type, dst_key_t *key, isc_buffer_t *data);

static isc_result_t
getkeybits(dst_key_t *key, struct dst_private_element *element) {
	uint16_t *bits = (uint16_t *)element->data;

	if (element->length != 2) {
		return DST_R_INVALIDPRIVATEKEY;
	}

	key->key_bits = ntohs(*bits);

	return ISC_R_SUCCESS;
}

static isc_result_t
hmac_createctx(const dst_key_t *key, dst_context_t *dctx) {
	isc_result_t result;
	isc_hmac_t *ctx = isc_hmac_new(); /* Either returns or abort()s */

	result = isc_hmac_init(ctx, key->keydata.hmac_key);
	if (result != ISC_R_SUCCESS) {
		isc_hmac_free(ctx);
		return DST_R_UNSUPPORTEDALG;
	}

	dctx->ctxdata.hmac_ctx = ctx;
	return ISC_R_SUCCESS;
}

static void
hmac_destroyctx(dst_context_t *dctx) {
	isc_hmac_t *ctx = dctx->ctxdata.hmac_ctx;
	REQUIRE(ctx != NULL);

	isc_hmac_free(ctx);
	dctx->ctxdata.hmac_ctx = NULL;
}

static isc_result_t
hmac_adddata(const dst_context_t *dctx, const isc_region_t *data) {
	isc_result_t result;
	isc_hmac_t *ctx = dctx->ctxdata.hmac_ctx;

	REQUIRE(ctx != NULL);

	result = isc_hmac_update(ctx, data->base, data->length);
	if (result != ISC_R_SUCCESS) {
		return DST_R_OPENSSLFAILURE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
hmac_sign(const dst_context_t *dctx, isc_buffer_t *sig) {
	isc_hmac_t *ctx = dctx->ctxdata.hmac_ctx;

	REQUIRE(ctx != NULL);

	return isc_hmac_final(ctx, sig);
}

static isc_result_t
hmac_verify(const dst_context_t *dctx, const isc_region_t *sig) {
	isc_hmac_t *ctx = dctx->ctxdata.hmac_ctx;
	unsigned char digest[ISC_MAX_MD_SIZE];
	isc_buffer_t hmac;
	unsigned int sig_expected_length = ISC_MAX_MD_SIZE;
	uint16_t digestbits = dst_key_getbits(dctx->key);

	REQUIRE(ctx != NULL);

	isc_buffer_init(&hmac, digest, sizeof(digest));

	if (isc_hmac_final(ctx, &hmac) != ISC_R_SUCCESS) {
		return DST_R_OPENSSLFAILURE;
	}

	if (digestbits == 0) {
		/*
		 * If digestbits is zero then HMAC truncation is not used, just
		 * use the key's actual length.
		 */
		isc_result_t result = dst_key_sigsize(dctx->key,
						      &sig_expected_length);
		if (result != ISC_R_SUCCESS) {
			return DST_R_VERIFYFAILURE;
		}
	} else {
		sig_expected_length = (digestbits + 7) / 8;
	}

	if (sig->length != sig_expected_length ||
	    sig->length > isc_buffer_usedlength(&hmac))
	{
		return DST_R_VERIFYFAILURE;
	}

	return isc_safe_memequal(digest, sig->base, sig->length)
		       ? ISC_R_SUCCESS
		       : DST_R_VERIFYFAILURE;
}

static bool
hmac_compare(const dst_key_t *key1, const dst_key_t *key2) {
	isc_hmac_key_t *hkey1, *hkey2;

	hkey1 = key1->keydata.hmac_key;
	hkey2 = key2->keydata.hmac_key;

	if (hkey1 == NULL && hkey2 == NULL) {
		return true;
	} else if (hkey1 == NULL || hkey2 == NULL) {
		return false;
	}

	return isc_hmac_key_equal(hkey1, hkey2);
}

static isc_result_t
hmac_generate(isc_md_type_t type, dst_key_t *key) {
	isc_buffer_t b;
	isc_result_t result;
	unsigned int bytes, len;
	unsigned char data[ISC_MAX_BLOCK_SIZE] = { 0 };

	len = isc_md_type_get_block_size(type);

	bytes = (key->key_size + 7) / 8;

	if (bytes > len) {
		bytes = len;
		key->key_size = len * 8;
	}

	isc_nonce_buf(data, bytes);

	isc_buffer_init(&b, data, bytes);
	isc_buffer_add(&b, bytes);

	result = hmac_fromdns(type, key, &b);

	isc_safe_memwipe(data, sizeof(data));

	return result;
}

static bool
hmac_isprivate(const dst_key_t *key) {
	UNUSED(key);
	return true;
}

static void
hmac_destroy(dst_key_t *key) {
	isc_hmac_key_destroy(&key->keydata.hmac_key);
}

static isc_result_t
hmac_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t raw_key;

	REQUIRE(key != NULL && key->keydata.hmac_key != NULL);

	raw_key = isc_hmac_key_expose(key->keydata.hmac_key);

	if (isc_buffer_availablelength(data) < raw_key.length) {
		return ISC_R_NOSPACE;
	}

	return isc_buffer_copyregion(data, &raw_key);
}

static isc_result_t
hmac_fromdns(isc_md_type_t type, dst_key_t *key, isc_buffer_t *data) {
	isc_hmac_key_t *hkey = NULL;
	isc_result_t result;
	isc_region_t r;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}

	result = isc_hmac_key_create(type, r.base, r.length, key->mctx, &hkey);
	if (result != ISC_R_SUCCESS) {
		return DST_R_OPENSSLFAILURE;
	}

	key->key_size = isc_hmac_key_expose(hkey).length * 8;
	key->keydata.hmac_key = hkey;

	isc_buffer_forward(data, r.length);

	return ISC_R_SUCCESS;
}

static int
hmac__get_tag_key(isc_md_type_t type) {
	switch (type) {
	case ISC_MD_MD5:
		return TAG_HMACMD5_KEY;
	case ISC_MD_SHA1:
		return TAG_HMACSHA1_KEY;
	case ISC_MD_SHA224:
		return TAG_HMACSHA224_KEY;
	case ISC_MD_SHA256:
		return TAG_HMACSHA256_KEY;
	case ISC_MD_SHA384:
		return TAG_HMACSHA384_KEY;
	case ISC_MD_SHA512:
		return TAG_HMACSHA512_KEY;
	default:
		UNREACHABLE();
	}
}

static int
hmac__get_tag_bits(isc_md_type_t type) {
	switch (type) {
	case ISC_MD_MD5:
		return TAG_HMACMD5_BITS;
	case ISC_MD_SHA1:
		return TAG_HMACSHA1_BITS;
	case ISC_MD_SHA224:
		return TAG_HMACSHA224_BITS;
	case ISC_MD_SHA256:
		return TAG_HMACSHA256_BITS;
	case ISC_MD_SHA384:
		return TAG_HMACSHA384_BITS;
	case ISC_MD_SHA512:
		return TAG_HMACSHA512_BITS;
	default:
		UNREACHABLE();
	}
}

static isc_result_t
hmac_tofile(isc_md_type_t type, const dst_key_t *key, const char *directory) {
	isc_region_t raw_key;
	dst_private_t priv;
	uint16_t bits;

	if (key->keydata.hmac_key == NULL) {
		return DST_R_NULLKEY;
	}

	if (key->external) {
		return DST_R_EXTERNALKEY;
	}

	raw_key = isc_hmac_key_expose(key->keydata.hmac_key);

	priv.elements[0].tag = hmac__get_tag_key(type);
	priv.elements[0].length = raw_key.length;
	priv.elements[0].data = raw_key.base;

	bits = htons(key->key_bits);

	priv.elements[1].tag = hmac__get_tag_bits(type);
	priv.elements[1].length = sizeof(bits);
	priv.elements[1].data = (uint8_t *)&bits;

	priv.nelements = 2;

	return dst__privstruct_writefile(key, &priv, directory);
}

static int
hmac__to_dst_alg(isc_md_type_t type) {
	if (type == ISC_MD_MD5) {
		return DST_ALG_HMACMD5;
	} else if (type == ISC_MD_SHA1) {
		return DST_ALG_HMACSHA1;
	} else if (type == ISC_MD_SHA224) {
		return DST_ALG_HMACSHA224;
	} else if (type == ISC_MD_SHA256) {
		return DST_ALG_HMACSHA256;
	} else if (type == ISC_MD_SHA384) {
		return DST_ALG_HMACSHA384;
	} else if (type == ISC_MD_SHA512) {
		return DST_ALG_HMACSHA512;
	} else {
		UNREACHABLE();
	}
}

static isc_result_t
hmac_parse(isc_md_type_t type, dst_key_t *key, isc_lex_t *lexer,
	   dst_key_t *pub) {
	dst_private_t priv;
	isc_result_t result = ISC_R_SUCCESS, tresult;
	isc_buffer_t b;
	isc_mem_t *mctx = key->mctx;
	unsigned int i;

	UNUSED(pub);
	/* read private key file */
	RETERR(dst__privstruct_parse(key, hmac__to_dst_alg(type), lexer, mctx,
				     &priv));

	if (key->external) {
		result = DST_R_EXTERNALKEY;
	}

	key->key_bits = 0;
	for (i = 0; i < priv.nelements && result == ISC_R_SUCCESS; i++) {
		switch (priv.elements[i].tag) {
		case TAG_HMACMD5_KEY:
		case TAG_HMACSHA1_KEY:
		case TAG_HMACSHA224_KEY:
		case TAG_HMACSHA256_KEY:
		case TAG_HMACSHA384_KEY:
		case TAG_HMACSHA512_KEY:
			isc_buffer_init(&b, priv.elements[i].data,
					priv.elements[i].length);
			isc_buffer_add(&b, priv.elements[i].length);
			tresult = hmac_fromdns(type, key, &b);
			if (tresult != ISC_R_SUCCESS) {
				result = tresult;
			}
			break;
		case TAG_HMACMD5_BITS:
		case TAG_HMACSHA1_BITS:
		case TAG_HMACSHA224_BITS:
		case TAG_HMACSHA256_BITS:
		case TAG_HMACSHA384_BITS:
		case TAG_HMACSHA512_BITS:
			tresult = getkeybits(key, &priv.elements[i]);
			if (tresult != ISC_R_SUCCESS) {
				result = tresult;
			}
			break;
		default:
			result = DST_R_INVALIDPRIVATEKEY;
			break;
		}
	}
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return result;
}

hmac_register_algorithm(md5);
hmac_register_algorithm(sha1);
hmac_register_algorithm(sha224);
hmac_register_algorithm(sha256);
hmac_register_algorithm(sha384);
hmac_register_algorithm(sha512);

/*! \file */
