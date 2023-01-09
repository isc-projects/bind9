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

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/mutexblock.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/tls.h>
#include <isc/util.h>

#include <dns/log.h>

#include "dst_internal.h"
#include "dst_openssl.h"

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
#include <openssl/engine.h>
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/store.h>
#endif

#include "openssl_shim.h"

#define DST_RET(a)        \
	{                 \
		ret = a;  \
		goto err; \
	}

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
static ENGINE *global_engine = NULL;
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */

static void
enable_fips_mode(void) {
#ifdef HAVE_FIPS_MODE
	if (FIPS_mode() != 0) {
		/*
		 * FIPS mode is already enabled.
		 */
		return;
	}

	if (FIPS_mode_set(1) == 0) {
		dst__openssl_toresult2("FIPS_mode_set", DST_R_OPENSSLFAILURE);
		exit(1);
	}
#endif /* HAVE_FIPS_MODE */
}

isc_result_t
dst__openssl_init(const char *engine) {
	isc_result_t result = ISC_R_SUCCESS;

	enable_fips_mode();

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	if (engine != NULL && *engine == '\0') {
		engine = NULL;
	}

	if (engine != NULL) {
		global_engine = ENGINE_by_id(engine);
		if (global_engine == NULL) {
			result = DST_R_NOENGINE;
			goto cleanup_rm;
		}
		if (!ENGINE_init(global_engine)) {
			result = DST_R_NOENGINE;
			goto cleanup_rm;
		}
		/* This will init the engine. */
		if (!ENGINE_set_default(global_engine, ENGINE_METHOD_ALL)) {
			result = DST_R_NOENGINE;
			goto cleanup_init;
		}
	}

	return (ISC_R_SUCCESS);
cleanup_init:
	ENGINE_finish(global_engine);
cleanup_rm:
	if (global_engine != NULL) {
		ENGINE_free(global_engine);
	}
	global_engine = NULL;
#else
	UNUSED(engine);
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
	return (result);
}

void
dst__openssl_destroy(void) {
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	if (global_engine != NULL) {
		ENGINE_finish(global_engine);
		ENGINE_free(global_engine);
	}
	global_engine = NULL;
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
}

static isc_result_t
toresult(isc_result_t fallback) {
	isc_result_t result = fallback;
	unsigned long err = ERR_peek_error();
#if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
	int lib = ERR_GET_LIB(err);
#endif /* if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED) */
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
#if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
		if (lib == ERR_R_ECDSA_LIB &&
		    reason == ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED)
		{
			result = ISC_R_NOENTROPY;
			break;
		}
#endif /* if defined(ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED) */
		break;
	}

	return (result);
}

isc_result_t
dst__openssl_toresult(isc_result_t fallback) {
	isc_result_t result;

	result = toresult(fallback);

	ERR_clear_error();
	return (result);
}

isc_result_t
dst__openssl_toresult2(const char *funcname, isc_result_t fallback) {
	return (dst__openssl_toresult3(DNS_LOGCATEGORY_GENERAL, funcname,
				       fallback));
}

isc_result_t
dst__openssl_toresult3(isc_logcategory_t *category, const char *funcname,
		       isc_result_t fallback) {
	isc_result_t result;
	unsigned long err;
	const char *file, *func, *data;
	int line, flags;
	char buf[256];

	result = toresult(fallback);

	isc_log_write(dns_lctx, category, DNS_LOGMODULE_CRYPTO, ISC_LOG_WARNING,
		      "%s failed (%s)", funcname, isc_result_totext(result));

	if (result == ISC_R_NOMEMORY) {
		goto done;
	}

	for (;;) {
		err = ERR_get_error_all(&file, &line, &func, &data, &flags);
		if (err == 0U) {
			goto done;
		}
		ERR_error_string_n(err, buf, sizeof(buf));
		isc_log_write(dns_lctx, category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_INFO, "%s:%s:%d:%s", buf, file, line,
			      ((flags & ERR_TXT_STRING) != 0) ? data : "");
	}

done:
	ERR_clear_error();
	return (result);
}

#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
ENGINE *
dst__openssl_getengine(const char *engine) {
	if (engine == NULL) {
		return (NULL);
	}
	if (global_engine == NULL) {
		return (NULL);
	}
	if (strcmp(engine, ENGINE_get_id(global_engine)) == 0) {
		return (global_engine);
	}
	return (NULL);
}
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */

static isc_result_t
dst__openssl_fromlabel_engine(int key_base_id, const char *engine,
			      const char *label, const char *pin,
			      EVP_PKEY **ppub, EVP_PKEY **ppriv) {
#if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000
	isc_result_t ret = ISC_R_SUCCESS;
	ENGINE *e = NULL;

	UNUSED(pin);

	if (engine == NULL) {
		DST_RET(DST_R_NOENGINE);
	}
	e = dst__openssl_getengine(engine);
	if (e == NULL) {
		DST_RET(dst__openssl_toresult(DST_R_NOENGINE));
	}

	*ppub = ENGINE_load_public_key(e, label, NULL, NULL);
	if (*ppub == NULL) {
		DST_RET(dst__openssl_toresult2("ENGINE_load_public_key",
					       DST_R_OPENSSLFAILURE));
	}
	if (EVP_PKEY_base_id(*ppub) != key_base_id) {
		DST_RET(DST_R_BADKEYTYPE);
	}

	*ppriv = ENGINE_load_private_key(e, label, NULL, NULL);
	if (*ppriv == NULL) {
		DST_RET(dst__openssl_toresult2("ENGINE_load_private_key",
					       DST_R_OPENSSLFAILURE));
	}
	if (EVP_PKEY_base_id(*ppriv) != key_base_id) {
		DST_RET(DST_R_BADKEYTYPE);
	}
err:
	return (ret);
#else  /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
	UNUSED(key_base_id);
	UNUSED(engine);
	UNUSED(label);
	UNUSED(pin);
	UNUSED(ppub);
	UNUSED(ppriv);
	return (DST_R_NOENGINE);
#endif /* if !defined(OPENSSL_NO_ENGINE) && OPENSSL_API_LEVEL < 30000 */
}

static isc_result_t
dst__openssl_fromlabel_provider(int key_base_id, const char *engine,
				const char *label, const char *pin,
				EVP_PKEY **ppub, EVP_PKEY **ppriv) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	isc_result_t ret = DST_R_OPENSSLFAILURE;
	OSSL_STORE_CTX *ctx = NULL;

	UNUSED(pin);
	UNUSED(engine);

	ctx = OSSL_STORE_open(label, NULL, NULL, NULL, NULL);
	if (!ctx) {
		DST_RET(dst__openssl_toresult2("OSSL_STORE_open_ex",
					       DST_R_OPENSSLFAILURE));
	}

	while (!OSSL_STORE_eof(ctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
		if (info == NULL) {
			continue;
		}
		switch (OSSL_STORE_INFO_get_type(info)) {
		case OSSL_STORE_INFO_PKEY:
			if (*ppriv != NULL) {
				DST_RET(DST_R_INVALIDPRIVATEKEY);
			}
			*ppriv = OSSL_STORE_INFO_get1_PKEY(info);
			if (EVP_PKEY_get_base_id(*ppriv) != key_base_id) {
				DST_RET(DST_R_BADKEYTYPE);
			}
			break;
		case OSSL_STORE_INFO_PUBKEY:
			if (*ppub != NULL) {
				DST_RET(DST_R_INVALIDPUBLICKEY);
			}
			*ppub = OSSL_STORE_INFO_get1_PUBKEY(info);
			if (EVP_PKEY_get_base_id(*ppub) != key_base_id) {
				DST_RET(DST_R_BADKEYTYPE);
			}
			break;
		}
		OSSL_STORE_INFO_free(info);
	}
	if (*ppriv != NULL && *ppub != NULL) {
		ret = ISC_R_SUCCESS;
	}
err:
	OSSL_STORE_close(ctx);
	return (ret);
#else
	UNUSED(key_base_id);
	UNUSED(engine);
	UNUSED(label);
	UNUSED(pin);
	UNUSED(ppub);
	UNUSED(ppriv);
	return (DST_R_OPENSSLFAILURE);
#endif
}

isc_result_t
dst__openssl_fromlabel(int key_base_id, const char *engine, const char *label,
		       const char *pin, EVP_PKEY **ppub, EVP_PKEY **ppriv) {
	isc_result_t result;

	result = dst__openssl_fromlabel_provider(key_base_id, engine, label,
						 pin, ppub, ppriv);
	if (result != DST_R_OPENSSLFAILURE) {
		return (result);
	}

	return (dst__openssl_fromlabel_engine(key_base_id, engine, label, pin,
					      ppub, ppriv));
}

/*! \file */
