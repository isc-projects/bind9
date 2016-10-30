/*
 * Copyright (C) 2002, 2004, 2005, 2007-2009, 2011, 2012, 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: dst_openssl.h,v 1.11 2011/03/12 04:59:48 tbox Exp $ */

#ifndef DST_OPENSSL_H
#define DST_OPENSSL_H 1

#include <isc/lang.h>
#include <isc/log.h>
#include <isc/result.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>

#if !defined(OPENSSL_NO_ENGINE) && \
    ((defined(CRYPTO_LOCK_ENGINE) && \
      (OPENSSL_VERSION_NUMBER >= 0x0090707f)) || \
     (OPENSSL_VERSION_NUMBER >= 0x10100000L))
#define USE_ENGINE 1
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
/*
 * These are new in OpenSSL 1.1.0.  BN_GENCB _cb needs to be declared in
 * the function like this before the BN_GENCB_new call:
 *
 * #if OPENSSL_VERSION_NUMBER < 0x10100000L
 *     	 _cb;
 * #endif
 */
#define BN_GENCB_free(x) (x = NULL);
#define BN_GENCB_new() (&_cb)
#define BN_GENCB_get_arg(x) ((x)->arg)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
/*
 * EVP_dss1() is a version of EVP_sha1() that was needed prior to
 * 1.1.0 because there was a link between digests and signing algorithms;
 * the link has been eliminated and EVP_sha1() can be used now instead.
 */
#define EVP_dss1 EVP_sha1
#endif

ISC_LANG_BEGINDECLS

isc_result_t
dst__openssl_toresult(isc_result_t fallback);

isc_result_t
dst__openssl_toresult2(const char *funcname, isc_result_t fallback);

isc_result_t
dst__openssl_toresult3(isc_logcategory_t *category,
		       const char *funcname, isc_result_t fallback);

#ifdef USE_ENGINE
ENGINE *
dst__openssl_getengine(const char *engine);
#else
#define dst__openssl_getengine(x) NULL
#endif

ISC_LANG_ENDDECLS

#endif /* DST_OPENSSL_H */
/*! \file */
