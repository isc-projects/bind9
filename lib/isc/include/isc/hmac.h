#ifndef ISC_HMAC_H
#define ISC_HMAC_H

#include <config.h>

#include <isc/types.h>
#include <isc/platform.h>
#include <isc/md5.h>
#include <isc/sha1.h>
#include <isc/sha2.h>

typedef enum {
	ISC_HMAC_MD5_DIGESTLENGTH	= ISC_MD5_BLOCK_LENGTH,
	ISC_HMAC_SHA1_DIGESTLENGTH	= ISC_SHA1_BLOCK_LENGTH,
	ISC_HMAC_SHA224_DIGESTLENGTH	= ISC_SHA224_BLOCK_LENGTH,
	ISC_HMAC_SHA256_DIGESTLENGTH	= ISC_SHA256_BLOCK_LENGTH,
	ISC_HMAC_SHA384_DIGESTLENGTH	= ISC_SHA384_BLOCK_LENGTH,
	ISC_HMAC_SHA512_DIGESTLENGTH	= ISC_SHA512_BLOCK_LENGTH
} isc_hmac_digestlen_t;

typedef enum {
	ISC_HMAC_ALGO_MD5,
	ISC_HMAC_ALGO_SHA1,
	ISC_HMAC_ALGO_SHA224,
	ISC_HMAC_ALGO_SHA256,
	ISC_HMAC_ALGO_SHA384,
	ISC_HMAC_ALGO_SHA512,
	ISC_HMAC_ALOG_MAX = ISC_HMAC_ALGO_SHA512
} isc_hmac_algo_t;

#define isc_hmacmd5_t isc_hmac_t
#define isc_hmacsha1_t isc_hmac_t
#define isc_hmacsha224_t isc_hmac_t
#define isc_hmacsha256_t isc_hmac_t
#define isc_hmacsha384_t isc_hmac_t
#define isc_hmacsha512_t isc_hmac_t

#ifdef OPENSSL
#include <openssl/hmac.h>

/* OpenSSL 1.1 compatibility wrappers */
typedef struct {
	HMAC_CTX *ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	HMAC_CTX _ctx;
#endif
} isc_hmac_t;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define HMAC_CTX_new() &(ctx->_ctx), HMAC_CTX_init(&(ctx->_ctx))
#define HMAC_CTX_free(ptr) HMAC_CTX_cleanup(ptr)
#endif

#define isc_hmacmd5_init(ctx, key, len) isc_hmac_init_openssl(ctx, key, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_invalidate(ctx) isc_hmac_invalidate_openssl(ctx, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_update(ctx, buf, len) isc_hmac_update_openssl(ctx, buf, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_sign(ctx, digest, len) isc_hmac_sign_openssl(ctx, digest, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_verify(ctx, digest, len) isc_hmac_verify_openssl(ctx, digest, len, ISC_HMAC_ALGO_MD5)

#define isc_hmacsha1_init(ctx, key, len) isc_hmac_init_openssl(ctx, key, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_invalidate(ctx) isc_hmac_invalidate_openssl(ctx, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_update(ctx, buf, len) isc_hmac_update_openssl(ctx, buf, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_sign(ctx, digest, len) isc_hmac_sign_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_verify(ctx, digest, len) isc_hmac_verify_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA1)

#define isc_hmacsha224_init(ctx, key, len) isc_hmac_init_openssl(ctx, key, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_invalidate(ctx) isc_hmac_invalidate_openssl(ctx, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_update(ctx, buf, len) isc_hmac_update_openssl(ctx, buf, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_sign(ctx, digest, len) isc_hmac_sign_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_verify(ctx, digest, len) isc_hmac_verify_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA224)

#define isc_hmacsha256_init(ctx, key, len) isc_hmac_init_openssl(ctx, key, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_invalidate(ctx) isc_hmac_invalidate_openssl(ctx, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_update(ctx, buf, len) isc_hmac_update_openssl(ctx, buf, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_sign(ctx, digest, len) isc_hmac_sign_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_verify(ctx, digest, len) isc_hmac_verify_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA256)

#define isc_hmacsha384_init(ctx, key, len) isc_hmac_init_openssl(ctx, key, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_invalidate(ctx) isc_hmac_invalidate_openssl(ctx, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_update(ctx, buf, len) isc_hmac_update_openssl(ctx, buf, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_sign(ctx, digest, len) isc_hmac_sign_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_verify(ctx, digest, len) isc_hmac_verify_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA384)

#define isc_hmacsha512_init(ctx, key, len) isc_hmac_init_openssl(ctx, key, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_invalidate(ctx) isc_hmac_invalidate_openssl(ctx, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_update(ctx, buf, len) isc_hmac_update_openssl(ctx, buf, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_sign(ctx, digest, len) isc_hmac_sign_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_verify(ctx, digest, len) isc_hmac_verify_openssl(ctx, digest, len, ISC_HMAC_ALGO_SHA512)

void
isc_hmac_init_openssl(isc_hmac_t *, const unsigned char *, unsigned int, isc_hmac_algo_t);

void
isc_hmac_invalidate_openssl(isc_hmac_t *, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_update_openssl(isc_hmac_t *, const unsigned char *, unsigned int, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_sign_openssl(isc_hmac_t *, unsigned char *, size_t, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

isc_boolean_t
isc_hmac_verify_openssl(isc_hmac_t *, unsigned char *, size_t, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

#elif PKCS11CRYPTO

typedef pk11_context_t isc_hmac_t;

#ifdef PK11_MD5_HMAC_REPLACE
#define isc_hmacmd5_init(ctx, key, len) isc_hmac_init_pkcs11_replace(ctx, key, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_invalidate(ctx) isc_hmac_invalidate_pkcs11_replace(ctx, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_update(ctx, buf, len) isc_hmac_update_pkcs11_replace(ctx, buf, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_sign(ctx, digest, len) isc_hmac_sign_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_verify(ctx, digest, len) isc_hmac_verify_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_MD5)
#else
#define isc_hmacmd5_init(ctx, key, len) isc_hmac_init_pkcs11(ctx, key, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_invalidate(ctx) isc_hmac_invalidate_pkcs11(ctx, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_update(ctx, buf, len) isc_hmac_update_pkcs11(ctx, buf, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_sign(ctx, digest, len) isc_hmac_sign_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_MD5)
#define isc_hmacmd5_verify(ctx, digest, len) isc_hmac_verify_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_MD5)
#endif

#ifdef PK11_SHA_1_HMAC_REPLACE
#define isc_hmacsha1_init(ctx, key, len) isc_hmac_init_pkcs11_replace(ctx, key, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_invalidate(ctx) isc_hmac_invalidate_pkcs11_replace(ctx, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_update(ctx, buf, len) isc_hmac_update_pkcs11_replace(ctx, buf, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_sign(ctx, digest, len) isc_hmac_sign_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_verify(ctx, digest, len) isc_hmac_verify_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA1)
#else
#define isc_hmacsha1_init(ctx, key, len) isc_hmac_init_pkcs11(ctx, key, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_invalidate(ctx) isc_hmac_invalidate_pkcs11(ctx, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_update(ctx, buf, len) isc_hmac_update_pkcs11(ctx, buf, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_sign(ctx, digest, len) isc_hmac_sign_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA1)
#define isc_hmacsha1_verify(ctx, digest, len) isc_hmac_verify_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA1)
#endif	

#ifdef PK11_SHA224_HMAC_REPLACE
#define isc_hmacsha224_init(ctx, key, len) isc_hmac_init_pkcs11_replace(ctx, key, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_invalidate(ctx) isc_hmac_invalidate_pkcs11_replace(ctx, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_update(ctx, buf, len) isc_hmac_update_pkcs11_replace(ctx, buf, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_sign(ctx, digest, len) isc_hmac_sign_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_verify(ctx, digest, len) isc_hmac_verify_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA224)
#else
#define isc_hmacsha224_init(ctx, key, len) isc_hmac_init_pkcs11(ctx, key, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_invalidate(ctx) isc_hmac_invalidate_pkcs11(ctx, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_update(ctx, buf, len) isc_hmac_update_pkcs11(ctx, buf, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_sign(ctx, digest, len) isc_hmac_sign_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA224)
#define isc_hmacsha224_verify(ctx, digest, len) isc_hmac_verify_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA224)
#endif

#ifdef PK11_SHA256_HMAC_REPLACE
#define isc_hmacsha256_init(ctx, key, len) isc_hmac_init_pkcs11_replace(ctx, key, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_invalidate(ctx) isc_hmac_invalidate_pkcs11_replace(ctx, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_update(ctx, buf, len) isc_hmac_update_pkcs11_replace(ctx, buf, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_sign(ctx, digest, len) isc_hmac_sign_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_verify(ctx, digest, len) isc_hmac_verify_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA256)
#else
#define isc_hmacsha256_init(ctx, key, len) isc_hmac_init_pkcs11(ctx, key, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_invalidate(ctx) isc_hmac_invalidate_pkcs11(ctx, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_update(ctx, buf, len) isc_hmac_update_pkcs11(ctx, buf, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_sign(ctx, digest, len) isc_hmac_sign_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA256)
#define isc_hmacsha256_verify(ctx, digest, len) isc_hmac_verify_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA256)
#endif

#ifdef PK11_SHA384_HMAC_REPLACE
#define isc_hmacsha384_init(ctx, key, len) isc_hmac_init_pkcs11_replace(ctx, key, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_invalidate(ctx) isc_hmac_invalidate_pkcs11_replace(ctx, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_update(ctx, buf, len) isc_hmac_update_pkcs11_replace(ctx, buf, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_sign(ctx, digest, len) isc_hmac_sign_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_verify(ctx, digest, len) isc_hmac_verify_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA384)
#else
#define isc_hmacsha384_init(ctx, key, len) isc_hmac_init_pkcs11(ctx, key, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_invalidate(ctx) isc_hmac_invalidate_pkcs11(ctx, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_update(ctx, buf, len) isc_hmac_update_pkcs11(ctx, buf, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_sign(ctx, digest, len) isc_hmac_sign_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA384)
#define isc_hmacsha384_verify(ctx, digest, len) isc_hmac_verify_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA384)
#endif

#ifdef PK11_SHA512_HMAC_REPLACE
#define isc_hmacsha512_init(ctx, key, len) isc_hmac_init_pkcs11_replace(ctx, key, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_invalidate(ctx) isc_hmac_invalidate_pkcs11_replace(ctx, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_update(ctx, buf, len) isc_hmac_update_pkcs11_replace(ctx, buf, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_sign(ctx, digest, len) isc_hmac_sign_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_verify(ctx, digest, len) isc_hmac_verify_pkcs11_replace(ctx, digest, len, ISC_HMAC_ALGO_SHA512)
#else
#define isc_hmacsha512_init(ctx, key, len) isc_hmac_init_pkcs11(ctx, key, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_invalidate(ctx) isc_hmac_invalidate_pkcs11(ctx, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_update(ctx, buf, len) isc_hmac_update_pkcs11(ctx, buf, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_sign(ctx, digest, len) isc_hmac_sign_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA512)
#define isc_hmacsha512_verify(ctx, digest, len) isc_hmac_verify_pkcs11(ctx, digest, len, ISC_HMAC_ALGO_SHA512)
#endif

void
isc_hmac_init_pkcs11(isc_hmac_t *, const unsigned char *, unsigned int, isc_hmac_algo_t);

void
isc_hmac_invalidate_pkcs11(isc_hmac_t *, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_update_pkcs11(isc_hmac_t *, const unsigned char *, unsigned int, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_sign_pkcs11(isc_hmac_t *, unsigned char *, size_t, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

isc_boolean_t
isc_hmac_verify_pkcs11(isc_hmac_t *, unsigned char *, size_t, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_init_pkcs11_replace(isc_hmac_t *, const unsigned char *, unsigned int, isc_hmac_algo_t);

void
isc_hmac_invalidate_pkcs11_replace(isc_hmac_t *, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_update_pkcs11_replace(isc_hmac_t *, const unsigned char *, unsigned int, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

void
isc_hmac_sign_pkcs11_replace(isc_hmac_t *, unsigned char *, size_t, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

isc_boolean_t
isc_hmac_verify_pkcs11_replace(isc_hmac_t *, unsigned char *, size_t, isc_hmac_algo_t)
	__attribute__((nonnull(1)));

#else

#error Either OpenSSL or PKCS#11 cryptographic provider is mandatory.

#endif


#endif /* ISC_HMAC_H */
