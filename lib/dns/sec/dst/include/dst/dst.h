#ifndef DST_DST_H
#define DST_DST_H 1

#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/int.h>
#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/region.h>

#include <dst/result.h>

ISC_LANG_BEGINDECLS

/***
 *** Types
 ***/

/*
 * The dst_key structure is opaque.  Applications should use the accessor
 * functions provided to retrieve key attributes.  If an application needs
 * to set attributes, new accessor functions will be written.
 */

typedef struct dst_key	dst_key_t;
typedef void *		dst_context_t;

/* DST algorithm codes */
#define DST_ALG_UNKNOWN		0
#define DST_ALG_RSA		1
#define DST_ALG_DH		2
#define DST_ALG_DSA		3
#define DST_ALG_HMACMD5		157
#define DST_ALG_HMACSHA1	158	/* not implemented */
#define DST_ALG_PRIVATE		254
#define DST_ALG_EXPAND		255
#define DST_MAX_ALGS		DST_ALG_HMACSHA1

/* DST algorithm codes */
#define DST_DIGEST_MD5		258
#define DST_DIGEST_SHA1		259

/* 'Mode' passed into dst_sign() and dst_verify() */
#define DST_SIGMODE_INIT	1	/* initialize digest */
#define DST_SIGMODE_UPDATE	2	/* add data to digest */
#define DST_SIGMODE_FINAL	4 	/* generate/verify signature */
#define DST_SIGMODE_ALL		(DST_SIGMODE_INIT | \
				 DST_SIGMODE_UPDATE | \
				 DST_SIGMODE_FINAL)

/* A buffer of this size is large enough to hold any key */
#define DST_KEY_MAXSIZE		1024

/* 'Type' for dst_read_key() */
#define DST_TYPE_PRIVATE	0x2000000
#define DST_TYPE_PUBLIC		0x4000000

/***
 *** Functions
 ***/

/*
 * Check that a given algorithm is supported
 */
isc_boolean_t
dst_supported_algorithm(const int alg);

/* Sign a block of data.
 *
 * Requires:
 *	"mode" is some combination of DST_SIGMODE_INIT, DST_SIGMODE_UPDATE,
 *		and DST_SIGMODE_FINAL.
 *	"key" is a valid key.
 *	"context" contains a value appropriate for the value of "mode".
 *	"data" is a valid region.
 *	"sig" is a valid buffer.
 *
 * Ensures:
 *	All allocated memory will be freed after the FINAL call.  "sig"
 *	will contain a signature if all operations completed successfully.
 */
dst_result_t
dst_sign(const unsigned int mode, dst_key_t *key, dst_context_t *context,
	 isc_region_t *data, isc_buffer_t *sig);

/* Verify a signature on a block of data.
 *
 * Requires:
 *	"mode" is some combination of DST_SIGMODE_INIT, DST_SIGMODE_UPDATE,
 *		and DST_SIGMODE_FINAL.
 *	"key" is a valid key.
 *	"context" contains a value appropriate for the value of "mode".
 *	"data" is a valid region.
 *	"sig" is a valid region.
 *
 * Ensures:
 *	All allocated memory will be freed after the FINAL call.
 */
dst_result_t
dst_verify(const unsigned int mode, dst_key_t *key, dst_context_t *context,
	   isc_region_t *data, isc_region_t *sig);

/* Digest a block of data.
 *
 * Requires:
 *	"mode" is some combination of DST_SIGMODE_INIT, DST_SIGMODE_UPDATE,
 *		and DST_SIGMODE_FINAL.
 *	"alg" is a valid digest algorithm
 *	"context" contains a value appropriate for the value of "mode".
 *	"data" is a valid region.
 *	"digest" is a valid buffer.
 *
 * Ensures:
 *	All allocated memory will be freed after the FINAL call.  "digest"
 *	will contain a digest if all operations completed successfully.
 */
dst_result_t
dst_digest(const unsigned int mode, const unsigned int alg,
	   dst_context_t *context, isc_region_t *data, isc_buffer_t *digest);

/*
 * dst_computesecret
 *      A function to compute a shared secret from two (Diffie-Hellman) keys.
 *
 * Requires:
 *      "pub" is a valid key that can be used to derive a shared secret
 *      "priv" is a valid private key that can be used to derive a shared secret
 *      "secret" is a valid buffer
 *
 * Ensures:
 *      If successful, secret will contain the derived shared secret.
 */
dst_result_t
dst_computesecret(const dst_key_t *pub, const dst_key_t *priv,
                  isc_buffer_t *secret);

/* Reads a key from permanent storage.
 *
 * Requires:
 *	"name" is not NULL.
 *	"id" is a valid key tag identifier.
 *	"alg" is a supported key algorithm.
 *	"type" is either DST_TYPE_PUBLIC or DST_TYPE_PRIVATE.
 *	"mctx" is a valid memory context.
 *	"keyp" is not NULL.
 *
 * Ensures:
 *	If successful, *keyp will contain a valid key.
 */
dst_result_t
dst_key_fromfile(const char *name, const isc_uint16_t id, const int alg,
		 const int type, isc_mem_t *mctx, dst_key_t **keyp);

/* Writes a key to permanent storage.
 *
 * Requires:
 *	"key" is a valid key.
 *	"type" is either DST_TYPE_PUBLIC, DST_TYPE_PRIVATE, or both.
 */
dst_result_t
dst_key_tofile(const dst_key_t *key, const int type);

/* Converts a DNS KEY record into a DST key.
 *
 * Requires:
 *	"name" is not NULL.
 *	"source" is a valid buffer.  There must be at least 4 bytes available.
 *	"mctx" is a valid memory context.
 *	"keyp" is not NULL.
 *
 * Ensures:
 *	If successful, *keyp will contain a valid key, and the consumed
 *	pointer in data will be advanced.
 */
dst_result_t
dst_key_fromdns(const char *name, isc_buffer_t *source, isc_mem_t *mctx,
		dst_key_t **keyp);

/*  Converts a DST key into a DNS KEY record.
 *
 * Requires:
 *	"key" is a valid key.
 *	"target" is a valid buffer.  There must be at least 4 bytes unused.
 *
 * Ensures:
 *	If successful, the used pointer in 'target' is advanced by at least 4.
 */
dst_result_t
dst_key_todns(const dst_key_t *key, isc_buffer_t *target);

/* Converts a buffer containing DNS KEY RDATA into a DST key.
 *
 * Requires:
 *	"name" is not NULL.
 *	"alg" is a supported key algorithm.
 *	"source" is a valid buffer.
 *	"mctx" is a valid memory context.
 *	"keyp" is not NULL.
 *
 * Ensures:
 *	If successful, *keyp will contain a valid key, and the consumed
 *	pointer in source will be advanced.
 */
dst_result_t
dst_key_frombuffer(const char *name, const int alg, const int flags,
		   const int protocol, isc_buffer_t *source, isc_mem_t *mctx,
		   dst_key_t **keyp);

/*  Converts a DST key into DNS KEY RDATA format.
 *
 * Requires:
 *	"key" is a valid key.
 *	"target" is a valid buffer.
 *
 * Ensures:
 *	If successful, the used pointer in 'target' is advanced.
 */
dst_result_t
dst_key_tobuffer(const dst_key_t *key, isc_buffer_t *target);

/* Generate a DST key (or keypair)
 *
 * Requires:
 *	"name" is not NULL
 *	"alg" is a supported algorithm
 *	"bits" is a valid key size for the given algorithm
 *	"keyp" is not NULL.
 *
 * Ensures:
 *	If successful, *keyp will contain a valid key.
 */
dst_result_t
dst_key_generate(const char *name, const int alg, const int bits,
		 const int param, const int flags, const int protocol,
		 isc_mem_t *mctx, dst_key_t **keyp);

/* Compares two DST keys.
 *
 * Requires:
 *	"key1" is a valid key.
 *	"key2" is a valid key.
 */
isc_boolean_t
dst_key_compare(const dst_key_t *key1, const dst_key_t *key2);

/* Compares the parameters of two DST keys.
 *
 * Requires:
 *	"key1" is a valid key.
 *	"key2" is a valid key.
 */
isc_boolean_t
dst_key_paramcompare(const dst_key_t *key1, const dst_key_t *key2);

/* Free a DST key.
 *
 * Requires:
 *	"key" is a valid key.
 *
 * Ensures:
 *	All memory associated with "key" will be freed.
 */
void
dst_key_free(dst_key_t *key);

/* Accessor functions to obtain key fields.
 *
 * Require:
 *	"key" is a valid key.
 */
char *
dst_key_name(const dst_key_t *key);

int
dst_key_size(const dst_key_t *key);

int
dst_key_proto(const dst_key_t *key);

int
dst_key_alg(const dst_key_t *key);

isc_uint32_t
dst_key_flags(const dst_key_t *key);

isc_uint16_t
dst_key_id(const dst_key_t *key);

isc_boolean_t
dst_key_isprivate(const dst_key_t *key);

/* Computes the size of a signature generated by the given key.
 *
 * Requires:
 *	"key" is a valid key.
 *	"n" is not NULL
 *
 * Returns:
 *	ISC_R_SUCCESS
 *	DST_R_UNSUPPORTEDALG
 */
isc_result_t
dst_sig_size(const dst_key_t *key, unsigned int *n);

/* Computes the size of a shared secret generated by the given key.
 *
 * Requires:
 *	"key" is a valid key.
 *	"n" is not NULL
 *
 * Returns:
 *	ISC_R_SUCCESS
 *	DST_R_UNSUPPORTEDALG
 */
isc_result_t
dst_secret_size(const dst_key_t *key, unsigned int *n);

/* Generate random data.
 *
 * Requires:
 *	"data" is a valid buffer, with at least "wanted" bytes available.
 *
 * Ensures:
 *	<= wanted bytes will be written to "data", and the used pointer will
 *		be advanced.
 */
dst_result_t
dst_random_get(const unsigned int wanted, isc_buffer_t *data);

ISC_LANG_ENDDECLS

#endif /* DST_DST_H */
