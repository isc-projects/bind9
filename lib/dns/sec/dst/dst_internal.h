/*
 * Portions Copyright (c) 1995-1998 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */

#ifndef DST_DST_INTERNAL_H
#define DST_DST_INTERNAL_H 1

#include <isc/lang.h>
#include <isc/buffer.h>
#include <isc/int.h>
#include <isc/region.h>

#include "../rename.h"

#include <dst/dst.h>

ISC_LANG_BEGINDECLS

/* 
 * define what crypto systems are supported.
 * BSAFE, DNSSAFE for RSA
 * OPENSSL for DSA
 * Only one package per algorithm can be defined.
 */
#if defined(BSAFE) && defined(DNSSAFE)
# error "Cannot have both BSAFE and DNSSAFE defined"
#endif

/***
 *** Types
 ***/

typedef struct dst_func dst_func;

struct dst_key {
	unsigned int	magic;
	char *		key_name;	/* name of the key */
	int		key_size;	/* size of the key in bits */
	int		key_proto;	/* protocols this key is used for */
	int		key_alg;	/* algorithm of the key */
	isc_uint32_t	key_flags;	/* flags of the public key */
	isc_uint16_t	key_id;		/* identifier of the key */
	isc_mem_t	*mctx;		/* memory context */
	void *		opaque;		/* pointer to key in crypto pkg fmt */
	dst_func *	func;		/* crypto package specific functions */
};

struct dst_func {
	isc_result_t (*sign)(const unsigned int mode, dst_key_t *key,
			     void **context, isc_region_t *data,
			     isc_buffer_t *sig, isc_mem_t *mctx);
	isc_result_t (*verify)(const unsigned int mode, dst_key_t *key,
			       void **context, isc_region_t *data,
			       isc_region_t *sig, isc_mem_t *mctx);
	isc_result_t (*computesecret)(const dst_key_t *pub,
				      const dst_key_t *priv,
				      isc_buffer_t *secret);
	isc_boolean_t (*compare)(const dst_key_t *key1, const dst_key_t *key2);
	isc_boolean_t (*paramcompare)(const dst_key_t *key1,
				      const dst_key_t *key2);
	isc_result_t (*generate)(dst_key_t *key, int parms, isc_mem_t *mctx);
	isc_boolean_t (*isprivate)(const dst_key_t *key);
	void (*destroy)(void *key, isc_mem_t *mctx);
	/* conversion functions */
	isc_result_t (*to_dns)(const dst_key_t *key, isc_buffer_t *data);
	isc_result_t (*from_dns)(dst_key_t *key, isc_buffer_t *data,
				 isc_mem_t *mctx);
	isc_result_t (*to_file)(const dst_key_t *key);
	isc_result_t (*from_file)(dst_key_t *key, const isc_uint16_t id,
				  isc_mem_t *mctx);
};

extern dst_func *dst_t_func[DST_MAX_ALGS];

#ifndef DST_HASH_SIZE
#define DST_HASH_SIZE 20	/* RIPEMD160 & SHA-1 are 20 bytes, MD5 is 16 */
#endif

void
dst_s_hmacmd5_init(void);
void
dst_s_bsafersa_init(void);
void
dst_s_openssldsa_init(void);
void
dst_s_openssldh_init(void);

/*
 * Support functions.
 */
int
dst_s_calculate_bits(const unsigned char *str, const int max_bits); 
isc_uint16_t
dst_s_id_calc(const unsigned char *key, const int keysize);

/*
 * Digest functions.
 */
isc_result_t
dst_s_md5(const unsigned int mode, void **context, isc_region_t *data,
	  isc_buffer_t *digest, isc_mem_t *mctx);

/*
 * Memory allocators using the DST memory pool.
 */
void *
dst_mem_alloc(size_t size);
void
dst_mem_free(void *ptr);
void *
dst_mem_realloc(void *ptr, size_t size);

ISC_LANG_ENDDECLS

#endif /* DST_DST_INTERNAL_H */
