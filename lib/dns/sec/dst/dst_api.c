/*
 * Portions Copyright (c) 1995-1999 by Network Associates, Inc.
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
 * $Id: dst_api.c,v 1.46 2000/06/03 00:43:46 bwelling Exp $
 */

#include <config.h>

#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/dir.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/random.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/types.h>
#include <dns/keyvalues.h>

#include <dst/result.h>

#include "dst_internal.h"

#include <openssl/rand.h>

#define KEY_MAGIC	0x4453544BU	/* DSTK */
#define CTX_MAGIC	0x44535443U	/* DSTC */

#define VALID_KEY(x) ISC_MAGIC_VALID(x, KEY_MAGIC)
#define VALID_CTX(x) ISC_MAGIC_VALID(x, CTX_MAGIC)

static dst_key_t md5key;
dst_key_t *dst_key_md5 = NULL;

static dst_func_t *dst_t_func[DST_MAX_ALGS];
static isc_mem_t *dst_memory_pool = NULL;
static isc_once_t once = ISC_ONCE_INIT;
static isc_mutex_t random_lock;


/* Static functions */
static void		initialize(void);
static dst_key_t *	get_key_struct(dns_name_t *name,
				       const unsigned int alg,
				       const unsigned int flags,
				       const unsigned int protocol,
				       const unsigned int bits,
				       isc_mem_t *mctx);
static isc_result_t	read_public_key(dns_name_t *name,
					const isc_uint16_t id,
					const unsigned int alg,
					isc_mem_t *mctx,
					dst_key_t **keyp);
static isc_result_t	write_public_key(const dst_key_t *key);

isc_boolean_t
dst_algorithm_supported(const unsigned int alg) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	if (alg >= DST_MAX_ALGS || dst_t_func[alg] == NULL)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

isc_result_t
dst_context_create(dst_key_t *key, isc_mem_t *mctx, dst_context_t **dctxp) {
	dst_context_t *dctx;
	isc_result_t result;

	REQUIRE(mctx != NULL);
	REQUIRE(dctxp != NULL && *dctxp == NULL);
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);

	if (key->func->createctx == NULL)
		return (DST_R_UNSUPPORTEDALG);

	dctx = isc_mem_get(mctx, sizeof(dst_context_t));
	if (dctx == NULL)
		return (ISC_R_NOMEMORY);
	dctx->key = key;
	dctx->mctx = mctx;
	result = key->func->createctx(key, dctx);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, dctx, sizeof(dst_context_t));
		return (result);
	}
	dctx->magic = CTX_MAGIC;
	*dctxp = dctx;
	return (ISC_R_SUCCESS);
}

void
dst_context_destroy(dst_context_t **dctxp) {
	dst_context_t *dctx;

	REQUIRE(dctxp != NULL && VALID_CTX(*dctxp));

	dctx = *dctxp;
	INSIST(dctx->key->func->destroyctx != NULL);
	dctx->key->func->destroyctx(dctx);
	dctx->magic = 0;
	isc_mem_put(dctx->mctx, dctx, sizeof(dst_context_t));
	*dctxp = NULL;
}

isc_result_t
dst_context_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(VALID_CTX(dctx));
	REQUIRE(data != NULL);
	INSIST(dctx->key->func->adddata != NULL);

	return (dctx->key->func->adddata(dctx, data));
}

isc_result_t
dst_context_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	REQUIRE(VALID_CTX(dctx));
	REQUIRE(sig != NULL);

	if (dst_algorithm_supported(dctx->key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);
	if (dctx->key->opaque == NULL)
		return (DST_R_NULLKEY);
	if (dctx->key->func->sign == NULL)
		return (DST_R_NOTPRIVATEKEY);

	return (dctx->key->func->sign(dctx, sig));
}

isc_result_t
dst_context_verify(dst_context_t *dctx, isc_region_t *sig) {
	REQUIRE(VALID_CTX(dctx));
	REQUIRE(sig != NULL);

	if (dst_algorithm_supported(dctx->key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);
	if (dctx->key->opaque == NULL)
		return (DST_R_NULLKEY);
	if (dctx->key->func->verify == NULL)
		return (DST_R_NOTPUBLICKEY);

	return (dctx->key->func->verify(dctx, sig));
}

isc_result_t
dst_context_digest(dst_context_t *dctx, isc_buffer_t *digest) {
	REQUIRE(VALID_CTX(dctx));
	REQUIRE(digest != NULL);

	if (dst_algorithm_supported(dctx->key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);
	if (dctx->key->func->digest == NULL)
		return (DST_R_UNSUPPORTEDALG);

	return (dctx->key->func->digest(dctx, digest));
}

isc_result_t
dst_key_computesecret(const dst_key_t *pub, const dst_key_t *priv,
		  isc_buffer_t *secret) 
{
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(pub) && VALID_KEY(priv));
	REQUIRE(secret != NULL);

	if (dst_algorithm_supported(pub->key_alg)  == ISC_FALSE ||
	    dst_algorithm_supported(priv->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if (pub->opaque == NULL || priv->opaque == NULL)
		return (DST_R_NULLKEY);

	if (pub->key_alg != priv->key_alg ||
	    pub->func->computesecret == NULL ||
	    priv->func->computesecret == NULL)
		return (DST_R_KEYCANNOTCOMPUTESECRET);

	if (dst_key_isprivate(priv) == ISC_FALSE)
		return (DST_R_NOTPRIVATEKEY);

	return (pub->func->computesecret(pub, priv, secret));
}

isc_result_t 
dst_key_tofile(const dst_key_t *key, const int type) {
	isc_result_t ret = ISC_R_SUCCESS;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));

	if (dst_algorithm_supported(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if (key->func->tofile == NULL)
		return (DST_R_UNSUPPORTEDALG);

	if ((type & (DST_TYPE_PRIVATE | DST_TYPE_PUBLIC)) == 0)
		return (DST_R_UNSUPPORTEDTYPE);

	if (type & DST_TYPE_PUBLIC) {
		ret = write_public_key(key);
		if (ret != ISC_R_SUCCESS)
			return (ret);
	}

	if ((type & DST_TYPE_PRIVATE) &&
	    (key->key_flags & DNS_KEYFLAG_TYPEMASK) != DNS_KEYTYPE_NOKEY)
		return (key->func->tofile(key));
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dst_key_fromfile(dns_name_t *name, const isc_uint16_t id,
		 const unsigned int alg, const int type, isc_mem_t *mctx,
		 dst_key_t **keyp)
{
	dst_key_t *key = NULL, *pubkey = NULL;
	isc_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(mctx != NULL);
	REQUIRE(keyp != NULL && *keyp == NULL);

	if (dst_algorithm_supported(alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if ((type & (DST_TYPE_PRIVATE | DST_TYPE_PUBLIC)) == 0)
		return (DST_R_UNSUPPORTEDTYPE);

	ret = read_public_key(name, id, alg, mctx, &pubkey);
	if (ret == ISC_R_NOTFOUND && (type & DST_TYPE_PUBLIC) == 0)
		key = get_key_struct(name, alg, 0, 0, 0, mctx);
	else if (ret != ISC_R_SUCCESS)
		return (ret);
	else {
		if (type == DST_TYPE_PUBLIC ||
		    (pubkey->key_flags & DNS_KEYFLAG_TYPEMASK) ==
		     DNS_KEYTYPE_NOKEY)
		{
			*keyp = pubkey;
			return (ISC_R_SUCCESS);
		}
	
		key = get_key_struct(name, pubkey->key_alg, pubkey->key_flags,
				     pubkey->key_proto, 0, mctx);
		dst_key_free(&pubkey);
	}

	if (key == NULL)
		return (ISC_R_NOMEMORY);

	if (key->func->fromfile == NULL) {
		dst_key_free(&key);
		return (DST_R_UNSUPPORTEDALG);
	}

	ret = key->func->fromfile(key, id);
	if (ret != ISC_R_SUCCESS) {
		dst_key_free(&key);
		return (ret);
	}

	*keyp = key;
	return (ISC_R_SUCCESS);
}

isc_result_t
dst_key_todns(const dst_key_t *key, isc_buffer_t *target) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(target != NULL);

	if (dst_algorithm_supported(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if (key->func->todns == NULL)
		return (DST_R_UNSUPPORTEDALG);

	if (isc_buffer_availablelength(target) < 4)
		return (ISC_R_NOSPACE);
	isc_buffer_putuint16(target, (isc_uint16_t)(key->key_flags & 0xffff));
	isc_buffer_putuint8(target, (isc_uint8_t)key->key_proto);
	isc_buffer_putuint8(target, (isc_uint8_t)key->key_alg);

	if (key->key_flags & DNS_KEYFLAG_EXTENDED) {
		if (isc_buffer_availablelength(target) < 2)
			return (ISC_R_NOSPACE);
		isc_buffer_putuint16(target,
				     (isc_uint16_t)((key->key_flags >> 16)
						    & 0xffff));
	}

	if (key->opaque == NULL) /* NULL KEY */
		return (ISC_R_SUCCESS);

	return (key->func->todns(key, target));
}

isc_result_t
dst_key_fromdns(dns_name_t *name, isc_buffer_t *source, isc_mem_t *mctx,
		dst_key_t **keyp)
{
	isc_uint8_t alg, proto;
	isc_uint32_t flags, extflags;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(source != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(keyp != NULL && *keyp == NULL);

	if (isc_buffer_remaininglength(source) < 4)
		return (DST_R_INVALIDPUBLICKEY);
	flags = isc_buffer_getuint16(source);
	proto = isc_buffer_getuint8(source);
	alg = isc_buffer_getuint8(source);

	if (!dst_algorithm_supported(alg))
		return (DST_R_UNSUPPORTEDALG);

	if (flags & DNS_KEYFLAG_EXTENDED) {
		if (isc_buffer_remaininglength(source) < 2)
			return (DST_R_INVALIDPUBLICKEY);
		extflags = isc_buffer_getuint16(source);
		flags |= (extflags << 16);
	}

	return (dst_key_frombuffer(name, alg, flags, proto, source, mctx,
				   keyp));
}

isc_result_t
dst_key_frombuffer(dns_name_t *name, const unsigned int alg,
		   const unsigned int flags, const unsigned int protocol,
		   isc_buffer_t *source, isc_mem_t *mctx, dst_key_t **keyp)
{
	dst_key_t *key;
	isc_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(source != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(keyp != NULL && *keyp == NULL);

	if (dst_algorithm_supported(alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	key = get_key_struct(name, alg, flags, protocol, 0, mctx);
	if (key == NULL)
		return (ISC_R_NOMEMORY);

	if (key->func->fromdns == NULL) {
		dst_key_free(&key);
		return (DST_R_UNSUPPORTEDALG);
	}

	ret = key->func->fromdns(key, source);
	if (ret != ISC_R_SUCCESS) {
		dst_key_free(&key);
		return (ret);
	}

	*keyp = key;
	return (ISC_R_SUCCESS);
}

isc_result_t 
dst_key_tobuffer(const dst_key_t *key, isc_buffer_t *target) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(target != NULL);

	if (dst_algorithm_supported(key->key_alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	if (key->func->todns == NULL)
		return (DST_R_UNSUPPORTEDALG);

	return (key->func->todns(key, target));
}

isc_result_t
dst_key_generate(dns_name_t *name, const unsigned int alg,
		 const unsigned int bits, const unsigned int param,
		 const unsigned int flags, const unsigned int protocol,
		 isc_mem_t *mctx, dst_key_t **keyp)
{
	dst_key_t *key;
	isc_result_t ret;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(mctx != NULL);
	REQUIRE(keyp != NULL && *keyp == NULL);

	if (dst_algorithm_supported(alg) == ISC_FALSE)
		return (DST_R_UNSUPPORTEDALG);

	key = get_key_struct(name, alg, flags, protocol, bits, mctx);
	if (key == NULL)
		return (ISC_R_NOMEMORY);

	if (bits == 0) { /* NULL KEY */
		key->key_flags |= DNS_KEYTYPE_NOKEY;
		*keyp = key;
		return (ISC_R_SUCCESS);
	}

	if (key->func->generate == NULL) {
		dst_key_free(&key);
		return (DST_R_UNSUPPORTEDALG);
	}

	ret = key->func->generate(key, param);
	if (ret != ISC_R_SUCCESS) {
		dst_key_free(&key);
		return (ret);
	}

	*keyp = key;
	return (ISC_R_SUCCESS);
}

isc_boolean_t
dst_key_compare(const dst_key_t *key1, const dst_key_t *key2) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key1));
	REQUIRE(VALID_KEY(key2));

	if (key1 == key2)
		return (ISC_TRUE);
	if (key1 == NULL || key2 == NULL)
		return (ISC_FALSE);
	if (key1->key_alg == key2->key_alg &&
	    key1->key_id == key2->key_id &&
	    key1->func->compare != NULL &&
	    key1->func->compare(key1, key2) == ISC_TRUE)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

isc_boolean_t
dst_key_paramcompare(const dst_key_t *key1, const dst_key_t *key2) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key1));
	REQUIRE(VALID_KEY(key2));

	if (key1 == key2)
		return (ISC_TRUE);
	if (key1 == NULL || key2 == NULL)
		return (ISC_FALSE);
	if (key1->key_alg == key2->key_alg &&
	    key1->func->paramcompare != NULL &&
	    key1->func->paramcompare(key1, key2) == ISC_TRUE)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

void
dst_key_free(dst_key_t **keyp) {
	isc_mem_t *mctx;
	dst_key_t *key;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(keyp != NULL && VALID_KEY(*keyp));

	key = *keyp;
	mctx = key->mctx;

	INSIST(key->func->destroy != NULL);

	if (key->opaque != NULL)
		key->func->destroy(key);

	dns_name_free(key->key_name, mctx);
	isc_mem_put(mctx, key->key_name, sizeof(dns_name_t));
	memset(key, 0, sizeof(dst_key_t));
	isc_mem_put(mctx, key, sizeof(dst_key_t));
	*keyp = NULL;
}

dns_name_t *
dst_key_name(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_name);
}

unsigned int
dst_key_size(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_size);
}

unsigned int
dst_key_proto(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_proto);
}

unsigned int
dst_key_alg(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_alg);
}

isc_uint32_t
dst_key_flags(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_flags);
}

isc_uint16_t
dst_key_id(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	return (key->key_id);
}

isc_boolean_t
dst_key_isprivate(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
	INSIST(key->func->isprivate != NULL);
	return (key->func->isprivate(key));
}

isc_boolean_t
dst_key_iszonekey(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
      
	if ((key->key_flags & DNS_KEYTYPE_NOAUTH) != 0)
		return (ISC_FALSE);
	if ((key->key_flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		return (ISC_FALSE);
	if (key->key_proto != DNS_KEYPROTO_DNSSEC &&
	    key->key_proto != DNS_KEYPROTO_ANY)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

isc_boolean_t
dst_key_isnullkey(const dst_key_t *key) {
	REQUIRE(VALID_KEY(key));
      
	if ((key->key_flags & DNS_KEYFLAG_TYPEMASK) != DNS_KEYTYPE_NOKEY)
		return (ISC_FALSE);
	if ((key->key_flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		return (ISC_FALSE);
	if (key->key_proto != DNS_KEYPROTO_DNSSEC &&
	    key->key_proto != DNS_KEYPROTO_ANY)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

isc_result_t
dst_key_buildfilename(const dst_key_t *key, const int type, isc_buffer_t *out)
{
	const char *suffix;
	unsigned int len;
	isc_result_t result;

	REQUIRE(VALID_KEY(key));
	REQUIRE(type == DST_TYPE_PRIVATE || type == DST_TYPE_PUBLIC ||
		type == 0);
	REQUIRE(out != NULL);
	if (type == 0)
		suffix = "";
	else if (type == DST_TYPE_PRIVATE)
		suffix = ".private";
	else
		suffix = ".key";
	if (isc_buffer_availablelength(out) < 1)
		return (ISC_R_NOSPACE);
	isc_buffer_putstr(out, "K");
	result = dns_name_totext(key->key_name, ISC_FALSE, out);
	if (result != ISC_R_SUCCESS)
		return (result);
	len = 1 + 3 + 1 + 5 + strlen(suffix) + 1;
	if (isc_buffer_availablelength(out) < len)
		return (ISC_R_NOSPACE);
	sprintf((char *) isc_buffer_used(out), "+%03d+%05d%s",
		key->key_alg, key->key_id, suffix);
	isc_buffer_add(out, len);
	return (ISC_R_SUCCESS);
}

isc_result_t
dst_key_parsefilename(isc_buffer_t *source, isc_mem_t *mctx, dns_name_t *name,
		      isc_uint16_t *id, unsigned int *alg, char **suffix)
{
	isc_result_t result = ISC_R_SUCCESS;
	char c, str[6], *p, *endp;
	isc_region_t r;
	isc_buffer_t b;
	unsigned int length;
	long l;

	REQUIRE(source != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(dns_name_hasbuffer(name));
	REQUIRE(id != NULL);
	REQUIRE(alg != NULL);
	REQUIRE(suffix == NULL || *suffix == NULL);

	if (isc_buffer_remaininglength(source) < 1)
		return (ISC_R_UNEXPECTEDEND);
	c = (char) isc_buffer_getuint8(source);
	if (c != 'K')
		return (ISC_R_INVALIDFILE);

	isc_buffer_remainingregion(source, &r);
	p = (char *)r.base;
	length = r.length;
	while (length > 0 && *p != '+') {
		length--;
		p++;
	}
	if (length == 0)
		return (ISC_R_UNEXPECTEDEND);
	length = p - (char *)r.base;
	isc_buffer_init(&b, r.base, length);
	isc_buffer_add(&b, length);
	result = dns_name_fromtext(name, &b, dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS)
		return (result);
	isc_buffer_forward(source, length);
	if (isc_buffer_remaininglength(source) < 1 + 3 + 1 + 5)
		return (ISC_R_UNEXPECTEDEND);
	c = (char) isc_buffer_getuint8(source);
	if (c != '+')
		return (ISC_R_INVALIDFILE);
	isc_buffer_remainingregion(source, &r);
	memcpy(str, r.base, 3);
	str[3] = 0;
	*alg = strtol(str, &endp, 10);
	if (*endp != '\0')
		return (ISC_R_INVALIDFILE);
	isc_buffer_forward(source, 3);
	c = (char) isc_buffer_getuint8(source);
	if (c != '+')
		return (ISC_R_INVALIDFILE);
	isc_buffer_remainingregion(source, &r);
	memcpy(str, r.base, 5);
	str[5] = 0;

	l = strtol(str, &endp, 10);
	if (*endp != '\0' || l > (isc_uint16_t)-1)
		return (ISC_R_INVALIDFILE);
	*id = (isc_uint16_t)l;

	isc_buffer_forward(source, 5);
	if (suffix == NULL)
		return (ISC_R_SUCCESS);
	isc_buffer_remainingregion(source, &r);
	*suffix = isc_mem_get(mctx, r.length + 1);
	if (*suffix == NULL)
		return (ISC_R_NOMEMORY);
	if (r.length > 0)
		memcpy(*suffix, r.base, r.length);
	(*suffix)[r.length] = 0;
	return (ISC_R_SUCCESS);
}

isc_result_t
dst_key_sigsize(const dst_key_t *key, unsigned int *n) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(n != NULL);

	switch (key->key_alg) {
		case DST_ALG_RSA:
			*n = (key->key_size + 7) / 8;
			break;
		case DST_ALG_DSA:
			*n = DNS_SIG_DSASIGSIZE;
			break;
		case DST_ALG_HMACMD5:
			*n = 16;
			break;
		case DST_ALG_DH:
		case DST_ALG_MD5:
		default:
			return (DST_R_UNSUPPORTEDALG);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
dst_key_secretsize(const dst_key_t *key, unsigned int *n) {
	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(VALID_KEY(key));
	REQUIRE(n != NULL);

	switch (key->key_alg) {
		case DST_ALG_DH:
			*n = (key->key_size + 7) / 8;
			break;
		case DST_ALG_RSA:
		case DST_ALG_DSA:
		case DST_ALG_HMACMD5:
		case DST_ALG_MD5:
		default:
			return (DST_R_UNSUPPORTEDALG);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t 
dst_random_get(const unsigned int wanted, isc_buffer_t *target) {
	isc_region_t r;
	int status;

	RUNTIME_CHECK(isc_once_do(&once, initialize) == ISC_R_SUCCESS);
	REQUIRE(target != NULL);

	isc_buffer_availableregion(target, &r);
	if (r.length < wanted)
		return (ISC_R_NOSPACE);

	RUNTIME_CHECK(isc_mutex_lock((&random_lock)) == ISC_R_SUCCESS);
	status = RAND_bytes(r.base, wanted);
	RUNTIME_CHECK(isc_mutex_unlock((&random_lock)) == ISC_R_SUCCESS);
	if (status == 0)
		return (DST_R_NORANDOMNESS);

	isc_buffer_add(target, wanted);
	return (ISC_R_SUCCESS);
}

/***
 *** Static methods
 ***/

/*
 * Initializes the Digital Signature Toolkit.
 */
static void
initialize(void) {
	memset(dst_t_func, 0, sizeof(dst_t_func));

	RUNTIME_CHECK(isc_mem_create(0, 0, &dst_memory_pool) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_mutex_init(&random_lock) == ISC_R_SUCCESS);

	dst_result_register();

	dst__hmacmd5_init(&dst_t_func[DST_ALG_HMACMD5]);
#ifdef DNSSAFE
	dst__dnssafersa_init(&dst_t_func[DST_ALG_RSA]);
#endif
#ifdef OPENSSL
	dst__openssldsa_init(&dst_t_func[DST_ALG_DSA]);
	dst__openssldh_init(&dst_t_func[DST_ALG_DH]);
	dst__opensslmd5_init(&dst_t_func[DST_ALG_MD5]);

	memset(&md5key, 0, sizeof(dst_key_t));
	md5key.magic = KEY_MAGIC;
	md5key.key_name = NULL;
	md5key.key_alg = DST_ALG_MD5;
	md5key.mctx = dst_memory_pool;
	md5key.opaque = NULL;
	md5key.func = dst_t_func[DST_ALG_MD5];
	dst_key_md5 = &md5key;

	/*
	 * Seed the random number generator, if necessary.
	 * XXX This doesn't do a very good job, and must be fixed.
	 */
	if (RAND_status() == 0) {
		isc_random_t rctx;
		isc_uint32_t val;
		isc_time_t now;
		isc_result_t result;

		isc_random_init(&rctx);
		result = isc_time_now(&now);
		INSIST(result == ISC_R_SUCCESS);
		isc_random_seed(&rctx, isc_time_nanoseconds(&now));
		while (RAND_status() == 0) {
			isc_random_get(&rctx, &val);
			RAND_add(&val, sizeof(isc_uint32_t), 1);
		}
		isc_random_invalidate(&rctx);
	}
#endif
}

/* 
 * Allocates a key structure and fills in some of the fields. 
 */
static dst_key_t *
get_key_struct(dns_name_t *name, const unsigned int alg,
	       const unsigned int flags, const unsigned int protocol,
	       const unsigned int bits, isc_mem_t *mctx)
{
	dst_key_t *key; 
	isc_result_t result;

	REQUIRE(dst_algorithm_supported(alg) != ISC_FALSE);

	key = (dst_key_t *) isc_mem_get(mctx, sizeof(dst_key_t));
	if (key == NULL)
		return (NULL);

	memset(key, 0, sizeof(dst_key_t));
	key->magic = KEY_MAGIC;

	key->key_name = isc_mem_get(mctx, sizeof(dns_name_t));
	if (key->key_name == NULL) {
		isc_mem_put(mctx, key, sizeof(dst_key_t));
		return (NULL);
	}
	dns_name_init(key->key_name, NULL);
	result = dns_name_dup(name, mctx, key->key_name);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, key->key_name, sizeof(dns_name_t));
		isc_mem_put(mctx, key, sizeof(dst_key_t));
		return (NULL);
	}
	key->key_alg = alg;
	key->key_flags = flags;
	key->key_proto = protocol;
	key->mctx = mctx;
	key->opaque = NULL;
	key->key_size = bits;
	key->func = dst_t_func[alg];
	return (key);
}

/*
 * Reads a public key from disk
 */
static isc_result_t
read_public_key(dns_name_t *name, const isc_uint16_t id, const unsigned int alg,
		isc_mem_t *mctx, dst_key_t **keyp)
{
	char filename[ISC_DIR_NAMEMAX];
	u_char rdatabuf[DST_KEY_MAXSIZE];
	isc_buffer_t b;
	isc_lex_t *lex = NULL;
	isc_token_t token;
	isc_result_t ret;
	dns_rdata_t rdata;
	unsigned int opt = ISC_LEXOPT_DNSMULTILINE;
	dst_key_t *tempkey;

	tempkey = get_key_struct(name, alg, 0, 0, 0, mctx);
	if (tempkey == NULL)
		return (ISC_R_NOMEMORY);
	tempkey->key_id = id;
	isc_buffer_init(&b, filename, sizeof(filename));
	ret = dst_key_buildfilename(tempkey, DST_TYPE_PUBLIC, &b);
	dst_key_free(&tempkey);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	/*
	 * Open the file and read its formatted contents
	 * File format:
	 *    domain.name [ttl] [IN] KEY  <flags> <protocol> <algorithm> <key>
	 */

	/* 1500 should be large enough for any key */
	ret = isc_lex_create(mctx, 1500, &lex);
	if (ret != ISC_R_SUCCESS)
		return (ISC_R_NOMEMORY);

	ret = isc_lex_openfile(lex, filename);
	if (ret != ISC_R_SUCCESS) {
		if (ret == ISC_R_FILENOTFOUND)
			ret = ISC_R_NOTFOUND;
		goto cleanup;
	}

#define NEXTTOKEN(lex, opt, token) { \
	ret = isc_lex_gettoken(lex, opt, token); \
	if (ret != ISC_R_SUCCESS) \
		goto cleanup; \
	}

#define BADTOKEN() { \
	ret = ISC_R_UNEXPECTEDTOKEN; \
	goto cleanup; \
	}

	/* Read the domain name */
	NEXTTOKEN(lex, opt, &token);
	
	/* Read the next word: either TTL, 'IN', or 'KEY' */
	NEXTTOKEN(lex, opt, &token);

	/* If it's a TTL, read the next one */
	if (token.type == isc_tokentype_number)
		NEXTTOKEN(lex, opt, &token);
	
	if (token.type != isc_tokentype_string)
		BADTOKEN();

	if (strcasecmp(token.value.as_pointer, "IN") == 0)
		NEXTTOKEN(lex, opt, &token);
	
	if (token.type != isc_tokentype_string)
		BADTOKEN();

	if (strcasecmp(token.value.as_pointer, "KEY") != 0)
		BADTOKEN();
	
	isc_buffer_init(&b, rdatabuf, sizeof(rdatabuf));
	ret = dns_rdata_fromtext(&rdata, dns_rdataclass_in, dns_rdatatype_key,
				 lex, NULL, ISC_FALSE, &b, NULL);
	if (ret != ISC_R_SUCCESS)
		goto cleanup;

	ret = dst_key_fromdns(name, &b, mctx, keyp);
	if (ret != ISC_R_SUCCESS || (*keyp)->key_alg != alg)
		goto cleanup;

	isc_lex_close(lex);
	isc_lex_destroy(&lex);

	return (ISC_R_SUCCESS);

cleanup:
        if (lex != NULL) {
		isc_lex_close(lex);
		isc_lex_destroy(&lex);
        }
	return (ret);
}

/*
 * Writes a public key to disk in DNS format.
 */
static isc_result_t
write_public_key(const dst_key_t *key) {
	FILE *fp;
	isc_buffer_t keyb, textb, fileb;
	isc_region_t r;
	char filename[ISC_DIR_NAMEMAX];
	unsigned char key_array[DST_KEY_MAXSIZE];
	char text_array[DST_KEY_MAXSIZE];
	isc_result_t ret;
	isc_result_t dnsret;
	dns_rdata_t rdata;

	REQUIRE(VALID_KEY(key));

	isc_buffer_init(&keyb, key_array, sizeof(key_array));
	isc_buffer_init(&textb, text_array, sizeof(text_array));

	ret = dst_key_todns(key, &keyb);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	isc_buffer_usedregion(&keyb, &r);
	dns_rdata_fromregion(&rdata, dns_rdataclass_in, dns_rdatatype_key, &r);

	dnsret = dns_rdata_totext(&rdata, (dns_name_t *) NULL, &textb);
	if (dnsret != ISC_R_SUCCESS)
		return (DST_R_INVALIDPUBLICKEY);

	dns_rdata_freestruct(&rdata);

	isc_buffer_usedregion(&textb, &r);
	
	/*
	 * Make the filename.
	 */
	isc_buffer_init(&fileb, filename, sizeof(filename));
	ret = dst_key_buildfilename(key, DST_TYPE_PUBLIC, &fileb);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	/*
	 * Create public key file.
	 */
	if ((fp = fopen(filename, "w")) == NULL)
		return (DST_R_WRITEERROR);

	ret = dns_name_print(key->key_name, fp);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	fprintf(fp, " IN KEY ");
	fwrite(r.base, 1, r.length, fp);
	fputc('\n', fp);
	fclose(fp);
	return (ISC_R_SUCCESS);
}

void *
dst__mem_alloc(size_t size) {
	INSIST(dst_memory_pool != NULL);
	return (isc_mem_allocate(dst_memory_pool, size));
}

void
dst__mem_free(void *ptr) {
	INSIST(dst_memory_pool != NULL);
	if (ptr != NULL)
		isc_mem_free(dst_memory_pool, ptr);
}

void *
dst__mem_realloc(void *ptr, size_t size) {
	void *p;

	INSIST(dst_memory_pool != NULL);
	p = NULL;
	if (size > 0) {
		p = dst__mem_alloc(size);
		if (p != NULL && ptr != NULL)
			memcpy(p, ptr, size);
	}
	if (ptr != NULL)
		dst__mem_free(ptr);
	return (p);
}
