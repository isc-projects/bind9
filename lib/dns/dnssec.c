/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * $Id: dnssec.c,v 1.8 1999/10/07 21:51:49 bwelling Exp $
 * Principal Author: Brian Wellington
 */


#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/list.h>
#include <isc/net.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/stdtime.h>
#include <isc/types.h>

#include <dns/db.h>
#include <dns/keyvalues.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatalist.h>
#include <dns/rdatastruct.h>
#include <dns/dnssec.h>

#include <dst/dst.h>
#include <dst/result.h>

#define TRUSTED_KEY_MAGIC	0x54525354	/* TRST */
#define VALID_TRUSTED_KEY(x)	((x) != NULL && (x)->magic == TRUSTED_KEY_MAGIC)

typedef struct dns_trusted_key dns_trusted_key_t;

struct dns_trusted_key {
        unsigned int                    magic;          /* Magic number. */
        isc_mem_t                       *mctx;
        dst_key_t                       *key;           /* Key */
        dns_name_t                      name;           /* Key name */
        ISC_LINK(dns_trusted_key_t)     link;
};

#define TYPE_SIGN 0
#define TYPE_VERIFY 1

typedef struct digestctx {
	dst_key_t *key;
	dst_context_t context;
	isc_uint8_t type;
} digestctx_t;

/* XXXBEW If an unsorted list isn't good enough, this can be updated */
static ISC_LIST(dns_trusted_key_t) trusted_keys;
static isc_rwlock_t trusted_key_lock;


static isc_result_t digest_callback(void *arg, isc_region_t *data);
static isc_result_t keyname_to_name(char *keyname, isc_mem_t *mctx,
				    dns_name_t *name);
static int rdata_compare_wrapper(const void *rdata1, const void *rdata2);
static isc_result_t rdataset_to_sortedarray(dns_rdataset_t *set,
					    isc_mem_t *mctx,
					    dns_rdata_t **rdata, int *nrdata);


static isc_result_t
digest_callback(void *arg, isc_region_t *data) {
	digestctx_t *ctx = arg;
	isc_result_t result;

	REQUIRE(ctx->type == TYPE_SIGN || ctx->type == TYPE_VERIFY);

	if (ctx->type == TYPE_SIGN)
		result = dst_sign(DST_SIGMODE_UPDATE, ctx->key, &ctx->context,
				  data, NULL);
	else
		result = dst_verify(DST_SIGMODE_UPDATE, ctx->key, &ctx->context,
				    data, NULL);
	return (result);
}

/* converts the name of a key into a canonical isc_name_t */
static isc_result_t
keyname_to_name(char *keyname, isc_mem_t *mctx, dns_name_t *name) {
	isc_buffer_t src, dst;
	unsigned char data[1024];
	isc_result_t ret;
	dns_name_t tname;

	dns_name_init(name, NULL);
	dns_name_init(&tname, NULL);
	isc_buffer_init(&src, keyname, strlen(keyname), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&src, strlen(keyname));
	isc_buffer_init(&dst, data, sizeof(data), ISC_BUFFERTYPE_BINARY);
	ret = dns_name_fromtext(&tname, &src, NULL, ISC_TRUE, &dst);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	ret = dns_name_dup(&tname, mctx, name);
	dns_name_downcase(name, name, NULL);
	return (ret);
}

/* make qsort happy */
static int
rdata_compare_wrapper(const void *rdata1, const void *rdata2) {
	return dns_rdata_compare((dns_rdata_t *)rdata1, (dns_rdata_t *)rdata2);
}

/* sort the rdataset into an array */
static isc_result_t
rdataset_to_sortedarray(dns_rdataset_t *set, isc_mem_t *mctx,
			dns_rdata_t **rdata, int *nrdata)
{
	isc_result_t ret;
	int i = 0, n = 1;
	dns_rdata_t *data;

	ret = dns_rdataset_first(set);
	if (ret != ISC_R_SUCCESS)
		return (ret);
	/* count the records */
	while (dns_rdataset_next(set) == ISC_R_SUCCESS)
		n++;

	ret = dns_rdataset_first(set);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	data = isc_mem_get(mctx, n * sizeof(dns_rdata_t));

	/* put them in the array */
	do {
		dns_rdataset_current(set, &data[i++]);
	} while (dns_rdataset_next(set) == ISC_R_SUCCESS);

	/* This better not change.  Should this be locked somehow? XXXBEW */
	INSIST(i == n);

	/* sort the array */
	qsort(data, n, sizeof(dns_rdata_t), rdata_compare_wrapper);
	*rdata = data;
	*nrdata = n;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_dnssec_add_trusted_key(dst_key_t *key, isc_mem_t *mctx) {
	dns_trusted_key_t *tkey;
	isc_result_t ret;

	REQUIRE(key != NULL);
	REQUIRE(mctx != NULL);

	tkey = isc_mem_get(mctx, sizeof(dns_trusted_key_t));
	if (tkey == NULL)
		return (ISC_R_NOMEMORY);

	ret = keyname_to_name(dst_key_name(key), mctx, &tkey->name);
	if (ret != ISC_R_SUCCESS)
		goto cleanup;

	tkey->mctx = mctx;
	ISC_LINK_INIT(tkey, link);
	isc_rwlock_lock(&trusted_key_lock, isc_rwlocktype_write);
	ISC_LIST_APPEND(trusted_keys, tkey, link);
	isc_rwlock_unlock(&trusted_key_lock, isc_rwlocktype_write);

	tkey->mctx = mctx;
	tkey->magic = TRUSTED_KEY_MAGIC;
	return (ISC_R_SUCCESS);

cleanup:
	isc_mem_put(mctx, tkey, sizeof(dns_trusted_key_t));
	return (ret);
}

isc_result_t
dns_dnssec_keyfromrdata(dns_name_t *name, dns_rdata_t *rdata, isc_mem_t *mctx,
			dst_key_t **key)
{
	isc_buffer_t b, namebuf;
	isc_region_t r;
	isc_result_t ret;
	char namestr[1024];

	INSIST(name != NULL);
	INSIST(rdata != NULL);
	INSIST(mctx != NULL);
	INSIST(key != NULL);
	INSIST(*key == NULL);

	isc_buffer_init(&namebuf, namestr, sizeof(namestr) - 1,
			ISC_BUFFERTYPE_TEXT);
	ret = dns_name_totext(name, ISC_FALSE, &namebuf);
	if (ret != ISC_R_SUCCESS)
		return ret;
	isc_buffer_used(&namebuf, &r);
	namestr[r.length] = 0;
	dns_rdata_toregion(rdata, &r);
	isc_buffer_init(&b, r.base, r.length, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&b, r.length);
	return (dst_key_fromdns(namestr, &b, mctx, key));
}

isc_result_t
dns_dnssec_sign(dns_name_t *name, dns_rdataset_t *set, dst_key_t *key,
		isc_stdtime_t *inception, isc_stdtime_t *expire,
		isc_mem_t *mctx, isc_buffer_t *buffer, dns_rdata_t *sigrdata)
{
	dns_rdata_generic_sig_t sig;
	dns_rdata_t *rdatas;
	int nrdatas, i;
	isc_buffer_t b, sigbuf, envbuf;
	isc_region_t r;
	dst_context_t ctx = NULL;
	isc_result_t ret;
	unsigned char data[300];
	digestctx_t dctx;
	isc_uint32_t flags;

	REQUIRE(name != NULL);
	REQUIRE(set != NULL);
	REQUIRE(key != NULL);
	REQUIRE(inception != NULL);
	REQUIRE(expire != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(sigrdata != NULL);

	if (*inception >= *expire)
		return (DNS_R_INVALIDTIME);

	/* Is the key allowed to sign data? */
	flags = dst_key_flags(key);
	if (flags & DNS_KEYTYPE_NOAUTH)
		return (DNS_R_KEYUNAUTHORIZED);
	if ((flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		return (DNS_R_KEYUNAUTHORIZED);

	sig.mctx = mctx;
	sig.common.rdclass = set->rdclass;
	sig.common.rdtype = dns_rdatatype_sig;
	ISC_LINK_INIT(&sig.common, link);

	ret = keyname_to_name(dst_key_name(key), mctx, &sig.signer);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	sig.covered = set->type;
	sig.algorithm = dst_key_alg(key);
	sig.labels = dns_name_countlabels(name) - 1;
	if (dns_name_iswildcard(name))
		sig.labels--;
	sig.originalttl = set->ttl;
	sig.timesigned = *inception;
	sig.timeexpire = *expire;
	sig.keyid = dst_key_id(key);
	if (dst_sig_size(key) < 0) {
		/* close enough for now */
		return (DNS_R_KEYUNAUTHORIZED);
	}
	sig.siglen = dst_sig_size(key);
	sig.signature = isc_mem_get(mctx, sig.siglen);
	if (sig.signature == NULL)
		goto cleanup_name;

	isc_buffer_init(&b, data, sizeof(data), ISC_BUFFERTYPE_BINARY);
	ret = dns_rdata_fromstruct(NULL, sig.common.rdclass,
				  sig.common.rdtype, &sig, &b);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;

	isc_buffer_used(&b, &r);

	/* Digest the SIG rdata */
	r.length -= sig.siglen;
	ret = dst_sign(DST_SIGMODE_INIT | DST_SIGMODE_UPDATE,
		       key, &ctx, &r, NULL);

	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;

	dns_name_toregion(name, &r);

	/* create an envelope for each rdata: <name|type|class|ttl> */
	isc_buffer_init(&envbuf, data, sizeof(data), ISC_BUFFERTYPE_BINARY);
	memcpy(data, r.base, r.length);
	isc_buffer_add(&envbuf, r.length);
	isc_buffer_putuint16(&envbuf, set->type);
	isc_buffer_putuint16(&envbuf, set->rdclass);
	isc_buffer_putuint32(&envbuf, set->ttl);
	
	memset(&dctx, 0, sizeof(dctx));
	dctx.key = key;
	dctx.context = ctx;
	dctx.type = TYPE_SIGN;

	ret = rdataset_to_sortedarray(set, mctx, &rdatas, &nrdatas);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;
	isc_buffer_used(&envbuf, &r);

	for (i = 0; i < nrdatas; i++) {
		isc_uint16_t len;
		isc_buffer_t lenbuf;
		isc_region_t lenr;
		
		/* Digest the envelope */
		ret = dst_sign(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_array;

		/* Digest the length of the rdata */
		isc_buffer_init(&lenbuf, &len, sizeof(len),
				ISC_BUFFERTYPE_BINARY);
		isc_buffer_putuint16(&lenbuf, rdatas[i].length);
		isc_buffer_used(&lenbuf, &lenr);
		ret = dst_sign(DST_SIGMODE_UPDATE, key, &ctx, &lenr, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_array;

		/* Digest the rdata */
		ret = dns_rdata_digest(&rdatas[i], digest_callback, &dctx);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_array;
	}
		
	isc_buffer_init(&sigbuf, sig.signature, sig.siglen,
			ISC_BUFFERTYPE_BINARY);
	ret = dst_sign(DST_SIGMODE_FINAL, key, &ctx, NULL, &sigbuf);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_array;
	isc_buffer_used(&sigbuf, &r);
	if (r.length != sig.siglen) {
		ret = DNS_R_NOSPACE;
		goto cleanup_array;
	}
	memcpy(sig.signature, r.base, sig.siglen);

	ret = dns_rdata_fromstruct(sigrdata, sig.common.rdclass,
				  sig.common.rdtype, &sig, buffer);

cleanup_array:
	isc_mem_put(mctx, rdatas, nrdatas * sizeof(dns_rdata_t));
cleanup_signature:
	isc_mem_put(mctx, sig.signature, sig.siglen);
cleanup_name:
	dns_name_free(&sig.signer, mctx);

	return (ret);
}

isc_result_t
dns_dnssec_verify(dns_name_t *name, dns_rdataset_t *set, dst_key_t *key,
		  isc_mem_t *mctx, dns_rdata_t *sigrdata)
{
	dns_rdata_generic_sig_t sig;
	dns_name_t newname;
	isc_region_t r;
	isc_buffer_t envbuf;
	dns_rdata_t *rdatas;
	int nrdatas, i;
	isc_stdtime_t now;
	isc_result_t ret;
	unsigned char data[300];
	dst_context_t ctx;
	digestctx_t dctx;
	int labels;
	isc_uint32_t flags;

	REQUIRE(name != NULL);
	REQUIRE(set != NULL);
	REQUIRE(key != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(sigrdata != NULL && sigrdata->type == dns_rdatatype_sig);

	ret = dns_rdata_tostruct(sigrdata, &sig, mctx);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	ret = isc_stdtime_get(&now);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_struct;

	/* Is SIG temporally valid? */
	if (sig.timesigned > now)
		return (DNS_R_SIGFUTURE);
	else if (sig.timeexpire < now)
		return (DNS_R_SIGEXPIRED);

	/* Is the key allowed to sign data? */
	flags = dst_key_flags(key);
	if (flags & DNS_KEYTYPE_NOAUTH)
		return (DNS_R_KEYUNAUTHORIZED);
	if ((flags & DNS_KEYFLAG_OWNERMASK) != DNS_KEYOWNER_ZONE)
		return (DNS_R_KEYUNAUTHORIZED);

	/* Digest the SIG rdata (not including the signature) */
	dns_rdata_toregion(sigrdata, &r);
	r.length -= sig.siglen;
	if (r.length < 20) {
		ret = DNS_R_RANGE;
		goto cleanup_struct;
	}
	
	ret = dst_verify(DST_SIGMODE_INIT | DST_SIGMODE_UPDATE,
			 key, &ctx, &r, NULL);

	/* if the name is an expanded wildcard, use the wildcard name */
	dns_name_init(&newname, NULL);
	labels = dns_name_countlabels(name) - 1;
	dns_name_getlabelsequence(name, labels - sig.labels, sig.labels + 1,
				  &newname);
	dns_name_toregion(&newname, &r);

	/* create an envelope for each rdata: <name|type|class|ttl> */
	isc_buffer_init(&envbuf, data, sizeof(data), ISC_BUFFERTYPE_BINARY);
	if (labels - sig.labels > 0) {
		isc_buffer_putuint8(&envbuf, 1);
		isc_buffer_putuint8(&envbuf, '*');
		memcpy(data + 2, r.base, r.length);
	}
	else
		memcpy(data, r.base, r.length);
	isc_buffer_add(&envbuf, r.length);
	isc_buffer_putuint16(&envbuf, set->type);
	isc_buffer_putuint16(&envbuf, set->rdclass);
	isc_buffer_putuint32(&envbuf, set->ttl);

	memset(&dctx, 0, sizeof(dctx));
	dctx.key = key;
	dctx.context = ctx;
	dctx.type = TYPE_VERIFY;

	ret = rdataset_to_sortedarray(set, mctx, &rdatas, &nrdatas);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_struct;
	isc_buffer_used(&envbuf, &r);

	for (i = 0; i < nrdatas; i++) {
		isc_uint16_t len;
		isc_buffer_t lenbuf;
		isc_region_t lenr;

		/* Digest the envelope */
		ret = dst_verify(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_array;

		/* Digest the rdata length */
		isc_buffer_init(&lenbuf, &len, sizeof(len),
				ISC_BUFFERTYPE_BINARY);
		isc_buffer_putuint16(&lenbuf, rdatas[i].length);
		isc_buffer_used(&lenbuf, &lenr);

		/* Digest the rdata */
		ret = dst_verify(DST_SIGMODE_UPDATE, key, &ctx, &lenr, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_array;
		ret = dns_rdata_digest(&rdatas[i], digest_callback, &dctx);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_array;
	}

	r.base = sig.signature;
	r.length = sig.siglen;
	ret = dst_verify(DST_SIGMODE_FINAL, key, &ctx, NULL, &r);
	if (ret == DST_R_VERIFYFINALFAILURE)
		ret = DNS_R_SIGINVALID;

cleanup_array:
	isc_mem_put(mctx, rdatas, nrdatas * sizeof(dns_rdata_t));
cleanup_struct:
	dns_rdata_freestruct(&sig);

	return (ret);
}

isc_result_t
dns_dnssec_init() {
	isc_result_t ret;

        ret = isc_rwlock_init(&trusted_key_lock, 0, 0);
        if (ret != ISC_R_SUCCESS) {
                UNEXPECTED_ERROR(__FILE__, __LINE__,
                                 "isc_rwlock_init() failed: %s",
                                 isc_result_totext(ret));
                return (DNS_R_UNEXPECTED);
        }
	
	ISC_LIST_INIT(trusted_keys);

	return (ISC_R_SUCCESS);
}

void
dns_dnssec_destroy() {
	while (!ISC_LIST_EMPTY(trusted_keys)) {
		dns_trusted_key_t *key = ISC_LIST_HEAD(trusted_keys);
		isc_mem_t *mctx = key->mctx;
		dns_name_free(&key->name, mctx);
		isc_mem_put(mctx, key, sizeof(dns_trusted_key_t));
	}
}

#define is_zone_key(key) ((dst_key_flags(key) & DNS_KEYFLAG_OWNERMASK) \
			  == DNS_KEYOWNER_ZONE)

#define check_result(op, msg) \
	do { result = (op); \
		if (result != DNS_R_SUCCESS) { \
			fprintf(stderr, "%s: %s\n", msg, \
				isc_result_totext(result)); \
			goto failure; \
		} \
	} while (0)

dns_result_t
dns_dnssec_findzonekeys(dns_db_t *db, dns_dbversion_t *ver, dns_dbnode_t *node, 
			dns_name_t *name, isc_mem_t *mctx, unsigned int maxkeys,
			dst_key_t **keys, unsigned int *nkeys)
{
	dns_rdataset_t rdataset;
	dns_rdata_t rdata;
	isc_result_t result;
	dst_key_t *pubkey;
	unsigned int count = 0;

	*nkeys = 0;
	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, ver, dns_rdatatype_key, 0, 0,
				     &rdataset, NULL);
	check_result(result, "dns_db_findrdataset()");
	result = dns_rdataset_first(&rdataset);
	check_result(result, "dns_rdataset_first()");
	while (result == ISC_R_SUCCESS && count < maxkeys) {
		pubkey = NULL;
		dns_rdataset_current(&rdataset, &rdata);
		result = dns_dnssec_keyfromrdata(name, &rdata, mctx, &pubkey);
		check_result(result, "dns_dnssec_keyfromrdata()");
		if (!is_zone_key(pubkey))
			goto next;
		result = dst_key_fromfile(dst_key_name(pubkey),
					  dst_key_id(pubkey),
					  dst_key_alg(pubkey),
					  DST_TYPE_PRIVATE,
					  mctx, &keys[count++]);
		check_result(result, "dst_key_fromfile()");
 next:
		dst_key_free(pubkey);
		pubkey = NULL;
		result = dns_rdataset_next(&rdataset);
	}
	if (result != DNS_R_NOMORE)
		check_result(result, "iteration over zone keys");
	result = DNS_R_SUCCESS;
	if (count == 0)
		check_result(ISC_R_FAILURE, "no key found");
		
 failure:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (pubkey != NULL)
		dst_key_free(pubkey);
	*nkeys = count;
	return (result);
}
