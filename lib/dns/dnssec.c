/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
 * $Id: dnssec.c,v 1.24 2000/03/13 19:27:33 bwelling Exp $
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
#include <dns/tsig.h> /* for DNS_TSIG_FUDGE */

#include <dst/dst.h>
#include <dst/result.h>

#define is_response(msg) (msg->flags & DNS_MESSAGEFLAG_QR)

#define RETERR(x) do { \
	result = (x); \
	if (result != ISC_R_SUCCESS) \
		goto failure; \
	} while (0)


#define TYPE_SIGN 0
#define TYPE_VERIFY 1

typedef struct digestctx {
	dst_key_t *key;
	dst_context_t context;
	isc_uint8_t type;
} digestctx_t;

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

	/* sort the array */
	qsort(data, n, sizeof(dns_rdata_t), rdata_compare_wrapper);
	*rdata = data;
	*nrdata = n;
	return (ISC_R_SUCCESS);
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
	unsigned int sigsize;

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
	sig.labels = dns_name_depth(name) - 1;
	if (dns_name_iswildcard(name))
		sig.labels--;
	sig.originalttl = set->ttl;
	sig.timesigned = *inception;
	sig.timeexpire = *expire;
	sig.keyid = dst_key_id(key);
	ret = dst_sig_size(key, &sigsize);
	if (ret != ISC_R_SUCCESS)
		return (ret);
	sig.siglen = sigsize;
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
		INSIST(rdatas[i].length < 65536);
		isc_buffer_putuint16(&lenbuf, (isc_uint16_t)rdatas[i].length);
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
	dns_fixedname_t fnewname;
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

	isc_stdtime_get(&now);

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
	RUNTIME_CHECK(r.length >= 20);
	
	ret = dst_verify(DST_SIGMODE_INIT | DST_SIGMODE_UPDATE,
			 key, &ctx, &r, NULL);

	/* if the name is an expanded wildcard, use the wildcard name */
	labels = dns_name_depth(name) - 1;
	if (labels - sig.labels > 0) {
		dns_fixedname_init(&fnewname);
		dns_name_splitatdepth(name, sig.labels + 1, NULL,
				      dns_fixedname_name(&fnewname));
		dns_name_toregion(dns_fixedname_name(&fnewname), &r);
	}
	else
		dns_name_toregion(name, &r);

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
		INSIST(rdatas[i].length < 65536);
		isc_buffer_putuint16(&lenbuf, (isc_uint16_t)rdatas[i].length);
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

isc_result_t
dns_dnssec_findzonekeys(dns_db_t *db, dns_dbversion_t *ver,
			dns_dbnode_t *node, dns_name_t *name, isc_mem_t *mctx,
			unsigned int maxkeys, dst_key_t **keys,
			unsigned int *nkeys)
{
	dns_rdataset_t rdataset;
	dns_rdata_t rdata;
	isc_result_t result;
	dst_key_t *pubkey = NULL;
	unsigned int count = 0;

	*nkeys = 0;
	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(db, node, ver, dns_rdatatype_key, 0, 0,
				     &rdataset, NULL);
	if (result == ISC_R_NOTFOUND)
		goto failure;
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
		if (result == DST_R_INVALIDPRIVATEKEY)
			count--;
		else {
			check_result(result, "dst_key_fromfile()");
			if (dst_key_flags(keys[count - 1]) & DNS_KEYTYPE_NOAUTH)
			{
				dst_key_free(keys[count - 1]);
				keys[count - 1] = NULL;
				count--;
			}
		}
 next:
		dst_key_free(pubkey);
		pubkey = NULL;
		result = dns_rdataset_next(&rdataset);
	}
	if (result != DNS_R_NOMORE)
		check_result(result, "iteration over zone keys");
	if (count == 0)
		result = ISC_R_NOTFOUND;
	else
		result = ISC_R_SUCCESS;

 failure:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (pubkey != NULL)
		dst_key_free(pubkey);
	*nkeys = count;
	return (result);
}

isc_result_t
dns_dnssec_signmessage(dns_message_t *msg, dst_key_t *key) {
	dns_rdata_generic_sig_t sig;
	unsigned char data[512];
	unsigned char header[DNS_MESSAGE_HEADERLEN];
	isc_buffer_t headerbuf, databuf, sigbuf;
	unsigned int sigsize;
	isc_buffer_t *dynbuf;
	dns_name_t *owner, signer;
	dns_rdata_t *rdata;
	dns_rdatalist_t *datalist;
	dns_rdataset_t *dataset;
	isc_region_t r;
	isc_stdtime_t now;
	dst_context_t ctx;
	isc_mem_t *mctx;
	isc_result_t result;
	isc_boolean_t signeedsfree = ISC_TRUE;

	REQUIRE(msg != NULL);
	REQUIRE(key != NULL);

	if (is_response(msg))
		REQUIRE(msg->query != NULL);

	mctx = msg->mctx;

	memset(&sig, 0, sizeof(dns_rdata_generic_sig_t));

	sig.mctx = mctx;
	sig.common.rdclass = dns_rdataclass_any;
	sig.common.rdtype = dns_rdatatype_sig;
	ISC_LINK_INIT(&sig.common, link);

	sig.covered = 0;
	sig.algorithm = dst_key_alg(key);
	sig.labels = 1; /* the root name */
	sig.originalttl = 0;

	isc_stdtime_get(&now);
	sig.timesigned = now - DNS_TSIG_FUDGE;
	sig.timeexpire = now + DNS_TSIG_FUDGE;

	sig.keyid = dst_key_id(key);

	dns_name_init(&signer, NULL);
	RETERR(keyname_to_name(dst_key_name(key), mctx, &sig.signer));

	sig.siglen = 0;
	sig.signature = NULL;
	
	isc_buffer_init(&databuf, data, sizeof(data), ISC_BUFFERTYPE_BINARY);

	RETERR(dst_sign(DST_SIGMODE_INIT, key, &ctx, NULL, NULL));

	if (is_response(msg))
		RETERR(dst_sign(DST_SIGMODE_UPDATE, key, &ctx, msg->query,
				NULL));

	/* Digest the header */
	isc_buffer_init(&headerbuf, header, sizeof(header),
			ISC_BUFFERTYPE_BINARY);
	dns_message_renderheader(msg, &headerbuf);
	isc_buffer_used(&headerbuf, &r);
	RETERR(dst_sign(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL));

	/* Digest the remainder of the message */
	isc_buffer_used(msg->buffer, &r);
	isc_region_consume(&r, DNS_MESSAGE_HEADERLEN);
	RETERR(dst_sign(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL));

	/*
	 * Digest the fields of the SIG - we can cheat and use
	 * dns_rdata_fromstruct.  Since siglen is 0, the digested data
	 * is identical to dns format with the last 2 bytes removed.
	 */
	RETERR(dns_rdata_fromstruct(NULL, dns_rdataclass_any,
				    dns_rdatatype_sig, &sig, &databuf));
	isc_buffer_used(&databuf, &r);
	r.length -= 2;
	RETERR(dst_sign(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL));

	RETERR(dst_sig_size(key, &sigsize));
	sig.siglen = sigsize;
	sig.signature = (unsigned char *) isc_mem_get(mctx, sig.siglen);
	if (sig.signature == NULL) {
		result = ISC_R_NOMEMORY;
		goto failure;
	}

	isc_buffer_init(&sigbuf, sig.signature, sig.siglen,
			ISC_BUFFERTYPE_BINARY);
	RETERR(dst_sign(DST_SIGMODE_FINAL, key, &ctx, NULL, &sigbuf));

	rdata = NULL;
	RETERR(dns_message_gettemprdata(msg, &rdata));
	dynbuf = NULL;
	RETERR(isc_buffer_allocate(msg->mctx, &dynbuf, 1024,
				   ISC_BUFFERTYPE_BINARY));
	RETERR(dns_rdata_fromstruct(rdata, dns_rdataclass_any,
				    dns_rdatatype_sig, &sig, dynbuf));

	dns_rdata_freestruct(&sig);
	signeedsfree = ISC_FALSE;

	dns_message_takebuffer(msg, &dynbuf);

	owner = NULL;
	RETERR(dns_message_gettempname(msg, &owner));
	dns_name_init(owner, NULL);
	dns_name_clone(dns_rootname, owner);

	datalist = NULL;
	RETERR(dns_message_gettemprdatalist(msg, &datalist));
	datalist->rdclass = dns_rdataclass_any;
	datalist->type = dns_rdatatype_sig;
	datalist->covers = 0;
	datalist->ttl = 0;
	ISC_LIST_INIT(datalist->rdata);
	ISC_LIST_APPEND(datalist->rdata, rdata, link);
	dataset = NULL;
	RETERR(dns_message_gettemprdataset(msg, &dataset));
	dns_rdataset_init(dataset);
	dns_rdatalist_tordataset(datalist, dataset);
	ISC_LIST_APPEND(owner->list, dataset, link);
	dns_message_addname(msg, owner, DNS_SECTION_SIG0);

	return (ISC_R_SUCCESS);

failure:
	if (dynbuf != NULL)
		isc_buffer_free(&dynbuf);
	if (signeedsfree)
		dns_rdata_freestruct(&sig);

	return (result);
}

isc_result_t
dns_dnssec_verifymessage(dns_message_t *msg, dst_key_t *key) {
	dns_rdata_generic_sig_t sig;
	unsigned char header[DNS_MESSAGE_HEADERLEN];
	dns_rdata_t rdata;
	dns_rdataset_t *dataset;
	dns_name_t tname, *sig0name;
	isc_region_t r, r2, sig_r, header_r;
	isc_stdtime_t now;
	dst_context_t ctx;
	isc_mem_t *mctx;
	isc_result_t result;
	isc_uint16_t addcount;
	isc_boolean_t signeedsfree = ISC_FALSE;

	REQUIRE(msg != NULL);
	REQUIRE(msg->saved != NULL);
	REQUIRE(key != NULL);

	if (is_response(msg))
		REQUIRE(msg->query != NULL);

	mctx = msg->mctx;

	result = dns_message_firstname(msg, DNS_SECTION_SIG0);
	if (result != ISC_R_SUCCESS) {
		result = ISC_R_NOTFOUND;
		goto failure;
	}
	sig0name = NULL;
	dns_message_currentname(msg, DNS_SECTION_SIG0, &sig0name);
	dataset = NULL;
	result = dns_message_findtype(sig0name, dns_rdatatype_sig, 0, &dataset);
	if (result != ISC_R_SUCCESS)
		goto failure;

	RETERR(dns_rdataset_first(dataset));
	dns_rdataset_current(dataset, &rdata);

	RETERR(dns_rdata_tostruct(&rdata, &sig, mctx));
	signeedsfree = ISC_TRUE;

	isc_stdtime_get(&now);
	if (sig.timesigned > now) {
		result = DNS_R_SIGFUTURE;
		msg->sig0status = dns_tsigerror_badtime;
		goto failure;
	}
	else if (sig.timeexpire < now) {
		result = DNS_R_SIGEXPIRED;
		msg->sig0status = dns_tsigerror_badtime;
		goto failure;
	}

	/* ensure that sig.signer refers to this key :) */

	RETERR(dst_verify(DST_SIGMODE_INIT, key, &ctx, NULL, NULL));

	/* if this is a response, digest the query */
	if (is_response(msg))
		RETERR(dst_verify(DST_SIGMODE_UPDATE, key, &ctx, msg->query,
				  NULL));

	/* Extract the header */
	memcpy(header, msg->saved->base, DNS_MESSAGE_HEADERLEN);

	/* Decrement the additional field counter */
	memcpy(&addcount, &header[DNS_MESSAGE_HEADERLEN - 2], 2);
	addcount = htons(ntohs(addcount) - 1);
	memcpy(&header[DNS_MESSAGE_HEADERLEN - 2], &addcount, 2);

	/* Digest the modified header */
	header_r.base = (unsigned char *) header;
	header_r.length = DNS_MESSAGE_HEADERLEN;
	RETERR(dst_verify(DST_SIGMODE_UPDATE, key, &ctx, &header_r, NULL));

	/* Digest all non-SIG(0) records */
	r.base = msg->saved->base + DNS_MESSAGE_HEADERLEN;
	r.length = msg->sigstart - DNS_MESSAGE_HEADERLEN;
	RETERR(dst_verify(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL));

	/*
 	 * Digest the SIG(0) record .  Find the start of the record, skip
	 * the name and 10 bytes for class, type, ttl, length to get to
	 * the start of the rdata.
	 */
	r.base = msg->saved->base + msg->sigstart;
	r.length = msg->saved->length - msg->sigstart;
	dns_name_init(&tname, NULL);
	dns_name_fromregion(&tname, &r);
	dns_name_toregion(&tname, &r2);
	isc_region_consume(&r, r2.length + 10);
	r.length -= (sig.siglen + 2);
	RETERR(dst_verify(DST_SIGMODE_UPDATE, key, &ctx, &r, NULL));

	sig_r.base = sig.signature;
	sig_r.length = sig.siglen;
	result = dst_verify(DST_SIGMODE_FINAL, key, &ctx, NULL, &sig_r);
	if (result != ISC_R_SUCCESS) {
		msg->sig0status = dns_tsigerror_badsig;
		goto failure;
	}

	msg->verified_sig = 1;

	dns_rdata_freestruct(&sig);

	return (ISC_R_SUCCESS);

failure:
	if (signeedsfree)
		dns_rdata_freestruct(&sig);

	msg->verify_attempted = 1;

	return (result);
}
