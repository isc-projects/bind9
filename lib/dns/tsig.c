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
 * $Id: tsig.c,v 1.1 1999/08/20 18:56:23 bwelling Exp $
 * Principal Author: Brian Wellington
 */


#include <config.h>

#include <stdlib.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/list.h>
#include <isc/net.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/time.h>
#include <isc/types.h>

#include <dns/keyvalues.h>
#include <dns/name.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/tsig.h>

#include <dst/dst.h>
#include <dst/result.h>

#define TSIG_MAGIC		0x54534947	/* TSIG */
#define VALID_TSIG_KEY(x)	((x) != NULL && (x)->magic == TSIG_MAGIC)

/* XXXBEW If an unsorted list isn't good enough, this can be updated */
static ISC_LIST(dns_tsig_key_t) tsigkeys;
static isc_rwlock_t tsiglock;
static isc_mem_t *tsig_mctx = NULL;

dns_name_t *dns_tsig_hmacmd5_name = NULL;

#define is_response(msg) (msg->flags & DNS_MESSAGEFLAG_QR)

isc_result_t
dns_tsig_key_create(dns_name_t *name, dns_name_t *algorithm,
		    unsigned char *secret, int length,
		    isc_mem_t *mctx, dns_tsig_key_t **key)
{
	isc_buffer_t b, nameb;
	char namestr[1024];
	isc_uint16_t alg;
	dns_tsig_key_t *tkey;
	isc_result_t ret;

	REQUIRE(key != NULL);
	REQUIRE(*key == NULL);
	REQUIRE(name != NULL);
	REQUIRE(algorithm != NULL);
	REQUIRE(length >= 0);
	if (length > 0)
		REQUIRE(secret != NULL);
	REQUIRE(mctx != NULL);

	if (!dns_name_equal(algorithm, DNS_TSIG_HMACMD5_NAME))
		return (ISC_R_NOTFOUND);
	else
		alg = DST_ALG_HMAC_MD5;

	*key = (dns_tsig_key_t *) isc_mem_get(mctx, sizeof(dns_tsig_key_t));
	if (*key == NULL)
		return (ISC_R_NOMEMORY);
	tkey = *key;

	dns_name_init(&tkey->name, NULL);
	ret = dns_name_dup(name, mctx, &tkey->name);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_key;
	dns_name_downcase(&tkey->name);

	dns_name_init(&tkey->algorithm, NULL);
	ret = dns_name_dup(algorithm, mctx, &tkey->algorithm);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_name;
	dns_name_downcase(&tkey->algorithm);

	isc_buffer_init(&nameb, namestr, sizeof(namestr), ISC_BUFFERTYPE_TEXT);
	ret = dns_name_totext(name, ISC_FALSE, &nameb);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_algorithm;

	if (length > 0) {
		isc_buffer_init(&b, secret, length, ISC_BUFFERTYPE_BINARY);
		isc_buffer_add(&b, length);
		ret = dst_key_frombuffer(namestr, alg,
					 NS_KEY_NAME_ENTITY,
					 NS_KEY_PROT_DNSSEC,
					 &b, mctx, &tkey->key);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_algorithm;
	}
	else
		tkey->key = NULL;

	ISC_LINK_INIT(tkey, link);
	isc_rwlock_lock(&tsiglock, isc_rwlocktype_write);
	ISC_LIST_APPEND(tsigkeys, tkey, link);
	isc_rwlock_unlock(&tsiglock, isc_rwlocktype_write);
	tkey->mctx = mctx;
	tkey->magic = TSIG_MAGIC;
	return (ISC_R_SUCCESS);

cleanup_algorithm:
	dns_name_free(&tkey->algorithm, mctx);
cleanup_name:
	dns_name_free(&tkey->name, mctx);
cleanup_key:
	isc_mem_put(mctx, *key, sizeof(dns_tsig_key_t));

	return (ret);
}

/* Caller must be sure that this key is not in use. */
void
dns_tsig_key_free(dns_tsig_key_t **key) {
	dns_tsig_key_t *tkey;

	REQUIRE(key != NULL);
	REQUIRE(VALID_TSIG_KEY(*key));
	tkey = *key;

	tkey->magic = 0;
	isc_rwlock_lock(&tsiglock, isc_rwlocktype_write);
	ISC_LIST_UNLINK(tsigkeys, tkey, link);
	isc_rwlock_unlock(&tsiglock, isc_rwlocktype_write);
	dns_name_free(&tkey->name, tkey->mctx);
	dns_name_free(&tkey->algorithm, tkey->mctx);
	if (tkey->key != NULL)
		dst_key_free(tkey->key);
	isc_mem_put(tkey->mctx, tkey, sizeof(dns_tsig_key_t));
}

isc_result_t
dns_tsig_sign(dns_message_t *msg) {
	dns_tsig_key_t *key;
	dns_rdata_any_tsig_t *tsig;
	unsigned char data[128];
	isc_buffer_t databuf, sigbuf, rdatabuf;
	isc_dynbuffer_t *dynbuf;
	dns_name_t *owner;
	dns_rdata_t *rdata;
	dns_rdatalist_t *datalist;
	dns_rdataset_t *dataset;
	isc_region_t r;
	isc_time_t now;
	dst_context_t ctx;
	isc_mem_t *mctx;
	int tries;
	isc_result_t ret;

	REQUIRE(msg != NULL);
	if (msg->tsigkey != NULL)
		REQUIRE(VALID_TSIG_KEY(msg->tsigkey));
	REQUIRE(msg->tsig == NULL);
	if (is_response(msg))
		REQUIRE(msg->querytsig != NULL);

	mctx = msg->mctx;
	key = msg->tsigkey;

	tsig = (dns_rdata_any_tsig_t *)
		isc_mem_get(mctx, sizeof(dns_rdata_any_tsig_t));
	if (tsig == NULL)
		return (ISC_R_NOMEMORY);
	tsig->mctx = mctx;
	tsig->common.rdclass = dns_rdataclass_any;
	tsig->common.rdtype = dns_rdatatype_tsig;
	ISC_LINK_INIT(&tsig->common, link);
	tsig->algorithm = (dns_name_t *) isc_mem_get(mctx, sizeof(dns_name_t));
	if (tsig->algorithm == NULL) {
		ret = ISC_R_NOMEMORY;
		goto cleanup_struct;
	}
	dns_name_init(tsig->algorithm, NULL);
	ret = dns_name_dup(&key->algorithm, mctx, tsig->algorithm);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_struct;

	ret = isc_time_now(&now);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_algorithm;
	tsig->timesigned = now.seconds;
	tsig->fudge = DNS_TSIG_FUDGE;

	tsig->originalid = msg->id;

	isc_buffer_init(&databuf, data, sizeof(data), ISC_BUFFERTYPE_BINARY);

	if (!dns_tsig_emptykey(key)) {
		ret = dst_sign(DST_SIG_MODE_INIT, key->key, &ctx, NULL, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_algorithm;
	}

	if (is_response(msg)) {
		if (!dns_tsig_emptykey(key)) {
			isc_buffer_putuint16(&databuf, msg->querytsig->siglen);
			isc_buffer_available(&databuf, &r);
			if (r.length < msg->querytsig->siglen)
				return (ISC_R_NOSPACE);
			memcpy(r.base, msg->querytsig->signature,
			       msg->querytsig->siglen);
			isc_buffer_add(&databuf, msg->querytsig->siglen);
			isc_buffer_used(&databuf, &r);
			ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r,
					NULL);
			if (ret != ISC_R_SUCCESS)
				goto cleanup_algorithm;
		}
		tsig->error = msg->querytsigstatus;
	}
	else
		tsig->error = dns_rcode_noerror;

	if (tsig->error != dns_tsigerror_badtime) {
		tsig->otherlen = 0;
		tsig->other = NULL;
	}
	else {
		isc_buffer_t otherbuf;
		tsig->otherlen = 6;
		tsig->other = (unsigned char *) isc_mem_get(mctx, 6);
		if (tsig->other == NULL) {
			ret = ISC_R_NOMEMORY;
			goto cleanup_other;
		}
		isc_buffer_init(&otherbuf, tsig->other, tsig->otherlen = 6,
				ISC_BUFFERTYPE_BINARY);
		isc_buffer_putuint16(&otherbuf, tsig->timesigned >> 32);
		isc_buffer_putuint32(&otherbuf, tsig->timesigned & 0xFFFFFFFF);
		
	}
	if (!dns_tsig_emptykey(key)) {
		unsigned char header[DNS_MESSAGE_HEADERLEN];
		isc_buffer_t headerbuf;

		isc_buffer_init(&headerbuf, header, sizeof header,
				ISC_BUFFERTYPE_BINARY);
		dns_message_renderheader(msg, &headerbuf);
		isc_buffer_used(&headerbuf, &r);
		ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_other;
		isc_buffer_used(msg->buffer, &r);
		isc_region_consume(&r, DNS_MESSAGE_HEADERLEN);
		ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_other;

		/* Digest the name, class, ttl, alg */
		dns_name_toregion(&key->name, &r);
		ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_other;

		isc_buffer_clear(&databuf);
		isc_buffer_putuint16(&databuf, dns_rdataclass_any);
		isc_buffer_putuint32(&databuf, 0); /* ttl */
		isc_buffer_used(&databuf, &r);
		ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_other;
		
		dns_name_toregion(tsig->algorithm, &r);
		ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_other;

		isc_buffer_clear(&databuf);
		if (tsig->error != dns_tsigerror_badtime) {
			isc_buffer_putuint16(&databuf,
					     tsig->timesigned >> 32);
			isc_buffer_putuint32(&databuf,
					     tsig->timesigned & 0xFFFFFFFF);
		}
		else {
   			isc_uint64_t querysigned = msg->querytsig->timesigned;
			isc_buffer_putuint16(&databuf,
					     querysigned >> 32);
			isc_buffer_putuint32(&databuf,
					     querysigned & 0xFFFFFFFF);
		}
		isc_buffer_putuint16(&databuf, tsig->fudge);
		isc_buffer_putuint16(&databuf, tsig->error);
		isc_buffer_putuint16(&databuf, tsig->otherlen);

		isc_buffer_used(&databuf, &r);
		ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r, NULL);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_other;

		if (tsig->otherlen > 0) {
			r.length = tsig->otherlen;
			r.base = tsig->other;
			ret = dst_sign(DST_SIG_MODE_UPDATE, key->key, &ctx, &r,
				       NULL);
			if (ret != ISC_R_SUCCESS)
				goto cleanup_other;
		}

		tsig->siglen = dst_sig_size(key->key);
		tsig->signature = (unsigned char *)
				  isc_mem_get(mctx, tsig->siglen);
		if (tsig->signature == NULL) {
			ret = ISC_R_NOMEMORY;
			goto cleanup_other;
		}

		isc_buffer_init(&sigbuf, tsig->signature, tsig->siglen,
				ISC_BUFFERTYPE_BINARY);
		ret = dst_sign(DST_SIG_MODE_FINAL, key->key, &ctx, NULL,
			       &sigbuf);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_signature;
	}
	else {
		tsig->siglen = 0;
		tsig->signature = NULL;
	}

	/* There should be a better way of accessing msg->scratchpad */
	rdata = NULL;
	ret = dns_message_gettemprdata(msg, &rdata);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;
	tries = 0;
	dynbuf = ISC_LIST_TAIL(msg->scratchpad);
	INSIST(dynbuf != NULL);
	rdatabuf = dynbuf->buffer;
	while (tries < 2) {
		ret = dns_rdata_fromstruct(rdata, dns_rdataclass_any,
					   dns_rdatatype_tsig, tsig, &rdatabuf);
		if (ret == ISC_R_SUCCESS)
			break;
		else if (ret == ISC_R_NOSPACE) {
			if (++tries == 2)
				return (ISC_R_NOMEMORY);
			ret = isc_dynbuffer_allocate(msg->mctx, &dynbuf, 512,
						     ISC_BUFFERTYPE_BINARY);
			if (ret != ISC_R_SUCCESS)
				goto cleanup_signature;
			ISC_LIST_APPEND(msg->scratchpad, dynbuf, link);
			rdatabuf = dynbuf->buffer;
		}
		else
			goto cleanup_signature;
	}

	msg->tsig = tsig;

	owner = NULL;
	ret = dns_message_gettempname(msg, &owner);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;
	dns_name_init(owner, NULL);
	dns_name_clone(&key->name, owner);

	datalist = NULL;
	ret = dns_message_gettemprdatalist(msg, &datalist);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;
	datalist->rdclass = dns_rdataclass_any;
	datalist->type = dns_rdatatype_tsig;
	datalist->ttl = 0;
	ISC_LIST_INIT(datalist->rdata);
	ISC_LIST_APPEND(datalist->rdata, rdata, link);
	dataset = NULL;
	ret = dns_message_gettemprdataset(msg, &dataset);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_signature;
	dns_rdataset_init(dataset);
	dns_rdatalist_tordataset(datalist, dataset);
	ISC_LIST_APPEND(owner->list, dataset, link);
	dns_message_addname(msg, owner, DNS_SECTION_TSIG);

	return (ISC_R_SUCCESS);

cleanup_signature:
	if (tsig->signature != NULL)
		isc_mem_put(mctx, tsig->signature, tsig->siglen);
cleanup_other:
	if (tsig->other != NULL)
		isc_mem_put(mctx, tsig->other, tsig->otherlen);
cleanup_algorithm:
	dns_name_free(tsig->algorithm, mctx);
cleanup_struct:
	msg->tsig = NULL;
	isc_mem_put(mctx, tsig, sizeof(dns_rdata_any_tsig_t));

	return (ret);
}

isc_result_t
dns_tsig_verify(isc_buffer_t *source, dns_message_t *msg) {
	dns_rdata_any_tsig_t *tsig;
	isc_region_t r, source_r, header_r, sig_r;
	isc_buffer_t databuf;
	unsigned char data[32];
	dns_name_t *keyname;
	dns_rdataset_t *dataset;
	dns_rdata_t rdata;
	isc_time_t now;
	isc_result_t ret;
	dns_tsig_key_t *tsigkey = NULL;
	dst_key_t *key = NULL;
	unsigned char header[DNS_MESSAGE_HEADERLEN];
	dst_context_t ctx;
	isc_mem_t *mctx;
	isc_uint16_t addcount, id;

	REQUIRE(source != NULL);
	REQUIRE(msg != NULL);
	REQUIRE(msg->tsigkey != NULL);
	REQUIRE(msg->tsig == NULL);
	REQUIRE(!(ISC_LIST_EMPTY(msg->sections[DNS_SECTION_TSIG])));
	if (is_response(msg))
		REQUIRE(msg->querytsig != NULL);

	mctx = msg->mctx;

	/*
	 * If we're here, we know the message is well formed and contains a
	 * TSIG record.
	 */

	ret = dns_message_firstname(msg, DNS_SECTION_TSIG);
	if (ret != ISC_R_SUCCESS)
		return (ret);
	keyname = NULL;
	dns_message_currentname(msg, DNS_SECTION_TSIG, &keyname);
	dataset = ISC_LIST_HEAD(keyname->list);
	ret = dns_rdataset_first(dataset);
	if (ret != ISC_R_SUCCESS)
		return (ret);
	dns_rdataset_current(dataset, &rdata);
	tsig = (dns_rdata_any_tsig_t *)
		isc_mem_get(mctx, sizeof(dns_rdata_any_tsig_t));
	if (tsig == NULL)
		return (ISC_R_NOMEMORY);
	msg->tsig = tsig;
	ret = dns_rdata_tostruct(&rdata, tsig, mctx);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_emptystruct;
	
	isc_buffer_used(source, &r);
	memcpy(header, r.base, DNS_MESSAGE_HEADERLEN);
	isc_region_consume(&r, DNS_MESSAGE_HEADERLEN);

	/* Do the key name and algorithm match that of the query? */
	if (is_response(msg) &&
	    (!dns_name_equal(keyname, &msg->tsigkey->name) ||
	     !dns_name_equal(tsig->algorithm, msg->querytsig->algorithm)))
	{
		msg->tsigstatus = dns_tsigerror_badkey;
		return (DNS_R_TSIGVERIFYFAILURE);
	}

	/* Find dns_tsig_key_t based on keyname */
	ret = dns_tsig_findkey(&tsigkey, keyname, tsig->algorithm); 
	if (ret != ISC_R_SUCCESS) {
		msg->tsigstatus = dns_tsigerror_badkey;
		msg->tsigkey = NULL;
		/*
		 * this key must be deleted later - an empty key can be found
		 * by calling dns_tsig_emptykey()
		 */
		ret = dns_tsig_key_create(keyname, tsig->algorithm, NULL, 0,
					   mctx, &msg->tsigkey);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_struct;
		return (DNS_R_TSIGVERIFYFAILURE);
	}

	msg->tsigkey = tsigkey;
	key = tsigkey->key;

	/* Is the time ok? */
	ret = isc_time_now(&now);
	if (ret != ISC_R_SUCCESS)
		goto cleanup_key;
	if (abs(now.seconds - tsig->timesigned) > tsig->fudge) {
		msg->tsigstatus = dns_tsigerror_badtime;
		return (DNS_R_TSIGVERIFYFAILURE);
	}

	if (tsig->siglen > 0) {
		sig_r.base = tsig->signature;
		sig_r.length = tsig->siglen;

		ret = dst_verify(DST_SIG_MODE_INIT, key, &ctx, NULL, &sig_r);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_key;

		if (is_response(msg)) {
			isc_buffer_init(&databuf, data, sizeof(data),
					ISC_BUFFERTYPE_BINARY);
			isc_buffer_putuint16(&databuf, msg->querytsig->siglen);
			isc_buffer_used(&databuf, &r);
			ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r,
					 NULL);
			if (ret != ISC_R_SUCCESS)
				goto cleanup_key;
			if (msg->querytsig->siglen > 0) {
				r.length = msg->querytsig->siglen;
				r.base = msg->querytsig->signature;
				ret = dst_verify(DST_SIG_MODE_UPDATE, key,
						 &ctx, &r, NULL);
				if (ret != ISC_R_SUCCESS)
					goto cleanup_key;
			}
		}

		/* Decrement the additional field counter */
		memcpy(&addcount, &header[DNS_MESSAGE_HEADERLEN - 2], 2);
		addcount = htons(ntohs(addcount) - 1);
		memcpy(&header[DNS_MESSAGE_HEADERLEN - 2], &addcount, 2);

		/* Put in the original id */
		id = htons(tsig->originalid);
		memcpy(&header[0], &id, 2);

		/* Digest the modified header */
		header_r.base = (unsigned char *) header;
		header_r.length = DNS_MESSAGE_HEADERLEN;
		ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &header_r,
				 &sig_r);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_key;

		/* Digest all non-TSIG records. */
		isc_buffer_used(source, &source_r);
		r.base = source_r.base + DNS_MESSAGE_HEADERLEN;
		r.length = msg->tsigstart - DNS_MESSAGE_HEADERLEN;
		ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r, &sig_r);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_key;

		/* Digest the key name */
		dns_name_toregion(&tsigkey->name, &r);
		ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r, &sig_r);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_key;

		isc_buffer_init(&databuf, data, sizeof(data),
				ISC_BUFFERTYPE_BINARY);
		isc_buffer_putuint16(&databuf, tsig->common.rdclass);
		isc_buffer_putuint32(&databuf, dataset->ttl);
		isc_buffer_used(&databuf, &r);
		ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r, &sig_r);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_key;

		/* Digest the key algorithm */
		dns_name_toregion(&tsigkey->algorithm, &r);
		ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r, &sig_r);
		if (ret != ISC_R_SUCCESS)
			goto cleanup_key;

		isc_buffer_clear(&databuf);
		isc_buffer_putuint16(&databuf, tsig->timesigned >> 32);
		isc_buffer_putuint32(&databuf, tsig->timesigned & 0xFFFFFFFF);
		isc_buffer_putuint16(&databuf, tsig->fudge);
		isc_buffer_putuint16(&databuf, tsig->error);
		isc_buffer_putuint16(&databuf, tsig->otherlen);
		isc_buffer_used(&databuf, &r);
		ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r, &sig_r);

		if (tsig->otherlen > 0) {
			r.base = tsig->other;
			r.length = tsig->otherlen;
			ret = dst_verify(DST_SIG_MODE_UPDATE, key, &ctx, &r,
					 &sig_r);
			if (ret != ISC_R_SUCCESS)
				goto cleanup_key;
		}

		ret = dst_verify(DST_SIG_MODE_FINAL, key, &ctx, NULL, &sig_r);
		if (ret == DST_R_VERIFY_FINAL_FAILURE) {
			msg->tsigstatus = dns_tsigerror_badsig;
			return (DNS_R_TSIGVERIFYFAILURE);
		}
		else if (ret != ISC_R_SUCCESS)
			goto cleanup_key;
	}
	else if (tsig->error != dns_tsigerror_badsig &&
		 tsig->error != dns_tsigerror_badkey)
	{
		msg->tsigstatus = dns_tsigerror_badsig;
		return (DNS_R_TSIGVERIFYFAILURE);
	}

	msg->tsigstatus = dns_rcode_noerror;

	if (tsig->error != dns_rcode_noerror) {
		if (is_response(msg)) {
			/* XXXBEW Log a message */
			return (ISC_R_SUCCESS);
		}
		else
			return (DNS_R_TSIGERRORSET);
	}

	return (ISC_R_SUCCESS);

cleanup_key:
	if (dns_tsig_emptykey(msg->tsigkey)) {
		dns_tsig_key_free(&msg->tsigkey);
		msg->tsigkey = NULL;
	}
cleanup_struct:
	dns_rdata_freestruct(tsig);
cleanup_emptystruct:
	msg->tsig = NULL;
	isc_mem_put(mctx, tsig, sizeof(dns_rdata_any_tsig_t));
	return (ret);
}

isc_result_t
dns_tsig_findkey(dns_tsig_key_t **tsigkey, dns_name_t *name,
		 dns_name_t *algorithm)
{
	dns_tsig_key_t *key;

	REQUIRE(tsigkey != NULL);
	REQUIRE(name != NULL);
	REQUIRE(algorithm != NULL);

	isc_rwlock_lock(&tsiglock, isc_rwlocktype_read);
	key = ISC_LIST_HEAD(tsigkeys);
	while (key != NULL) {
		if (dns_name_equal(&key->name, name) &&
		    dns_name_equal(&key->algorithm, algorithm))
		{
			*tsigkey = key;
			isc_rwlock_unlock(&tsiglock, isc_rwlocktype_read);
			 return (ISC_R_SUCCESS);
		}
		key = ISC_LIST_NEXT(key, link);
	}
	isc_rwlock_unlock(&tsiglock, isc_rwlocktype_read);
	*tsigkey = NULL;
	return (ISC_R_NOTFOUND);
}

isc_result_t
dns_tsig_init(isc_mem_t *mctx) {
	isc_buffer_t hmacsrc, namebuf;
	isc_result_t ret;
	dns_name_t hmac_name;
	unsigned char data[32];

        ret = isc_rwlock_init(&tsiglock, 0, 0);
        if (ret != ISC_R_SUCCESS) {
                UNEXPECTED_ERROR(__FILE__, __LINE__,
                                 "isc_rwlock_init() failed: %s",
                                 isc_result_totext(ret));
                return (DNS_R_UNEXPECTED);
        }
	
	ISC_LIST_INIT(tsigkeys);
	isc_buffer_init(&hmacsrc, DNS_TSIG_HMACMD5,
			strlen(DNS_TSIG_HMACMD5), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&hmacsrc, strlen(DNS_TSIG_HMACMD5));
	isc_buffer_init(&namebuf, data, sizeof(data), ISC_BUFFERTYPE_BINARY);

	dns_name_init(&hmac_name, NULL);
	ret = dns_name_fromtext(&hmac_name, &hmacsrc, NULL, ISC_TRUE, &namebuf);
	if (ret != ISC_R_SUCCESS)
		return (ret);

	dns_tsig_hmacmd5_name = isc_mem_get(mctx, sizeof(dns_name_t));
	if (dns_tsig_hmacmd5_name == NULL)
		return (ISC_R_NOMEMORY);
	dns_name_init(dns_tsig_hmacmd5_name, NULL);
	ret = dns_name_dup(&hmac_name, mctx, dns_tsig_hmacmd5_name);
	if (ret != ISC_R_SUCCESS) {
		isc_mem_put(mctx, dns_tsig_hmacmd5_name, sizeof(dns_name_t));
		return (ret);
	}

	tsig_mctx = mctx;

	return (ISC_R_SUCCESS);
}

void
dns_tsig_destroy() {
	while (!ISC_LIST_EMPTY(tsigkeys)) {
		dns_tsig_key_t *key = ISC_LIST_HEAD(tsigkeys);
		dns_tsig_key_free(&key);
	}
	dns_name_free(dns_tsig_hmacmd5_name, tsig_mctx);
	isc_mem_put(tsig_mctx, dns_tsig_hmacmd5_name, sizeof(dns_name_t));
}
