/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#if HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#endif

#include <isc/buffer.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/nonce.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>
#include <dns/tkey.h>
#include <dns/tsig.h>

#include <dst/dst.h>
#include <dst/gssapi.h>

#include "dst_internal.h"

#define TEMP_BUFFER_SZ	   8192
#define TKEY_RANDOM_AMOUNT 16

#define RETERR(x)                            \
	do {                                 \
		result = (x);                \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

static void
tkey_log(const char *fmt, ...) ISC_FORMAT_PRINTF(1, 2);

static void
tkey_log(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_REQUEST,
		       ISC_LOG_DEBUG(4), fmt, ap);
	va_end(ap);
}

isc_result_t
dns_tkeyctx_create(isc_mem_t *mctx, dns_tkeyctx_t **tctxp) {
	REQUIRE(mctx != NULL);
	REQUIRE(tctxp != NULL && *tctxp == NULL);

	dns_tkeyctx_t *tctx = isc_mem_get(mctx, sizeof(*tctx));
	*tctx = (dns_tkeyctx_t){
		.mctx = NULL,
	};
	isc_mem_attach(mctx, &tctx->mctx);

	*tctxp = tctx;
	return (ISC_R_SUCCESS);
}

void
dns_tkeyctx_destroy(dns_tkeyctx_t **tctxp) {
	isc_mem_t *mctx;
	dns_tkeyctx_t *tctx;

	REQUIRE(tctxp != NULL && *tctxp != NULL);

	tctx = *tctxp;
	*tctxp = NULL;
	mctx = tctx->mctx;

	if (tctx->domain != NULL) {
		if (dns_name_dynamic(tctx->domain)) {
			dns_name_free(tctx->domain, mctx);
		}
		isc_mem_put(mctx, tctx->domain, sizeof(dns_name_t));
	}
	if (tctx->gssapi_keytab != NULL) {
		isc_mem_free(mctx, tctx->gssapi_keytab);
	}
	if (tctx->gsscred != NULL) {
		dst_gssapi_releasecred(&tctx->gsscred);
	}
	isc_mem_putanddetach(&mctx, tctx, sizeof(dns_tkeyctx_t));
}

static void
add_rdata_to_list(dns_message_t *msg, dns_name_t *name, dns_rdata_t *rdata,
		  uint32_t ttl, dns_namelist_t *namelist) {
	isc_region_t r, newr;
	dns_rdata_t *newrdata = NULL;
	dns_name_t *newname = NULL;
	dns_rdatalist_t *newlist = NULL;
	dns_rdataset_t *newset = NULL;
	isc_buffer_t *tmprdatabuf = NULL;

	dns_message_gettemprdata(msg, &newrdata);

	dns_rdata_toregion(rdata, &r);
	isc_buffer_allocate(msg->mctx, &tmprdatabuf, r.length);
	isc_buffer_availableregion(tmprdatabuf, &newr);
	memmove(newr.base, r.base, r.length);
	dns_rdata_fromregion(newrdata, rdata->rdclass, rdata->type, &newr);
	dns_message_takebuffer(msg, &tmprdatabuf);

	dns_message_gettempname(msg, &newname);
	dns_name_copy(name, newname);

	dns_message_gettemprdatalist(msg, &newlist);
	newlist->rdclass = newrdata->rdclass;
	newlist->type = newrdata->type;
	newlist->ttl = ttl;
	ISC_LIST_APPEND(newlist->rdata, newrdata, link);

	dns_message_gettemprdataset(msg, &newset);
	dns_rdatalist_tordataset(newlist, newset);

	ISC_LIST_INIT(newname->list);
	ISC_LIST_APPEND(newname->list, newset, link);

	ISC_LIST_APPEND(*namelist, newname, link);
}

static void
free_namelist(dns_message_t *msg, dns_namelist_t *namelist) {
	dns_name_t *name;
	dns_rdataset_t *set;

	while (!ISC_LIST_EMPTY(*namelist)) {
		name = ISC_LIST_HEAD(*namelist);
		ISC_LIST_UNLINK(*namelist, name, link);
		while (!ISC_LIST_EMPTY(name->list)) {
			set = ISC_LIST_HEAD(name->list);
			ISC_LIST_UNLINK(name->list, set, link);
			if (dns_rdataset_isassociated(set)) {
				dns_rdataset_disassociate(set);
			}
			dns_message_puttemprdataset(msg, &set);
		}
		dns_message_puttempname(msg, &name);
	}
}

static isc_result_t
process_gsstkey(dns_message_t *msg, dns_name_t *name, dns_rdata_tkey_t *tkeyin,
		dns_tkeyctx_t *tctx, dns_rdata_tkey_t *tkeyout,
		dns_tsig_keyring_t *ring) {
	isc_result_t result = ISC_R_SUCCESS;
	dst_key_t *dstkey = NULL;
	dns_tsigkey_t *tsigkey = NULL;
	dns_fixedname_t fixed;
	dns_name_t *principal;
	isc_stdtime_t now;
	isc_region_t intoken;
	isc_buffer_t *outtoken = NULL;
	dns_gss_ctx_id_t gss_ctx = NULL;

	/*
	 * You have to define either a gss credential (principal) to
	 * accept with tkey-gssapi-credential, or you have to
	 * configure a specific keytab (with tkey-gssapi-keytab) in
	 * order to use gsstkey.
	 */
	if (tctx->gsscred == NULL && tctx->gssapi_keytab == NULL) {
		tkey_log("process_gsstkey(): no tkey-gssapi-credential "
			 "or tkey-gssapi-keytab configured");
		return (ISC_R_NOPERM);
	}

	if (!dns_name_equal(&tkeyin->algorithm, DNS_TSIG_GSSAPI_NAME) &&
	    !dns_name_equal(&tkeyin->algorithm, DNS_TSIG_GSSAPIMS_NAME))
	{
		tkeyout->error = dns_tsigerror_badalg;
		tkey_log("process_gsstkey(): dns_tsigerror_badalg"); /* XXXSRA
								      */
		return (ISC_R_SUCCESS);
	}

	/*
	 * XXXDCL need to check for key expiry per 4.1.1
	 * XXXDCL need a way to check fully established, perhaps w/key_flags
	 */

	intoken.base = tkeyin->key;
	intoken.length = tkeyin->keylen;

	result = dns_tsigkey_find(&tsigkey, name, &tkeyin->algorithm, ring);
	if (result == ISC_R_SUCCESS) {
		gss_ctx = dst_key_getgssctx(tsigkey->key);
	}

	principal = dns_fixedname_initname(&fixed);

	/*
	 * Note that tctx->gsscred may be NULL if tctx->gssapi_keytab is set
	 */
	result = dst_gssapi_acceptctx(tctx->gsscred, tctx->gssapi_keytab,
				      &intoken, &outtoken, &gss_ctx, principal,
				      tctx->mctx);
	if (result == DNS_R_INVALIDTKEY) {
		if (tsigkey != NULL) {
			dns_tsigkey_detach(&tsigkey);
		}
		tkeyout->error = dns_tsigerror_badkey;
		tkey_log("process_gsstkey(): dns_tsigerror_badkey"); /* XXXSRA
								      */
		return (ISC_R_SUCCESS);
	}
	if (result != DNS_R_CONTINUE && result != ISC_R_SUCCESS) {
		goto failure;
	}
	/*
	 * XXXDCL Section 4.1.3: Limit GSS_S_CONTINUE_NEEDED to 10 times.
	 */

	isc_stdtime_get(&now);

	if (dns_name_countlabels(principal) == 0U) {
		if (tsigkey != NULL) {
			dns_tsigkey_detach(&tsigkey);
		}
	} else if (tsigkey == NULL) {
#if HAVE_GSSAPI
		OM_uint32 gret, minor, lifetime;
#endif /* HAVE_GSSAPI */
		uint32_t expire;

		RETERR(dst_key_fromgssapi(name, gss_ctx, ring->mctx, &dstkey,
					  &intoken));
		/*
		 * Limit keys to 1 hour or the context's lifetime whichever
		 * is smaller.
		 */
		expire = now + 3600;
#if HAVE_GSSAPI
		gret = gss_context_time(&minor, gss_ctx, &lifetime);
		if (gret == GSS_S_COMPLETE && now + lifetime < expire) {
			expire = now + lifetime;
		}
#endif /* HAVE_GSSAPI */
		RETERR(dns_tsigkey_createfromkey(
			name, &tkeyin->algorithm, dstkey, true, false,
			principal, now, expire, ring->mctx, ring, &tsigkey));
		dst_key_free(&dstkey);
		tkeyout->inception = now;
		tkeyout->expire = expire;
	} else {
		tkeyout->inception = tsigkey->inception;
		tkeyout->expire = tsigkey->expire;
	}

	if (outtoken) {
		tkeyout->key = isc_mem_get(tkeyout->mctx,
					   isc_buffer_usedlength(outtoken));
		tkeyout->keylen = isc_buffer_usedlength(outtoken);
		memmove(tkeyout->key, isc_buffer_base(outtoken),
			isc_buffer_usedlength(outtoken));
		isc_buffer_free(&outtoken);
	} else {
		tkeyout->key = isc_mem_get(tkeyout->mctx, tkeyin->keylen);
		tkeyout->keylen = tkeyin->keylen;
		memmove(tkeyout->key, tkeyin->key, tkeyin->keylen);
	}

	tkeyout->error = dns_rcode_noerror;

	tkey_log("process_gsstkey(): dns_tsigerror_noerror"); /* XXXSRA */

	/*
	 * We found a TKEY to respond with.  If the request is not TSIG signed,
	 * we need to make sure the response is signed (see RFC 3645, Section
	 * 2.2).
	 */
	if (tsigkey != NULL) {
		if (msg->tsigkey == NULL && msg->sig0key == NULL) {
			dns_message_settsigkey(msg, tsigkey);
		}
		dns_tsigkey_detach(&tsigkey);
	}

	return (ISC_R_SUCCESS);

failure:
	if (tsigkey != NULL) {
		dns_tsigkey_detach(&tsigkey);
	}

	if (dstkey != NULL) {
		dst_key_free(&dstkey);
	}

	if (outtoken != NULL) {
		isc_buffer_free(&outtoken);
	}

	tkey_log("process_gsstkey(): %s", isc_result_totext(result)); /* XXXSRA
								       */

	return (result);
}

static isc_result_t
process_deletetkey(dns_name_t *signer, dns_name_t *name,
		   dns_rdata_tkey_t *tkeyin, dns_rdata_tkey_t *tkeyout,
		   dns_tsig_keyring_t *ring) {
	isc_result_t result;
	dns_tsigkey_t *tsigkey = NULL;
	const dns_name_t *identity;

	result = dns_tsigkey_find(&tsigkey, name, &tkeyin->algorithm, ring);
	if (result != ISC_R_SUCCESS) {
		tkeyout->error = dns_tsigerror_badname;
		return (ISC_R_SUCCESS);
	}

	/*
	 * Only allow a delete if the identity that created the key is the
	 * same as the identity that signed the message.
	 */
	identity = dns_tsigkey_identity(tsigkey);
	if (identity == NULL || !dns_name_equal(identity, signer)) {
		dns_tsigkey_detach(&tsigkey);
		return (DNS_R_REFUSED);
	}

	/*
	 * Set the key to be deleted when no references are left.  If the key
	 * was not generated with TKEY and is in the config file, it may be
	 * reloaded later.
	 */
	dns_tsigkey_setdeleted(tsigkey);

	/* Release the reference */
	dns_tsigkey_detach(&tsigkey);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_tkey_processquery(dns_message_t *msg, dns_tkeyctx_t *tctx,
		      dns_tsig_keyring_t *ring) {
	isc_result_t result = ISC_R_SUCCESS;
	dns_rdata_tkey_t tkeyin, tkeyout;
	bool freetkeyin = false;
	dns_name_t *qname, *name, *keyname, *signer, tsigner;
	dns_fixedname_t fkeyname;
	dns_rdataset_t *tkeyset;
	dns_rdata_t rdata;
	dns_namelist_t namelist;
	char tkeyoutdata[512];
	isc_buffer_t tkeyoutbuf;

	REQUIRE(msg != NULL);
	REQUIRE(tctx != NULL);
	REQUIRE(ring != NULL);

	ISC_LIST_INIT(namelist);

	/*
	 * Interpret the question section.
	 */
	result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
	if (result != ISC_R_SUCCESS) {
		return (DNS_R_FORMERR);
	}

	qname = NULL;
	dns_message_currentname(msg, DNS_SECTION_QUESTION, &qname);

	/*
	 * Look for a TKEY record that matches the question.
	 */
	tkeyset = NULL;
	name = NULL;
	result = dns_message_findname(msg, DNS_SECTION_ADDITIONAL, qname,
				      dns_rdatatype_tkey, 0, &name, &tkeyset);
	if (result != ISC_R_SUCCESS) {
		/*
		 * Try the answer section, since that's where Win2000
		 * puts it.
		 */
		name = NULL;
		if (dns_message_findname(msg, DNS_SECTION_ANSWER, qname,
					 dns_rdatatype_tkey, 0, &name,
					 &tkeyset) != ISC_R_SUCCESS)
		{
			result = DNS_R_FORMERR;
			tkey_log("dns_tkey_processquery: couldn't find a TKEY "
				 "matching the question");
			goto failure;
		}
	}
	result = dns_rdataset_first(tkeyset);
	if (result != ISC_R_SUCCESS) {
		result = DNS_R_FORMERR;
		goto failure;
	}
	dns_rdata_init(&rdata);
	dns_rdataset_current(tkeyset, &rdata);

	RETERR(dns_rdata_tostruct(&rdata, &tkeyin, NULL));
	freetkeyin = true;

	if (tkeyin.error != dns_rcode_noerror) {
		result = DNS_R_FORMERR;
		goto failure;
	}

	/*
	 * Before we go any farther, verify that the message was signed.
	 * GSSAPI TKEY doesn't require a signature, the rest do.
	 */
	dns_name_init(&tsigner, NULL);
	result = dns_message_signer(msg, &tsigner);
	if (result != ISC_R_SUCCESS) {
		if (tkeyin.mode == DNS_TKEYMODE_GSSAPI &&
		    result == ISC_R_NOTFOUND)
		{
			signer = NULL;
		} else {
			tkey_log("dns_tkey_processquery: query was not "
				 "properly signed - rejecting");
			result = DNS_R_FORMERR;
			goto failure;
		}
	} else {
		signer = &tsigner;
	}

	tkeyout.common.rdclass = tkeyin.common.rdclass;
	tkeyout.common.rdtype = tkeyin.common.rdtype;
	ISC_LINK_INIT(&tkeyout.common, link);
	tkeyout.mctx = msg->mctx;

	dns_name_init(&tkeyout.algorithm, NULL);
	dns_name_clone(&tkeyin.algorithm, &tkeyout.algorithm);

	tkeyout.inception = tkeyout.expire = 0;
	tkeyout.mode = tkeyin.mode;
	tkeyout.error = 0;
	tkeyout.keylen = tkeyout.otherlen = 0;
	tkeyout.key = tkeyout.other = NULL;

	/*
	 * A delete operation must have a fully specified key name.  If this
	 * is not a delete, we do the following:
	 * if (qname != ".")
	 *	keyname = qname + defaultdomain
	 * else
	 *	keyname = <random hex> + defaultdomain
	 */
	if (tkeyin.mode != DNS_TKEYMODE_DELETE) {
		dns_tsigkey_t *tsigkey = NULL;

		if (tctx->domain == NULL && tkeyin.mode != DNS_TKEYMODE_GSSAPI)
		{
			tkey_log("dns_tkey_processquery: tkey-domain not set");
			result = DNS_R_REFUSED;
			goto failure;
		}

		keyname = dns_fixedname_initname(&fkeyname);

		if (!dns_name_equal(qname, dns_rootname)) {
			unsigned int n = dns_name_countlabels(qname);
			dns_name_copy(qname, keyname);
			dns_name_getlabelsequence(keyname, 0, n - 1, keyname);
		} else {
			static char hexdigits[16] = { '0', '1', '2', '3',
						      '4', '5', '6', '7',
						      '8', '9', 'A', 'B',
						      'C', 'D', 'E', 'F' };
			unsigned char randomdata[16];
			char randomtext[32];
			isc_buffer_t b;
			unsigned int i, j;

			isc_nonce_buf(randomdata, sizeof(randomdata));

			for (i = 0, j = 0; i < sizeof(randomdata); i++) {
				unsigned char val = randomdata[i];
				randomtext[j++] = hexdigits[val >> 4];
				randomtext[j++] = hexdigits[val & 0xF];
			}
			isc_buffer_init(&b, randomtext, sizeof(randomtext));
			isc_buffer_add(&b, sizeof(randomtext));
			result = dns_name_fromtext(keyname, &b, NULL, 0, NULL);
			if (result != ISC_R_SUCCESS) {
				goto failure;
			}
		}

		if (tkeyin.mode == DNS_TKEYMODE_GSSAPI) {
			/* Yup.  This is a hack */
			result = dns_name_concatenate(keyname, dns_rootname,
						      keyname, NULL);
			if (result != ISC_R_SUCCESS) {
				goto failure;
			}
		} else {
			result = dns_name_concatenate(keyname, tctx->domain,
						      keyname, NULL);
			if (result != ISC_R_SUCCESS) {
				goto failure;
			}
		}

		result = dns_tsigkey_find(&tsigkey, keyname, NULL, ring);

		if (result == ISC_R_SUCCESS) {
			tkeyout.error = dns_tsigerror_badname;
			dns_tsigkey_detach(&tsigkey);
			goto failure_with_tkey;
		} else if (result != ISC_R_NOTFOUND) {
			goto failure;
		}
	} else {
		keyname = qname;
	}

	switch (tkeyin.mode) {
	case DNS_TKEYMODE_GSSAPI:
		tkeyout.error = dns_rcode_noerror;
		RETERR(process_gsstkey(msg, keyname, &tkeyin, tctx, &tkeyout,
				       ring));
		break;
	case DNS_TKEYMODE_DELETE:
		tkeyout.error = dns_rcode_noerror;
		RETERR(process_deletetkey(signer, keyname, &tkeyin, &tkeyout,
					  ring));
		break;
	case DNS_TKEYMODE_SERVERASSIGNED:
	case DNS_TKEYMODE_RESOLVERASSIGNED:
		result = DNS_R_NOTIMP;
		goto failure;
	default:
		tkeyout.error = dns_tsigerror_badmode;
	}

failure_with_tkey:

	dns_rdata_init(&rdata);
	isc_buffer_init(&tkeyoutbuf, tkeyoutdata, sizeof(tkeyoutdata));
	result = dns_rdata_fromstruct(&rdata, tkeyout.common.rdclass,
				      tkeyout.common.rdtype, &tkeyout,
				      &tkeyoutbuf);

	if (freetkeyin) {
		dns_rdata_freestruct(&tkeyin);
		freetkeyin = false;
	}

	if (tkeyout.key != NULL) {
		isc_mem_put(tkeyout.mctx, tkeyout.key, tkeyout.keylen);
	}
	if (tkeyout.other != NULL) {
		isc_mem_put(tkeyout.mctx, tkeyout.other, tkeyout.otherlen);
	}
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	add_rdata_to_list(msg, keyname, &rdata, 0, &namelist);

	RETERR(dns_message_reply(msg, true));

	name = ISC_LIST_HEAD(namelist);
	while (name != NULL) {
		dns_name_t *next = ISC_LIST_NEXT(name, link);
		ISC_LIST_UNLINK(namelist, name, link);
		dns_message_addname(msg, name, DNS_SECTION_ANSWER);
		name = next;
	}

	return (ISC_R_SUCCESS);

failure:

	if (freetkeyin) {
		dns_rdata_freestruct(&tkeyin);
	}
	if (!ISC_LIST_EMPTY(namelist)) {
		free_namelist(msg, &namelist);
	}
	return (result);
}

static isc_result_t
buildquery(dns_message_t *msg, const dns_name_t *name, dns_rdata_tkey_t *tkey,
	   bool win2k) {
	dns_name_t *qname = NULL, *aname = NULL;
	dns_rdataset_t *question = NULL, *tkeyset = NULL;
	dns_rdatalist_t *tkeylist = NULL;
	dns_rdata_t *rdata = NULL;
	isc_buffer_t *dynbuf = NULL;
	isc_result_t result;
	unsigned int len;

	REQUIRE(msg != NULL);
	REQUIRE(name != NULL);
	REQUIRE(tkey != NULL);

	len = 16 + tkey->algorithm.length + tkey->keylen + tkey->otherlen;
	isc_buffer_allocate(msg->mctx, &dynbuf, len);
	dns_message_gettemprdata(msg, &rdata);
	result = dns_rdata_fromstruct(rdata, dns_rdataclass_any,
				      dns_rdatatype_tkey, tkey, dynbuf);
	if (result != ISC_R_SUCCESS) {
		dns_message_puttemprdata(msg, &rdata);
		isc_buffer_free(&dynbuf);
		return (result);
	}
	dns_message_takebuffer(msg, &dynbuf);

	dns_message_gettempname(msg, &qname);
	dns_message_gettempname(msg, &aname);

	dns_message_gettemprdataset(msg, &question);
	dns_rdataset_makequestion(question, dns_rdataclass_any,
				  dns_rdatatype_tkey);

	dns_message_gettemprdatalist(msg, &tkeylist);
	tkeylist->rdclass = dns_rdataclass_any;
	tkeylist->type = dns_rdatatype_tkey;
	ISC_LIST_APPEND(tkeylist->rdata, rdata, link);

	dns_message_gettemprdataset(msg, &tkeyset);
	dns_rdatalist_tordataset(tkeylist, tkeyset);

	dns_name_copy(name, qname);
	dns_name_copy(name, aname);

	ISC_LIST_APPEND(qname->list, question, link);
	ISC_LIST_APPEND(aname->list, tkeyset, link);

	dns_message_addname(msg, qname, DNS_SECTION_QUESTION);

	/*
	 * Windows 2000 needs this in the answer section, not the additional
	 * section where the RFC specifies.
	 */
	if (win2k) {
		dns_message_addname(msg, aname, DNS_SECTION_ANSWER);
	} else {
		dns_message_addname(msg, aname, DNS_SECTION_ADDITIONAL);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_tkey_buildgssquery(dns_message_t *msg, const dns_name_t *name,
		       const dns_name_t *gname, isc_buffer_t *intoken,
		       uint32_t lifetime, dns_gss_ctx_id_t *context, bool win2k,
		       isc_mem_t *mctx, char **err_message) {
	dns_rdata_tkey_t tkey;
	isc_result_t result;
	isc_stdtime_t now;
	isc_buffer_t token;
	unsigned char array[TEMP_BUFFER_SZ];

	UNUSED(intoken);

	REQUIRE(msg != NULL);
	REQUIRE(name != NULL);
	REQUIRE(gname != NULL);
	REQUIRE(context != NULL);
	REQUIRE(mctx != NULL);

	isc_buffer_init(&token, array, sizeof(array));
	result = dst_gssapi_initctx(gname, NULL, &token, context, mctx,
				    err_message);
	if (result != DNS_R_CONTINUE && result != ISC_R_SUCCESS) {
		return (result);
	}

	tkey.common.rdclass = dns_rdataclass_any;
	tkey.common.rdtype = dns_rdatatype_tkey;
	ISC_LINK_INIT(&tkey.common, link);
	tkey.mctx = NULL;
	dns_name_init(&tkey.algorithm, NULL);

	if (win2k) {
		dns_name_clone(DNS_TSIG_GSSAPIMS_NAME, &tkey.algorithm);
	} else {
		dns_name_clone(DNS_TSIG_GSSAPI_NAME, &tkey.algorithm);
	}

	isc_stdtime_get(&now);
	tkey.inception = now;
	tkey.expire = now + lifetime;
	tkey.mode = DNS_TKEYMODE_GSSAPI;
	tkey.error = 0;
	tkey.key = isc_buffer_base(&token);
	tkey.keylen = isc_buffer_usedlength(&token);
	tkey.other = NULL;
	tkey.otherlen = 0;

	return (buildquery(msg, name, &tkey, win2k));
}

static isc_result_t
find_tkey(dns_message_t *msg, dns_name_t **name, dns_rdata_t *rdata,
	  int section) {
	dns_rdataset_t *tkeyset;
	isc_result_t result;

	result = dns_message_firstname(msg, section);
	while (result == ISC_R_SUCCESS) {
		*name = NULL;
		dns_message_currentname(msg, section, name);
		tkeyset = NULL;
		result = dns_message_findtype(*name, dns_rdatatype_tkey, 0,
					      &tkeyset);
		if (result == ISC_R_SUCCESS) {
			result = dns_rdataset_first(tkeyset);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
			dns_rdataset_current(tkeyset, rdata);
			return (ISC_R_SUCCESS);
		}
		result = dns_message_nextname(msg, section);
	}
	if (result == ISC_R_NOMORE) {
		return (ISC_R_NOTFOUND);
	}
	return (result);
}

isc_result_t
dns_tkey_gssnegotiate(dns_message_t *qmsg, dns_message_t *rmsg,
		      const dns_name_t *server, dns_gss_ctx_id_t *context,
		      dns_tsigkey_t **outkey, dns_tsig_keyring_t *ring,
		      bool win2k, char **err_message) {
	dns_rdata_t rtkeyrdata = DNS_RDATA_INIT, qtkeyrdata = DNS_RDATA_INIT;
	dns_name_t *tkeyname;
	dns_rdata_tkey_t rtkey, qtkey, tkey;
	isc_buffer_t intoken, outtoken;
	dst_key_t *dstkey = NULL;
	isc_result_t result;
	unsigned char array[TEMP_BUFFER_SZ];
	bool freertkey = false;

	REQUIRE(qmsg != NULL);
	REQUIRE(rmsg != NULL);
	REQUIRE(server != NULL);
	if (outkey != NULL) {
		REQUIRE(*outkey == NULL);
	}

	if (rmsg->rcode != dns_rcode_noerror) {
		return (dns_result_fromrcode(rmsg->rcode));
	}

	RETERR(find_tkey(rmsg, &tkeyname, &rtkeyrdata, DNS_SECTION_ANSWER));
	RETERR(dns_rdata_tostruct(&rtkeyrdata, &rtkey, NULL));
	freertkey = true;

	if (win2k) {
		RETERR(find_tkey(qmsg, &tkeyname, &qtkeyrdata,
				 DNS_SECTION_ANSWER));
	} else {
		RETERR(find_tkey(qmsg, &tkeyname, &qtkeyrdata,
				 DNS_SECTION_ADDITIONAL));
	}

	RETERR(dns_rdata_tostruct(&qtkeyrdata, &qtkey, NULL));

	if (rtkey.error != dns_rcode_noerror ||
	    rtkey.mode != DNS_TKEYMODE_GSSAPI ||
	    !dns_name_equal(&rtkey.algorithm, &qtkey.algorithm))
	{
		tkey_log("dns_tkey_processdhresponse: tkey mode invalid "
			 "or error set(4)");
		result = DNS_R_INVALIDTKEY;
		goto failure;
	}

	isc_buffer_init(&intoken, rtkey.key, rtkey.keylen);
	isc_buffer_init(&outtoken, array, sizeof(array));

	result = dst_gssapi_initctx(server, &intoken, &outtoken, context,
				    ring->mctx, err_message);
	if (result != DNS_R_CONTINUE && result != ISC_R_SUCCESS) {
		return (result);
	}

	if (result == DNS_R_CONTINUE) {
		dns_fixedname_t fixed;

		dns_fixedname_init(&fixed);
		dns_name_copy(tkeyname, dns_fixedname_name(&fixed));
		tkeyname = dns_fixedname_name(&fixed);

		tkey.common.rdclass = dns_rdataclass_any;
		tkey.common.rdtype = dns_rdatatype_tkey;
		ISC_LINK_INIT(&tkey.common, link);
		tkey.mctx = NULL;
		dns_name_init(&tkey.algorithm, NULL);

		if (win2k) {
			dns_name_clone(DNS_TSIG_GSSAPIMS_NAME, &tkey.algorithm);
		} else {
			dns_name_clone(DNS_TSIG_GSSAPI_NAME, &tkey.algorithm);
		}

		tkey.inception = qtkey.inception;
		tkey.expire = qtkey.expire;
		tkey.mode = DNS_TKEYMODE_GSSAPI;
		tkey.error = 0;
		tkey.key = isc_buffer_base(&outtoken);
		tkey.keylen = isc_buffer_usedlength(&outtoken);
		tkey.other = NULL;
		tkey.otherlen = 0;

		dns_message_reset(qmsg, DNS_MESSAGE_INTENTRENDER);
		RETERR(buildquery(qmsg, tkeyname, &tkey, win2k));
		return (DNS_R_CONTINUE);
	}

	RETERR(dst_key_fromgssapi(dns_rootname, *context, rmsg->mctx, &dstkey,
				  NULL));

	/*
	 * XXXSRA This seems confused.  If we got CONTINUE from initctx,
	 * the GSS negotiation hasn't completed yet, so we can't sign
	 * anything yet.
	 */

	RETERR(dns_tsigkey_createfromkey(
		tkeyname,
		(win2k ? DNS_TSIG_GSSAPIMS_NAME : DNS_TSIG_GSSAPI_NAME), dstkey,
		true, false, NULL, rtkey.inception, rtkey.expire, ring->mctx,
		ring, outkey));
	dst_key_free(&dstkey);
	dns_rdata_freestruct(&rtkey);
	return (result);

failure:
	/*
	 * XXXSRA This probably leaks memory from qtkey.
	 */
	if (freertkey) {
		dns_rdata_freestruct(&rtkey);
	}
	if (dstkey != NULL) {
		dst_key_free(&dstkey);
	}
	return (result);
}
