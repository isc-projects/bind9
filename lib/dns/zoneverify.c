/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <stdarg.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/types.h>
#include <dns/zone.h>
#include <dns/zoneverify.h>

#include <isc/base32.h>
#include <isc/heap.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#define check_dns_dbiterator_current(result) \
	check_result((result == DNS_R_NEWORIGIN) ? ISC_R_SUCCESS : result, \
		     "dns_dbiterator_current()")

typedef struct vctx {
	isc_mem_t *		mctx;
	dns_zone_t *		zone;
	dns_db_t *		db;
	dns_dbversion_t *	ver;
	dns_name_t *		origin;
	dns_rdataset_t		keyset;
	dns_rdataset_t		keysigs;
	dns_rdataset_t		soaset;
	dns_rdataset_t		soasigs;
	dns_rdataset_t		nsecset;
	dns_rdataset_t		nsecsigs;
	dns_rdataset_t		nsec3paramset;
	dns_rdataset_t		nsec3paramsigs;
	unsigned char		revoked_ksk[256];
	unsigned char		revoked_zsk[256];
	unsigned char		standby_ksk[256];
	unsigned char		standby_zsk[256];
	unsigned char		ksk_algorithms[256];
	unsigned char		zsk_algorithms[256];
	unsigned char		bad_algorithms[256];
	unsigned char		act_algorithms[256];
	isc_heap_t *		expected_chains;
	isc_heap_t *		found_chains;
} vctx_t;

struct nsec3_chain_fixed {
	isc_uint8_t		hash;
	isc_uint8_t		salt_length;
	isc_uint8_t		next_length;
	isc_uint16_t		iterations;
};

static void
fatal(const char *format, ...) {
	va_list args;

	fprintf(stderr, "fatal: ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

/*%
 * Log a zone verification error described by 'fmt' and the variable arguments
 * following it.  Either use dns_zone_logv() or print to stderr, depending on
 * whether the function was invoked from within named or by a standalone tool,
 * respectively.
 */
static void
zoneverify_log_error(const vctx_t *vctx, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (vctx->zone != NULL) {
		dns_zone_logv(vctx->zone, DNS_LOGCATEGORY_GENERAL,
			      ISC_LOG_ERROR, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

/*%
 * If invoked from a standalone tool, print a message described by 'fmt' and
 * the variable arguments following it to stderr.
 */
static void
zoneverify_print(const vctx_t *vctx, const char *fmt, ...) {
	va_list ap;

	if (vctx->zone != NULL) {
		return;
	}

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
check_result(isc_result_t result, const char *message) {
	if (result != ISC_R_SUCCESS)
		fatal("%s: %s", message, isc_result_totext(result));
}

static void
type_format(const dns_rdatatype_t type, char *cp, unsigned int size) {
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;

	isc_buffer_init(&b, cp, size - 1);
	result = dns_rdatatype_totext(type, &b);
	check_result(result, "dns_rdatatype_totext()");
	isc_buffer_usedregion(&b, &r);
	r.base[r.length] = 0;
}

static isc_boolean_t
is_delegation(const vctx_t *vctx, dns_name_t *name, dns_dbnode_t *node,
	      isc_uint32_t *ttlp)
{
	dns_rdataset_t nsset;
	isc_result_t result;

	if (dns_name_equal(name, vctx->origin))
		return (ISC_FALSE);

	dns_rdataset_init(&nsset);
	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_ns, 0, 0, &nsset, NULL);
	if (dns_rdataset_isassociated(&nsset)) {
		if (ttlp != NULL)
			*ttlp = nsset.ttl;
		dns_rdataset_disassociate(&nsset);
	}

	return (ISC_TF(result == ISC_R_SUCCESS));
}

static isc_boolean_t
goodsig(const vctx_t *vctx, dns_rdata_t *sigrdata, dns_name_t *name,
	dns_rdataset_t *keyrdataset, dns_rdataset_t *rdataset)
{
	dns_rdata_dnskey_t key;
	dns_rdata_rrsig_t sig;
	dst_key_t *dstkey = NULL;
	isc_result_t result;

	result = dns_rdata_tostruct(sigrdata, &sig, NULL);
	check_result(result, "dns_rdata_tostruct()");

	for (result = dns_rdataset_first(keyrdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(keyrdataset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(keyrdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &key, NULL);
		check_result(result, "dns_rdata_tostruct()");
		result = dns_dnssec_keyfromrdata(vctx->origin, &rdata,
						 vctx->mctx, &dstkey);
		if (result != ISC_R_SUCCESS)
			return (ISC_FALSE);
		if (sig.algorithm != key.algorithm ||
		    sig.keyid != dst_key_id(dstkey) ||
		    !dns_name_equal(&sig.signer, vctx->origin)) {
			dst_key_free(&dstkey);
			continue;
		}
		result = dns_dnssec_verify(name, rdataset, dstkey, ISC_FALSE,
					   0, vctx->mctx, sigrdata, NULL);
		dst_key_free(&dstkey);
		if (result == ISC_R_SUCCESS || result == DNS_R_FROMWILDCARD) {
			return(ISC_TRUE);
		}
	}
	return (ISC_FALSE);
}

static isc_result_t
verifynsec(const vctx_t *vctx, dns_name_t *name, dns_dbnode_t *node,
	   dns_name_t *nextname)
{
	unsigned char buffer[DNS_NSEC_BUFFERSIZE];
	char namebuf[DNS_NAME_FORMATSIZE];
	char nextbuf[DNS_NAME_FORMATSIZE];
	char found[DNS_NAME_FORMATSIZE];
	dns_rdataset_t rdataset;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_t tmprdata = DNS_RDATA_INIT;
	dns_rdata_nsec_t nsec;
	isc_result_t result;

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_nsec, 0, 0, &rdataset,
				     NULL);
	if (result != ISC_R_SUCCESS) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		fprintf(stderr, "Missing NSEC record for %s\n", namebuf);
		goto failure;
	}

	result = dns_rdataset_first(&rdataset);
	check_result(result, "dns_rdataset_first()");

	dns_rdataset_current(&rdataset, &rdata);
	result = dns_rdata_tostruct(&rdata, &nsec, NULL);
	check_result(result, "dns_rdata_tostruct()");
	/* Check bit next name is consistent */
	if (!dns_name_equal(&nsec.next, nextname)) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		dns_name_format(nextname, nextbuf, sizeof(nextbuf));
		dns_name_format(&nsec.next, found, sizeof(found));
		fprintf(stderr, "Bad NSEC record for %s, next name "
				"mismatch (expected:%s, found:%s)\n", namebuf,
				nextbuf, found);
		goto failure;
	}
	/* Check bit map is consistent */
	result = dns_nsec_buildrdata(vctx->db, vctx->ver, node, nextname,
				     buffer, &tmprdata);
	check_result(result, "dns_nsec_buildrdata()");
	if (dns_rdata_compare(&rdata, &tmprdata) != 0) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		fprintf(stderr, "Bad NSEC record for %s, bit map "
				"mismatch\n", namebuf);
		goto failure;
	}
	result = dns_rdataset_next(&rdataset);
	if (result != ISC_R_NOMORE) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		fprintf(stderr, "Multipe NSEC records for %s\n", namebuf);
		goto failure;

	}
	dns_rdataset_disassociate(&rdataset);
	return (ISC_R_SUCCESS);
 failure:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	return (ISC_R_FAILURE);
}

static void
check_no_rrsig(const vctx_t *vctx, dns_rdataset_t *rdataset, dns_name_t *name,
	       dns_dbnode_t *node)
{
	char namebuf[DNS_NAME_FORMATSIZE];
	char typebuf[80];
	dns_rdataset_t sigrdataset;
	dns_rdatasetiter_t *rdsiter = NULL;
	isc_result_t result;

	dns_rdataset_init(&sigrdataset);
	result = dns_db_allrdatasets(vctx->db, node, vctx->ver, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	for (result = dns_rdatasetiter_first(rdsiter);
	     result == ISC_R_SUCCESS;
	     result = dns_rdatasetiter_next(rdsiter)) {
		dns_rdatasetiter_current(rdsiter, &sigrdataset);
		if (sigrdataset.type == dns_rdatatype_rrsig &&
		    sigrdataset.covers == rdataset->type)
			break;
		dns_rdataset_disassociate(&sigrdataset);
	}
	if (result == ISC_R_SUCCESS) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		type_format(rdataset->type, typebuf, sizeof(typebuf));
		fprintf(stderr, "Warning: Found unexpected signatures for "
			"%s/%s\n", namebuf, typebuf);
	}
	if (dns_rdataset_isassociated(&sigrdataset))
		dns_rdataset_disassociate(&sigrdataset);
	dns_rdatasetiter_destroy(&rdsiter);
}

static isc_boolean_t
chain_compare(void *arg1, void *arg2) {
	struct nsec3_chain_fixed *e1 = arg1, *e2 = arg2;
	size_t len;

	/*
	 * Do each element in turn to get a stable sort.
	 */
	if (e1->hash < e2->hash)
		return (ISC_TRUE);
	if (e1->hash > e2->hash)
		return (ISC_FALSE);
	if (e1->iterations < e2->iterations)
		return (ISC_TRUE);
	if (e1->iterations > e2->iterations)
		return (ISC_FALSE);
	if (e1->salt_length < e2->salt_length)
		return (ISC_TRUE);
	if (e1->salt_length > e2->salt_length)
		return (ISC_FALSE);
	if (e1->next_length < e2->next_length)
		return (ISC_TRUE);
	if (e1->next_length > e2->next_length)
		return (ISC_FALSE);
	len = e1->salt_length + 2 * e1->next_length;
	if (memcmp(e1 + 1, e2 + 1, len) < 0)
		return (ISC_TRUE);
	return (ISC_FALSE);
}

static isc_boolean_t
chain_equal(struct nsec3_chain_fixed *e1, struct nsec3_chain_fixed *e2) {
	size_t len;

	if (e1->hash != e2->hash)
		return (ISC_FALSE);
	if (e1->iterations != e2->iterations)
		return (ISC_FALSE);
	if (e1->salt_length != e2->salt_length)
		return (ISC_FALSE);
	if (e1->next_length != e2->next_length)
		return (ISC_FALSE);
	len = e1->salt_length + 2 * e1->next_length;
	if (memcmp(e1 + 1, e2 + 1, len) != 0)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

static isc_result_t
record_nsec3(const unsigned char *rawhash, const dns_rdata_nsec3_t *nsec3,
	     isc_mem_t *mctx, isc_heap_t *chains)
{
	struct nsec3_chain_fixed *element;
	size_t len;
	unsigned char *cp;
	isc_result_t result;

	len = sizeof(*element) + nsec3->next_length * 2 + nsec3->salt_length;

	element = isc_mem_get(mctx, len);
	if (element == NULL)
		return (ISC_R_NOMEMORY);
	memset(element, 0, len);
	element->hash = nsec3->hash;
	element->salt_length = nsec3->salt_length;
	element->next_length = nsec3->next_length;
	element->iterations = nsec3->iterations;
	cp = (unsigned char *)(element + 1);
	memmove(cp, nsec3->salt, nsec3->salt_length);
	cp += nsec3->salt_length;
	memmove(cp, rawhash, nsec3->next_length);
	cp += nsec3->next_length;
	memmove(cp, nsec3->next, nsec3->next_length);
	result = isc_heap_insert(chains, element);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "isc_heap_insert failed: %s\n",
			isc_result_totext(result));
		isc_mem_put(mctx, element, len);
	}
	return (result);
}

static isc_result_t
match_nsec3(const vctx_t *vctx, dns_name_t *name,
	    dns_rdata_nsec3param_t *nsec3param, dns_rdataset_t *rdataset,
	    unsigned char types[8192], unsigned int maxtype,
	    unsigned char *rawhash, size_t rhsize)
{
	unsigned char cbm[8244];
	char namebuf[DNS_NAME_FORMATSIZE];
	dns_rdata_nsec3_t nsec3;
	isc_result_t result;
	unsigned int len;

	/*
	 * Find matching NSEC3 record.
	 */
	for (result = dns_rdataset_first(rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(rdataset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(rdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &nsec3, NULL);
		check_result(result, "dns_rdata_tostruct()");
		if (nsec3.hash == nsec3param->hash &&
		    nsec3.next_length == rhsize &&
		    nsec3.iterations == nsec3param->iterations &&
		    nsec3.salt_length == nsec3param->salt_length &&
		    memcmp(nsec3.salt, nsec3param->salt,
			   nsec3param->salt_length) == 0)
			break;
	}
	if (result != ISC_R_SUCCESS) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		fprintf(stderr, "Missing NSEC3 record for %s\n", namebuf);
		return (result);
	}

	/*
	 * Check the type list.
	 */
	len = dns_nsec_compressbitmap(cbm, types, maxtype);
	if (nsec3.len != len || memcmp(cbm, nsec3.typebits, len) != 0) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		fprintf(stderr, "Bad NSEC3 record for %s, bit map "
				"mismatch\n", namebuf);
		return (ISC_R_FAILURE);
	}

	/*
	 * Record chain.
	 */
	result = record_nsec3(rawhash, &nsec3, vctx->mctx,
			      vctx->expected_chains);
	check_result(result, "record_nsec3()");

	/*
	 * Make sure there is only one NSEC3 record with this set of
	 * parameters.
	 */
	for (result = dns_rdataset_next(rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(rdataset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(rdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &nsec3, NULL);
		check_result(result, "dns_rdata_tostruct()");
		if (nsec3.hash == nsec3param->hash &&
		    nsec3.iterations == nsec3param->iterations &&
		    nsec3.salt_length == nsec3param->salt_length &&
		    memcmp(nsec3.salt, nsec3param->salt,
			   nsec3.salt_length) == 0) {
			dns_name_format(name, namebuf, sizeof(namebuf));
			fprintf(stderr, "Multiple NSEC3 records with the "
				"same parameter set for %s", namebuf);
			result = DNS_R_DUPLICATE;
			break;
		}
	}
	if (result != ISC_R_NOMORE)
		return (result);

	result = ISC_R_SUCCESS;
	return (result);
}

static isc_boolean_t
innsec3params(dns_rdata_nsec3_t *nsec3, dns_rdataset_t *nsec3paramset) {
	dns_rdata_nsec3param_t nsec3param;
	isc_result_t result;

	for (result = dns_rdataset_first(nsec3paramset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(nsec3paramset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;

		dns_rdataset_current(nsec3paramset, &rdata);
		result = dns_rdata_tostruct(&rdata, &nsec3param, NULL);
		check_result(result, "dns_rdata_tostruct()");
		if (nsec3param.flags == 0 &&
		    nsec3param.hash == nsec3->hash &&
		    nsec3param.iterations == nsec3->iterations &&
		    nsec3param.salt_length == nsec3->salt_length &&
		    memcmp(nsec3param.salt, nsec3->salt,
			   nsec3->salt_length) == 0)
			return (ISC_TRUE);
	}
	return (ISC_FALSE);
}

static isc_result_t
record_found(const vctx_t *vctx, dns_name_t *name, dns_dbnode_t *node,
	     dns_rdataset_t *nsec3paramset)
{
	unsigned char owner[NSEC3_MAX_HASH_LENGTH];
	dns_rdata_nsec3_t nsec3;
	dns_rdataset_t rdataset;
	dns_label_t hashlabel;
	isc_buffer_t b;
	isc_result_t result;

	if (nsec3paramset == NULL || !dns_rdataset_isassociated(nsec3paramset))
		return (ISC_R_SUCCESS);

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_nsec3, 0, 0, &rdataset,
				     NULL);
	if (result != ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);

	dns_name_getlabel(name, 0, &hashlabel);
	isc_region_consume(&hashlabel, 1);
	isc_buffer_init(&b, owner, sizeof(owner));
	result = isc_base32hex_decoderegion(&hashlabel, &b);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	for (result = dns_rdataset_first(&rdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(&rdataset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(&rdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &nsec3, NULL);
		check_result(result, "dns_rdata_tostruct()");
		if (nsec3.next_length != isc_buffer_usedlength(&b))
			continue;
		/*
		 * We only care about NSEC3 records that match a NSEC3PARAM
		 * record.
		 */
		if (!innsec3params(&nsec3, nsec3paramset))
			continue;

		/*
		 * Record chain.
		 */
		result = record_nsec3(owner, &nsec3, vctx->mctx,
				      vctx->found_chains);
		check_result(result, "record_nsec3()");
	}

 cleanup:
	dns_rdataset_disassociate(&rdataset);
	return (ISC_R_SUCCESS);
}

static isc_boolean_t
isoptout(const vctx_t *vctx, dns_rdata_t *nsec3rdata)
{
	dns_rdataset_t rdataset;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_nsec3_t nsec3;
	dns_rdata_nsec3param_t nsec3param;
	dns_fixedname_t fixed;
	dns_name_t *hashname;
	isc_result_t result;
	dns_dbnode_t *node = NULL;
	unsigned char rawhash[NSEC3_MAX_HASH_LENGTH];
	size_t rhsize = sizeof(rawhash);
	isc_boolean_t ret;

	result = dns_rdata_tostruct(nsec3rdata, &nsec3param, NULL);
	check_result(result, "dns_rdata_tostruct()");

	dns_fixedname_init(&fixed);
	result = dns_nsec3_hashname(&fixed, rawhash, &rhsize, vctx->origin,
				    vctx->origin, nsec3param.hash,
				    nsec3param.iterations, nsec3param.salt,
				    nsec3param.salt_length);
	check_result(result, "dns_nsec3_hashname()");

	dns_rdataset_init(&rdataset);
	hashname = dns_fixedname_name(&fixed);
	result = dns_db_findnsec3node(vctx->db, hashname, ISC_FALSE, &node);
	if (result == ISC_R_SUCCESS)
		result = dns_db_findrdataset(vctx->db, node, vctx->ver,
					     dns_rdatatype_nsec3, 0, 0,
					     &rdataset, NULL);
	if (result != ISC_R_SUCCESS)
		return (ISC_FALSE);

	result = dns_rdataset_first(&rdataset);
	check_result(result, "dns_rdataset_first()");

	dns_rdataset_current(&rdataset, &rdata);

	result = dns_rdata_tostruct(&rdata, &nsec3, NULL);
	if (result != ISC_R_SUCCESS)
		ret = ISC_FALSE;
	else
		ret = ISC_TF((nsec3.flags & DNS_NSEC3FLAG_OPTOUT) != 0);

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (node != NULL)
		dns_db_detachnode(vctx->db, &node);

	return (ret);
}

static isc_result_t
verifynsec3(const vctx_t *vctx, dns_name_t *name, dns_rdata_t *rdata,
	    isc_boolean_t delegation, isc_boolean_t empty,
	    unsigned char types[8192], unsigned int maxtype)
{
	char namebuf[DNS_NAME_FORMATSIZE];
	char hashbuf[DNS_NAME_FORMATSIZE];
	dns_rdataset_t rdataset;
	dns_rdata_nsec3param_t nsec3param;
	dns_fixedname_t fixed;
	dns_name_t *hashname;
	isc_result_t result;
	dns_dbnode_t *node = NULL;
	unsigned char rawhash[NSEC3_MAX_HASH_LENGTH];
	size_t rhsize = sizeof(rawhash);
	isc_boolean_t optout;

	result = dns_rdata_tostruct(rdata, &nsec3param, NULL);
	check_result(result, "dns_rdata_tostruct()");

	if (nsec3param.flags != 0)
		return (ISC_R_SUCCESS);

	if (!dns_nsec3_supportedhash(nsec3param.hash))
		return (ISC_R_SUCCESS);

	optout = isoptout(vctx, rdata);

	dns_fixedname_init(&fixed);
	result = dns_nsec3_hashname(&fixed, rawhash, &rhsize, name,
				    vctx->origin, nsec3param.hash,
				    nsec3param.iterations, nsec3param.salt,
				    nsec3param.salt_length);
	check_result(result, "dns_nsec3_hashname()");

	/*
	 * We don't use dns_db_find() here as it works with the choosen
	 * nsec3 chain and we may also be called with uncommitted data
	 * from dnssec-signzone so the secure status of the zone may not
	 * be up to date.
	 */
	dns_rdataset_init(&rdataset);
	hashname = dns_fixedname_name(&fixed);
	result = dns_db_findnsec3node(vctx->db, hashname, ISC_FALSE, &node);
	if (result == ISC_R_SUCCESS)
		result = dns_db_findrdataset(vctx->db, node, vctx->ver,
					     dns_rdatatype_nsec3, 0, 0,
					     &rdataset, NULL);
	if (result != ISC_R_SUCCESS &&
	    (!delegation || (empty && !optout) ||
	     (!empty && dns_nsec_isset(types, dns_rdatatype_ds))))
	{
		dns_name_format(name, namebuf, sizeof(namebuf));
		dns_name_format(hashname, hashbuf, sizeof(hashbuf));
		fprintf(stderr, "Missing NSEC3 record for %s (%s)\n",
			namebuf, hashbuf);
	} else if (result == ISC_R_NOTFOUND &&
		   delegation && (!empty || optout))
	{
		result = ISC_R_SUCCESS;
	} else if (result == ISC_R_SUCCESS) {
		result = match_nsec3(vctx, name, &nsec3param, &rdataset, types,
				     maxtype, rawhash, rhsize);
	}

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (node != NULL)
		dns_db_detachnode(vctx->db, &node);

	return (result);
}

static isc_result_t
verifynsec3s(const vctx_t *vctx, dns_name_t *name,
	     dns_rdataset_t *nsec3paramset, isc_boolean_t delegation,
	     isc_boolean_t empty, unsigned char types[8192],
	     unsigned int maxtype)
{
	isc_result_t result;

	for (result = dns_rdataset_first(nsec3paramset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(nsec3paramset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;

		dns_rdataset_current(nsec3paramset, &rdata);
		result = verifynsec3(vctx, name, &rdata, delegation, empty,
				     types, maxtype);
		if (result != ISC_R_SUCCESS)
			break;
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;
	return (result);
}

static void
verifyset(vctx_t *vctx, dns_rdataset_t *rdataset, dns_name_t *name,
	  dns_dbnode_t *node, dns_rdataset_t *keyrdataset)
{
	unsigned char set_algorithms[256];
	char namebuf[DNS_NAME_FORMATSIZE];
	char algbuf[80];
	char typebuf[80];
	dns_rdataset_t sigrdataset;
	dns_rdatasetiter_t *rdsiter = NULL;
	isc_result_t result;
	int i;

	dns_rdataset_init(&sigrdataset);
	result = dns_db_allrdatasets(vctx->db, node, vctx->ver, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	for (result = dns_rdatasetiter_first(rdsiter);
	     result == ISC_R_SUCCESS;
	     result = dns_rdatasetiter_next(rdsiter)) {
		dns_rdatasetiter_current(rdsiter, &sigrdataset);
		if (sigrdataset.type == dns_rdatatype_rrsig &&
		    sigrdataset.covers == rdataset->type)
			break;
		dns_rdataset_disassociate(&sigrdataset);
	}
	if (result != ISC_R_SUCCESS) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		type_format(rdataset->type, typebuf, sizeof(typebuf));
		fprintf(stderr, "No signatures for %s/%s\n", namebuf, typebuf);
		for (i = 0; i < 256; i++)
			if (vctx->act_algorithms[i] != 0)
				vctx->bad_algorithms[i] = 1;
		dns_rdatasetiter_destroy(&rdsiter);
		return;
	}

	memset(set_algorithms, 0, sizeof(set_algorithms));
	for (result = dns_rdataset_first(&sigrdataset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(&sigrdataset)) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdata_rrsig_t sig;

		dns_rdataset_current(&sigrdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &sig, NULL);
		check_result(result, "dns_rdata_tostruct()");
		if (rdataset->ttl != sig.originalttl) {
			dns_name_format(name, namebuf, sizeof(namebuf));
			type_format(rdataset->type, typebuf, sizeof(typebuf));
			fprintf(stderr, "TTL mismatch for %s %s keytag %u\n",
				namebuf, typebuf, sig.keyid);
			continue;
		}
		if ((set_algorithms[sig.algorithm] != 0) ||
		    (vctx->act_algorithms[sig.algorithm] == 0))
			continue;
		if (goodsig(vctx, &rdata, name, keyrdataset, rdataset))
			set_algorithms[sig.algorithm] = 1;
	}
	dns_rdatasetiter_destroy(&rdsiter);
	if (memcmp(set_algorithms, vctx->act_algorithms,
		   sizeof(set_algorithms))) {
		dns_name_format(name, namebuf, sizeof(namebuf));
		type_format(rdataset->type, typebuf, sizeof(typebuf));
		for (i = 0; i < 256; i++)
			if ((vctx->act_algorithms[i] != 0) &&
			    (set_algorithms[i] == 0)) {
				dns_secalg_format(i, algbuf, sizeof(algbuf));
				fprintf(stderr, "No correct %s signature for "
					"%s %s\n", algbuf, namebuf, typebuf);
				vctx->bad_algorithms[i] = 1;
			}
	}
	dns_rdataset_disassociate(&sigrdataset);
}

static isc_result_t
verifynode(vctx_t *vctx, dns_name_t *name, dns_dbnode_t *node,
	   isc_boolean_t delegation, dns_rdataset_t *keyrdataset,
	   dns_rdataset_t *nsecset, dns_rdataset_t *nsec3paramset,
	   dns_name_t *nextname)
{
	unsigned char types[8192];
	unsigned int maxtype = 0;
	dns_rdataset_t rdataset; dns_rdatasetiter_t *rdsiter = NULL;
	isc_result_t result, tresult;

	memset(types, 0, sizeof(types));
	result = dns_db_allrdatasets(vctx->db, node, vctx->ver, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	result = dns_rdatasetiter_first(rdsiter);
	dns_rdataset_init(&rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdatasetiter_current(rdsiter, &rdataset);
		/*
		 * If we are not at a delegation then everything should be
		 * signed.  If we are at a delegation then only the DS set
		 * is signed.  The NS set is not signed at a delegation but
		 * its existance is recorded in the bit map.  Anything else
		 * other than NSEC and DS is not signed at a delegation.
		 */
		if (rdataset.type != dns_rdatatype_rrsig &&
		    rdataset.type != dns_rdatatype_dnskey &&
		    (!delegation || rdataset.type == dns_rdatatype_ds ||
		     rdataset.type == dns_rdatatype_nsec)) {
			verifyset(vctx, &rdataset, name, node, keyrdataset);
			dns_nsec_setbit(types, rdataset.type, 1);
			if (rdataset.type > maxtype)
				maxtype = rdataset.type;
		} else if (rdataset.type != dns_rdatatype_rrsig &&
			   rdataset.type != dns_rdatatype_dnskey) {
			if (rdataset.type == dns_rdatatype_ns)
				dns_nsec_setbit(types, rdataset.type, 1);
			check_no_rrsig(vctx, &rdataset, name, node);
		} else
			dns_nsec_setbit(types, rdataset.type, 1);
		dns_rdataset_disassociate(&rdataset);
		result = dns_rdatasetiter_next(rdsiter);
	}
	if (result != ISC_R_NOMORE)
		fatal("rdataset iteration failed: %s",
		      isc_result_totext(result));
	dns_rdatasetiter_destroy(&rdsiter);

	result = ISC_R_SUCCESS;

	if (nsecset != NULL && dns_rdataset_isassociated(nsecset))
		result = verifynsec(vctx, name, node, nextname);

	if (nsec3paramset != NULL && dns_rdataset_isassociated(nsec3paramset)) {
		tresult = verifynsec3s(vctx, name, nsec3paramset, delegation,
				       ISC_FALSE, types, maxtype);
		if (result == ISC_R_SUCCESS && tresult != ISC_R_SUCCESS)
			result = tresult;
	}
	return (result);
}

static isc_boolean_t
is_empty(const vctx_t *vctx, dns_dbnode_t *node) {
	dns_rdatasetiter_t *rdsiter = NULL;
	isc_result_t result;

	result = dns_db_allrdatasets(vctx->db, node, vctx->ver, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	result = dns_rdatasetiter_first(rdsiter);
	dns_rdatasetiter_destroy(&rdsiter);
	if (result == ISC_R_NOMORE)
		return (ISC_TRUE);
	return (ISC_FALSE);
}

static void
check_no_nsec(const vctx_t *vctx, dns_name_t *name, dns_dbnode_t *node) {
	dns_rdataset_t rdataset;
	isc_result_t result;

	dns_rdataset_init(&rdataset);
	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_nsec, 0, 0, &rdataset,
				     NULL);
	if (result != ISC_R_NOTFOUND) {
		char namebuf[DNS_NAME_FORMATSIZE];
		dns_name_format(name, namebuf, sizeof(namebuf));
		fatal("unexpected NSEC RRset at %s\n", namebuf);
	}

	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
}

static isc_boolean_t
newchain(const struct nsec3_chain_fixed *first,
	 const struct nsec3_chain_fixed *e)
{
	if (first->hash != e->hash ||
	    first->iterations != e->iterations ||
	    first->salt_length != e->salt_length ||
	    first->next_length != e->next_length ||
	    memcmp(first + 1, e + 1, first->salt_length) != 0)
		return (ISC_TRUE);
	return (ISC_FALSE);
}

static void
free_element(isc_mem_t *mctx, struct nsec3_chain_fixed *e) {
	size_t len;

	len = sizeof(*e) + e->salt_length + 2 * e->next_length;
	isc_mem_put(mctx, e, len);
}

static isc_boolean_t
checknext(const struct nsec3_chain_fixed *first,
	  const struct nsec3_chain_fixed *e)
{
	char buf[512];
	const unsigned char *d1 = (const unsigned char *)(first + 1);
	const unsigned char *d2 = (const unsigned char *)(e + 1);
	isc_buffer_t b;
	isc_region_t sr;

	d1 += first->salt_length + first->next_length;
	d2 += e->salt_length;

	if (memcmp(d1, d2, first->next_length) == 0)
		return (ISC_TRUE);

	DE_CONST(d1 - first->next_length, sr.base);
	sr.length = first->next_length;
	isc_buffer_init(&b, buf, sizeof(buf));
	isc_base32hex_totext(&sr, 1, "", &b);
	fprintf(stderr, "Break in NSEC3 chain at: %.*s\n",
		(int) isc_buffer_usedlength(&b), buf);

	DE_CONST(d1, sr.base);
	sr.length = first->next_length;
	isc_buffer_init(&b, buf, sizeof(buf));
	isc_base32hex_totext(&sr, 1, "", &b);
	fprintf(stderr, "Expected: %.*s\n", (int) isc_buffer_usedlength(&b),
		buf);

	DE_CONST(d2, sr.base);
	sr.length = first->next_length;
	isc_buffer_init(&b, buf, sizeof(buf));
	isc_base32hex_totext(&sr, 1, "", &b);
	fprintf(stderr, "Found: %.*s\n", (int) isc_buffer_usedlength(&b), buf);

	return (ISC_FALSE);
}

#define EXPECTEDANDFOUND "Expected and found NSEC3 chains not equal\n"

static isc_result_t
verify_nsec3_chains(const vctx_t *vctx, isc_mem_t *mctx) {
	isc_result_t result = ISC_R_SUCCESS;
	struct nsec3_chain_fixed *e, *f = NULL;
	struct nsec3_chain_fixed *first = NULL, *prev = NULL;

	while ((e = isc_heap_element(vctx->expected_chains, 1)) != NULL) {
		isc_heap_delete(vctx->expected_chains, 1);
		if (f == NULL)
			f = isc_heap_element(vctx->found_chains, 1);
		if (f != NULL) {
			isc_heap_delete(vctx->found_chains, 1);

			/*
			 * Check that they match.
			 */
			if (chain_equal(e, f)) {
				free_element(mctx, f);
				f = NULL;
			} else {
				if (result == ISC_R_SUCCESS)
					fprintf(stderr, EXPECTEDANDFOUND);
				result = ISC_R_FAILURE;
				/*
				 * Attempt to resync found_chain.
				 */
				while (f != NULL && !chain_compare(e, f)) {
					free_element(mctx, f);
					f = isc_heap_element(vctx->found_chains, 1);
					if (f != NULL)
						isc_heap_delete(vctx->found_chains, 1);
					if (f != NULL && chain_equal(e, f)) {
						free_element(mctx, f);
						f = NULL;
						break;
					}
				}
			}
		} else if (result == ISC_R_SUCCESS) {
			fprintf(stderr, EXPECTEDANDFOUND);
			result = ISC_R_FAILURE;
		}
		if (first == NULL || newchain(first, e)) {
			if (prev != NULL) {
				if (!checknext(prev, first))
					result = ISC_R_FAILURE;
				if (prev != first)
					free_element(mctx, prev);
			}
			if (first != NULL)
				free_element(mctx, first);
			prev = first = e;
			continue;
		}
		if (!checknext(prev, e))
			result = ISC_R_FAILURE;
		if (prev != first)
			free_element(mctx, prev);
		prev = e;
	}
	if (prev != NULL) {
		if (!checknext(prev, first))
			result = ISC_R_FAILURE;
		if (prev != first)
			free_element(mctx, prev);
	}
	if (first != NULL)
		free_element(mctx, first);
	do {
		if (f != NULL) {
			if (result == ISC_R_SUCCESS) {
				fprintf(stderr, EXPECTEDANDFOUND);
				result = ISC_R_FAILURE;
			}
			free_element(mctx, f);
		}
		f = isc_heap_element(vctx->found_chains, 1);
		if (f != NULL)
			isc_heap_delete(vctx->found_chains, 1);
	} while (f != NULL);

	return (result);
}

static isc_result_t
verifyemptynodes(const vctx_t *vctx, dns_name_t *name, dns_name_t *prevname,
		 isc_boolean_t isdelegation, dns_rdataset_t *nsec3paramset)
{
	dns_namereln_t reln;
	int order;
	unsigned int labels, nlabels, i;
	dns_name_t suffix;
	isc_result_t result = ISC_R_SUCCESS, tresult;

	reln = dns_name_fullcompare(prevname, name, &order, &labels);
	if (order >= 0)
		return (result);

	nlabels = dns_name_countlabels(name);

	if (reln == dns_namereln_commonancestor ||
	    reln == dns_namereln_contains) {
		dns_name_init(&suffix, NULL);
		for (i = labels + 1; i < nlabels; i++) {
			dns_name_getlabelsequence(name, nlabels - i, i,
						  &suffix);
			if (nsec3paramset != NULL &&
			     dns_rdataset_isassociated(nsec3paramset)) {
				tresult = verifynsec3s(vctx, &suffix,
						       nsec3paramset,
						       isdelegation, ISC_TRUE,
						       NULL, 0);
				if (result == ISC_R_SUCCESS &&
				    tresult != ISC_R_SUCCESS)
					result = tresult;
			}
		}
	}
	return (result);
}

static isc_result_t
vctx_init(vctx_t *vctx, isc_mem_t *mctx, dns_zone_t *zone, dns_db_t *db,
	  dns_dbversion_t *ver, dns_name_t *origin)
{
	isc_result_t result;

	memset(vctx, 0, sizeof(*vctx));

	vctx->mctx = mctx;
	vctx->zone = zone;
	vctx->db = db;
	vctx->ver = ver;
	vctx->origin = origin;

	dns_rdataset_init(&vctx->keyset);
	dns_rdataset_init(&vctx->keysigs);
	dns_rdataset_init(&vctx->soaset);
	dns_rdataset_init(&vctx->soasigs);
	dns_rdataset_init(&vctx->nsecset);
	dns_rdataset_init(&vctx->nsecsigs);
	dns_rdataset_init(&vctx->nsec3paramset);
	dns_rdataset_init(&vctx->nsec3paramsigs);

	vctx->expected_chains = NULL;
	result = isc_heap_create(mctx, chain_compare, NULL, 1024,
				 &vctx->expected_chains);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	vctx->found_chains = NULL;
	result = isc_heap_create(mctx, chain_compare, NULL, 1024,
				 &vctx->found_chains);
	if (result != ISC_R_SUCCESS) {
		isc_heap_destroy(&vctx->expected_chains);
		return (result);
	}

	return (result);
}

static void
vctx_destroy(vctx_t *vctx) {
	if (dns_rdataset_isassociated(&vctx->keyset)) {
		dns_rdataset_disassociate(&vctx->keyset);
	}
	if (dns_rdataset_isassociated(&vctx->keysigs)) {
		dns_rdataset_disassociate(&vctx->keysigs);
	}
	if (dns_rdataset_isassociated(&vctx->soaset)) {
		dns_rdataset_disassociate(&vctx->soaset);
	}
	if (dns_rdataset_isassociated(&vctx->soasigs)) {
		dns_rdataset_disassociate(&vctx->soasigs);
	}
	if (dns_rdataset_isassociated(&vctx->nsecset)) {
		dns_rdataset_disassociate(&vctx->nsecset);
	}
	if (dns_rdataset_isassociated(&vctx->nsecsigs)) {
		dns_rdataset_disassociate(&vctx->nsecsigs);
	}
	if (dns_rdataset_isassociated(&vctx->nsec3paramset)) {
		dns_rdataset_disassociate(&vctx->nsec3paramset);
	}
	if (dns_rdataset_isassociated(&vctx->nsec3paramsigs)) {
		dns_rdataset_disassociate(&vctx->nsec3paramsigs);
	}
	isc_heap_destroy(&vctx->expected_chains);
	isc_heap_destroy(&vctx->found_chains);
}

static void
check_apex_rrsets(vctx_t *vctx) {
	dns_dbnode_t *node = NULL;
	isc_result_t result;

	result = dns_db_findnode(vctx->db, vctx->origin, ISC_FALSE, &node);
	if (result != ISC_R_SUCCESS)
		fatal("failed to find the zone's origin: %s",
		      isc_result_totext(result));

	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_dnskey, 0, 0,
				     &vctx->keyset, &vctx->keysigs);
	if (result != ISC_R_SUCCESS)
		fatal("Zone contains no DNSSEC keys\n");

	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_soa, 0, 0,
				     &vctx->soaset, &vctx->soasigs);
	if (result != ISC_R_SUCCESS)
		fatal("Zone contains no SOA record\n");

	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_nsec, 0, 0,
				     &vctx->nsecset, &vctx->nsecsigs);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		fatal("NSEC lookup failed\n");

	result = dns_db_findrdataset(vctx->db, node, vctx->ver,
				     dns_rdatatype_nsec3param, 0, 0,
				     &vctx->nsec3paramset,
				     &vctx->nsec3paramsigs);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		fatal("NSEC3PARAM lookup failed\n");

	if (!dns_rdataset_isassociated(&vctx->keysigs))
		fatal("DNSKEY is not signed (keys offline or inactive?)\n");

	if (!dns_rdataset_isassociated(&vctx->soasigs))
		fatal("SOA is not signed (keys offline or inactive?)\n");

	if (dns_rdataset_isassociated(&vctx->nsecset) &&
	    !dns_rdataset_isassociated(&vctx->nsecsigs))
		fatal("NSEC is not signed (keys offline or inactive?)\n");

	if (dns_rdataset_isassociated(&vctx->nsec3paramset) &&
	    !dns_rdataset_isassociated(&vctx->nsec3paramsigs))
		fatal("NSEC3PARAM is not signed (keys offline or inactive?)\n");

	if (!dns_rdataset_isassociated(&vctx->nsecset) &&
	    !dns_rdataset_isassociated(&vctx->nsec3paramset))
		fatal("No valid NSEC/NSEC3 chain for testing\n");

	dns_db_detachnode(vctx->db, &node);
}

/*%
 * Check that the DNSKEY RR has at least one self signing KSK and one ZSK per
 * algorithm in it (or, if -x was used, one self-signing KSK).
 */
static void
check_dnskey(vctx_t *vctx, isc_boolean_t *goodksk, isc_boolean_t *goodzsk) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_dnskey_t dnskey;
	isc_result_t result;

	for (result = dns_rdataset_first(&vctx->keyset);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(&vctx->keyset)) {
		dns_rdataset_current(&vctx->keyset, &rdata);
		result = dns_rdata_tostruct(&rdata, &dnskey, NULL);
		check_result(result, "dns_rdata_tostruct");

		if ((dnskey.flags & DNS_KEYOWNER_ZONE) == 0)
			;
		else if ((dnskey.flags & DNS_KEYFLAG_REVOKE) != 0) {
			if ((dnskey.flags & DNS_KEYFLAG_KSK) != 0 &&
			    !dns_dnssec_selfsigns(&rdata, vctx->origin,
						  &vctx->keyset,
						  &vctx->keysigs, ISC_FALSE,
						  vctx->mctx)) {
				char namebuf[DNS_NAME_FORMATSIZE];
				char buffer[1024];
				isc_buffer_t buf;

				dns_name_format(vctx->origin, namebuf,
						sizeof(namebuf));
				isc_buffer_init(&buf, buffer, sizeof(buffer));
				result = dns_rdata_totext(&rdata, NULL, &buf);
				check_result(result, "dns_rdata_totext");
				fatal("revoked KSK is not self signed:\n"
				      "%s DNSKEY %.*s", namebuf,
				      (int)isc_buffer_usedlength(&buf), buffer);
			}
			if ((dnskey.flags & DNS_KEYFLAG_KSK) != 0 &&
			     vctx->revoked_ksk[dnskey.algorithm] != 255)
				vctx->revoked_ksk[dnskey.algorithm]++;
			else if ((dnskey.flags & DNS_KEYFLAG_KSK) == 0 &&
				 vctx->revoked_zsk[dnskey.algorithm] != 255)
				vctx->revoked_zsk[dnskey.algorithm]++;
		} else if ((dnskey.flags & DNS_KEYFLAG_KSK) != 0) {
			if (dns_dnssec_selfsigns(&rdata, vctx->origin,
						 &vctx->keyset, &vctx->keysigs,
						 ISC_FALSE, vctx->mctx)) {
				if (vctx->ksk_algorithms[dnskey.algorithm] != 255)
					vctx->ksk_algorithms[dnskey.algorithm]++;
				*goodksk = ISC_TRUE;
			} else {
				if (vctx->standby_ksk[dnskey.algorithm] != 255)
					vctx->standby_ksk[dnskey.algorithm]++;
			}
		} else if (dns_dnssec_selfsigns(&rdata, vctx->origin,
						&vctx->keyset, &vctx->keysigs,
						ISC_FALSE, vctx->mctx)) {
			if (vctx->zsk_algorithms[dnskey.algorithm] != 255)
				vctx->zsk_algorithms[dnskey.algorithm]++;
			*goodzsk = ISC_TRUE;
		} else if (dns_dnssec_signs(&rdata, vctx->origin,
					    &vctx->soaset, &vctx->soasigs,
					    ISC_FALSE, vctx->mctx)) {
			if (vctx->zsk_algorithms[dnskey.algorithm] != 255)
				vctx->zsk_algorithms[dnskey.algorithm]++;
		} else {
			if (vctx->standby_zsk[dnskey.algorithm] != 255)
				vctx->standby_zsk[dnskey.algorithm]++;
		}
		dns_rdata_freestruct(&dnskey);
		dns_rdata_reset(&rdata);
	}
}

isc_result_t
dns_zoneverify_dnssec(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *ver,
		      dns_name_t *origin, isc_mem_t *mctx,
		      isc_boolean_t ignore_kskflag,
		      isc_boolean_t keyset_kskonly)
{
	char algbuf[80];
	dns_dbiterator_t *dbiter = NULL;
	dns_dbnode_t *node = NULL, *nextnode = NULL;
	dns_fixedname_t fname, fnextname, fprevname, fzonecut;
	dns_name_t *name, *nextname, *prevname, *zonecut;
	int i;
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t first = ISC_TRUE;
	isc_boolean_t goodksk = ISC_FALSE;
	isc_boolean_t goodzsk = ISC_FALSE;
	isc_result_t result, vresult = ISC_R_UNSET;
	vctx_t vctx;

	result = vctx_init(&vctx, mctx, zone, db, ver, origin);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	check_apex_rrsets(&vctx);

	check_dnskey(&vctx, &goodksk, &goodzsk);

	if (ignore_kskflag ) {
		if (!goodksk && !goodzsk)
			fatal("No self-signed DNSKEY found.");
	} else if (!goodksk)
		fatal("No self-signed KSK DNSKEY found.  Supply an active\n"
		      "key with the KSK flag set, or use '-P'.");

	fprintf(stderr, "Verifying the zone using the following algorithms:");
	for (i = 0; i < 256; i++) {
		if (ignore_kskflag)
			vctx.act_algorithms[i] =
				(vctx.ksk_algorithms[i] != 0 ||
				 vctx.zsk_algorithms[i] != 0) ? 1 : 0;
		else
			vctx.act_algorithms[i] =
				vctx.ksk_algorithms[i] != 0 ? 1 : 0;
		if (vctx.act_algorithms[i] != 0) {
			dns_secalg_format(i, algbuf, sizeof(algbuf));
			fprintf(stderr, " %s", algbuf);
		}
	}
	fprintf(stderr, ".\n");

	if (!ignore_kskflag && !keyset_kskonly) {
		for (i = 0; i < 256; i++) {
			/*
			 * The counts should both be zero or both be non-zero.
			 * Mark the algorithm as bad if this is not met.
			 */
			if ((vctx.ksk_algorithms[i] != 0) ==
			    (vctx.zsk_algorithms[i] != 0))
				continue;
			dns_secalg_format(i, algbuf, sizeof(algbuf));
			fprintf(stderr, "Missing %s for algorithm %s\n",
				(vctx.ksk_algorithms[i] != 0)
				   ? "ZSK"
				   : "self-signed KSK",
				algbuf);
			vctx.bad_algorithms[i] = 1;
		}
	}

	/*
	 * Check that all the other records were signed by keys that are
	 * present in the DNSKEY RRSET.
	 */

	name = dns_fixedname_initname(&fname);
	nextname = dns_fixedname_initname(&fnextname);
	dns_fixedname_init(&fprevname);
	prevname = NULL;
	dns_fixedname_init(&fzonecut);
	zonecut = NULL;

	result = dns_db_createiterator(vctx.db, DNS_DB_NONSEC3, &dbiter);
	check_result(result, "dns_db_createiterator()");

	result = dns_dbiterator_first(dbiter);
	check_result(result, "dns_dbiterator_first()");

	while (!done) {
		isc_boolean_t isdelegation = ISC_FALSE;

		result = dns_dbiterator_current(dbiter, &node, name);
		check_dns_dbiterator_current(result);
		if (!dns_name_issubdomain(name, vctx.origin)) {
			check_no_nsec(&vctx, name, node);
			dns_db_detachnode(vctx.db, &node);
			result = dns_dbiterator_next(dbiter);
			if (result == ISC_R_NOMORE)
				done = ISC_TRUE;
			else
				check_result(result, "dns_dbiterator_next()");
			continue;
		}
		if (is_delegation(&vctx, name, node, NULL)) {
			zonecut = dns_fixedname_name(&fzonecut);
			dns_name_copy(name, zonecut, NULL);
			isdelegation = ISC_TRUE;
		}
		nextnode = NULL;
		result = dns_dbiterator_next(dbiter);
		while (result == ISC_R_SUCCESS) {
			result = dns_dbiterator_current(dbiter, &nextnode,
							nextname);
			check_dns_dbiterator_current(result);
			if (!dns_name_issubdomain(nextname, vctx.origin) ||
			    (zonecut != NULL &&
			     dns_name_issubdomain(nextname, zonecut)))
			{
				check_no_nsec(&vctx, nextname, nextnode);
				dns_db_detachnode(vctx.db, &nextnode);
				result = dns_dbiterator_next(dbiter);
				continue;
			}
			if (is_empty(&vctx, nextnode)) {
				dns_db_detachnode(vctx.db, &nextnode);
				result = dns_dbiterator_next(dbiter);
				continue;
			}
			dns_db_detachnode(vctx.db, &nextnode);
			break;
		}
		if (result == ISC_R_NOMORE) {
			done = ISC_TRUE;
			nextname = vctx.origin;
		} else if (result != ISC_R_SUCCESS)
			fatal("iterating through the database failed: %s",
			      isc_result_totext(result));
		result = verifynode(&vctx, name, node, isdelegation,
				    &vctx.keyset, &vctx.nsecset,
				    &vctx.nsec3paramset, nextname);
		if (vresult == ISC_R_UNSET)
			vresult = ISC_R_SUCCESS;
		if (vresult == ISC_R_SUCCESS && result != ISC_R_SUCCESS)
			vresult = result;
		if (prevname != NULL) {
			result = verifyemptynodes(&vctx, name, prevname,
						  isdelegation,
						  &vctx.nsec3paramset);
		} else
			prevname = dns_fixedname_name(&fprevname);
		dns_name_copy(name, prevname, NULL);
		if (vresult == ISC_R_SUCCESS && result != ISC_R_SUCCESS)
			vresult = result;
		dns_db_detachnode(vctx.db, &node);
	}

	dns_dbiterator_destroy(&dbiter);

	result = dns_db_createiterator(vctx.db, DNS_DB_NSEC3ONLY, &dbiter);
	check_result(result, "dns_db_createiterator()");

	for (result = dns_dbiterator_first(dbiter);
	     result == ISC_R_SUCCESS;
	     result = dns_dbiterator_next(dbiter) ) {
		result = dns_dbiterator_current(dbiter, &node, name);
		check_dns_dbiterator_current(result);
		result = verifynode(&vctx, name, node, ISC_FALSE, &vctx.keyset,
				    NULL, NULL, NULL);
		check_result(result, "verifynode");
		record_found(&vctx, name, node, &vctx.nsec3paramset);
		dns_db_detachnode(vctx.db, &node);
	}
	dns_dbiterator_destroy(&dbiter);

	result = verify_nsec3_chains(&vctx, mctx);
	if (vresult == ISC_R_UNSET)
		vresult = ISC_R_SUCCESS;
	if (result != ISC_R_SUCCESS && vresult == ISC_R_SUCCESS)
		vresult = result;

	/*
	 * If we made it this far, we have what we consider a properly signed
	 * zone.  Set the good flag.
	 */
	for (i = 0; i < 256; i++) {
		if (vctx.bad_algorithms[i] != 0) {
			if (first)
				fprintf(stderr, "The zone is not fully signed "
					"for the following algorithms:");
			dns_secalg_format(i, algbuf, sizeof(algbuf));
			fprintf(stderr, " %s", algbuf);
			first = ISC_FALSE;
		}
	}
	if (!first) {
		fprintf(stderr, ".\n");
		fatal("DNSSEC completeness test failed.");
	}

	if (vresult != ISC_R_SUCCESS)
		fatal("DNSSEC completeness test failed (%s).",
		      dns_result_totext(vresult));

	if (goodksk || ignore_kskflag) {
		/*
		 * Print the success summary.
		 */
		fprintf(stderr, "Zone fully signed:\n");
		for (i = 0; i < 256; i++) {
			if ((vctx.ksk_algorithms[i] != 0) ||
			    (vctx.standby_ksk[i] != 0) ||
			    (vctx.revoked_ksk[i] != 0) ||
			    (vctx.zsk_algorithms[i] != 0) ||
			    (vctx.standby_zsk[i] != 0) ||
			    (vctx.revoked_zsk[i] != 0)) {
				dns_secalg_format(i, algbuf, sizeof(algbuf));
				fprintf(stderr, "Algorithm: %s: KSKs: "
					"%u active, %u stand-by, %u revoked\n",
					algbuf, vctx.ksk_algorithms[i],
					vctx.standby_ksk[i],
					vctx.revoked_ksk[i]);
				fprintf(stderr, "%*sZSKs: "
					"%u active, %u %s, %u revoked\n",
					(int) strlen(algbuf) + 13, "",
					vctx.zsk_algorithms[i],
					vctx.standby_zsk[i],
					keyset_kskonly ? "present" : "stand-by",
					vctx.revoked_zsk[i]);
			}
		}
	}

	vctx_destroy(&vctx);

	return (result);
}
