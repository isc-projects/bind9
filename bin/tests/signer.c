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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/stdtime.h>

#include <dns/types.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>
#include <dns/dnssec.h>
#include <dns/keyvalues.h>
#include <dns/nxt.h>

#include <dst/dst.h>

#define MAXKEYS 10
#define is_zone_key(key) ((dst_key_flags(key) & DNS_KEYFLAG_OWNERMASK) \
			  == DNS_KEYOWNER_ZONE)

static isc_mem_t *mctx = NULL;

static inline void
fatal(char *message) {
	fprintf(stderr, "%s\n", message);
	exit(1);
}

static inline void
check_result(isc_result_t result, char *message) {
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "%s: %s\n", message,
			isc_result_totext(result));
		exit(1);
	}
}

static void
set_bit(unsigned char *array, unsigned int index, unsigned int bit) {
	unsigned int byte, shift, mask;
	
	byte = array[index / 8];
	shift = 7 - (index % 8);
	mask = 1 << shift;

	if (bit)
		array[index / 8] |= mask;
	else
		array[index / 8] &= (~mask & 0xFF);
}

dns_result_t
find_apex_keys(dns_db_t *db, dns_dbversion_t *ver, dns_dbnode_t *node,
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
		result = dst_key_fromfile(dst_key_name(pubkey),
					  dst_key_id(pubkey),
					  dst_key_alg(pubkey),
					  DST_TYPE_PRIVATE,
					  mctx, &keys[count++]);
		check_result(result, "dst_key_fromfile()");
		dst_key_free(pubkey);
		pubkey = NULL;
		result = dns_rdataset_next(&rdataset);
	}
	if (result != DNS_R_NOMORE)
		check_result(result, "iteration over zone keys");
	result = DNS_R_SUCCESS;
	if (count == 0)
		check_result(ISC_R_FAILURE, "no key found");

/* failure:*/
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (pubkey != NULL)
		dst_key_free(pubkey);
	*nkeys = count;
	return (result);
}


static void
sign_with_key(dns_name_t *name, dns_rdataset_t *rdataset, dns_rdata_t *rdata,
	      dns_rdatalist_t *sigrdatalist, isc_stdtime_t *now,
	      isc_stdtime_t *later, dst_key_t *key,
	      unsigned char *array, int len)
{
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;

	r.base = array;
	r.length = len;
	memset(r.base, 0, r.length);

	dns_rdata_init(rdata);
	isc_buffer_init(&b, r.base, r.length, ISC_BUFFERTYPE_BINARY);
	result = dns_dnssec_sign(name, rdataset, key, now, later,
				 mctx, &b, rdata);
	check_result(result, "dns_dnssec_sign()");
	result = dns_dnssec_verify(name, rdataset, key, mctx, rdata);
	check_result(result, "dns_dnssec_verify()");
	ISC_LIST_APPEND(sigrdatalist->rdata, rdata, link);
}

void
resign_set(dns_name_t *name, dns_name_t *origin, dns_rdataset_t *rdataset,
	   dns_rdata_t *rdata, dns_rdatalist_t *sigrdatalist,
	   dns_rdata_t *oldsigrdata, isc_stdtime_t *now, isc_stdtime_t *later,
	   dst_key_t **keys, int nkeys, unsigned char *array, int len)
{
	dns_rdata_generic_sig_t sig;
	isc_result_t result;
	isc_buffer_t b;
	int i;
	isc_boolean_t done = ISC_FALSE;
	isc_boolean_t foundnonzone = ISC_FALSE;

	result = dns_rdata_tostruct(oldsigrdata, &sig, mctx);
	check_result(result, "dns_rdata_tostruct()");

	/*
	 * Is this a real signture that we should regenerate?
	 */
	if (dns_name_compare(sig.signer, origin) == 0) {
		for (i = 0; i < nkeys; i++) {
			dst_key_t *key = keys[i];
			if (dst_key_id(key) == sig.keyid &&
			    dst_key_alg(key) == sig.algorithm)
			{
				if (!is_zone_key(key))
					foundnonzone = ISC_TRUE;
				else
					break;
			}
		}
		if (i < nkeys) {
			sign_with_key(name, rdataset, rdata, sigrdatalist,
				      now, later, keys[i], array, len);
			done = ISC_TRUE;
		}
	}
	if (!done) {
		if (dns_name_compare(sig.signer, origin) != 0 || foundnonzone) {
			printf("saving old sig...\n");
			isc_buffer_init(&b, array, len, ISC_BUFFERTYPE_BINARY);
			result = dns_rdata_fromstruct(rdata, rdataset->rdclass,
						      dns_rdatatype_sig,
						      &sig, &b);
			ISC_LIST_APPEND(sigrdatalist->rdata, rdata, link);
			check_result(result, "dns_rdata_fromstruct()");
		}
		else
			printf("couldn't find key <origin>/%d, dropping sig\n",
			       sig.keyid);
	}

	dns_rdata_freestruct(&sig);
}

static void
generate_sig(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
	     dns_name_t *name, dst_key_t **keys, isc_boolean_t *defaultkey,
	     int nkeys)
{
	isc_result_t result;
	dns_name_t *origin;
	dns_rdata_t rdata, rdatas[MAXKEYS];
	dns_rdataset_t rdataset, sigrdataset, oldsigset;
	dns_rdatalist_t sigrdatalist;
	dns_rdatasetiter_t *rdsiter;
	isc_stdtime_t now, later;
	unsigned char array[MAXKEYS][1024];
	int i;
	isc_boolean_t alreadysigned;

	origin = dns_db_origin(db);

	dns_rdataset_init(&rdataset);
	rdsiter = NULL;
	result = dns_db_allrdatasets(db, node, version, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	result = dns_rdatasetiter_first(rdsiter);
	while (result == ISC_R_SUCCESS) {
		dns_rdatasetiter_current(rdsiter, &rdataset);

		if (rdataset.type == dns_rdatatype_sig ||
		    (rdataset.type == dns_rdatatype_key &&
		     dns_name_compare(name, origin) == 0))
		{
			dns_rdataset_disassociate(&rdataset);
			result = dns_rdatasetiter_next(rdsiter);
			continue;
		}

		dns_rdataset_init(&oldsigset);
		result = dns_db_findrdataset(db, node, version,
					     dns_rdatatype_sig, rdataset.type,
					     0, &oldsigset, NULL);
		if (result == ISC_R_SUCCESS)
			alreadysigned = ISC_TRUE;
		else if (result == ISC_R_NOTFOUND) {
			alreadysigned = ISC_FALSE;
			result = ISC_R_SUCCESS;
		}
		else
			alreadysigned = ISC_FALSE; /* not that this matters */
		check_result(result, "dns_db_findrdataset()");

		/*
		 * There probably should be a dns_nxtsetbit or something,
		 * but it can get complicated if we need to extend the
		 * length.  In this case, since the NXT bit is set and
		 * SIG < NXT, the easy way works.
		 */
		if (rdataset.type == dns_rdatatype_nxt && !alreadysigned) {
			unsigned char *nxt_bits;
			dns_name_t nxtname;
			isc_region_t r, r2;

			result = dns_rdataset_first(&rdataset);
			check_result(result, "dns_rdataset_first()");
			dns_rdataset_current(&rdataset, &rdata);
			dns_rdata_toregion(&rdata, &r);
			dns_name_init(&nxtname, NULL);
			dns_name_fromregion(&nxtname, &r);
			dns_name_toregion(&nxtname, &r2);
			nxt_bits = r.base + r2.length;
			set_bit(nxt_bits, dns_rdatatype_sig, 1);
			
		}

		isc_stdtime_get(&now);
		later = 100000 + now;
		ISC_LIST_INIT(sigrdatalist.rdata);

		if (!alreadysigned) {
			for (i = 0; i < nkeys; i++) {
				if (!defaultkey[i] || !is_zone_key(keys[i]))
					continue;
				sign_with_key(name, &rdataset, &rdatas[i],
					      &sigrdatalist, &now, &later,
					      keys[i], array[i],
					      sizeof(array[i]));
			}
		}
		else {
			dns_rdata_t sigrdata;

			dns_rdata_init(&sigrdata);
			result = dns_rdataset_first(&oldsigset);
			i = 0;
			while (result == ISC_R_SUCCESS) {
				dns_rdataset_current(&oldsigset, &sigrdata);
				resign_set(name, origin, &rdataset, &rdatas[i],
					   &sigrdatalist, &sigrdata,
					   &now, &later, keys, nkeys, array[i],
					   sizeof(array[i]));
				i++;
				result = dns_rdataset_next(&oldsigset);
			}
			dns_rdataset_disassociate(&oldsigset);
		}

		sigrdatalist.rdclass = rdataset.rdclass;
		sigrdatalist.type = dns_rdatatype_sig;
		sigrdatalist.covers = rdataset.type;
		sigrdatalist.ttl = rdataset.ttl;
		dns_rdataset_init(&sigrdataset);
		result = dns_rdatalist_tordataset(&sigrdatalist, &sigrdataset);
		check_result(result, "dns_rdatalist_tordataset");
		result = dns_db_addrdataset(db, node, version, 0, &sigrdataset,
					    ISC_FALSE, NULL);
		if (result == DNS_R_UNCHANGED)
			result = ISC_R_SUCCESS;
		check_result(result, "dns_db_addrdataset");
		dns_rdataset_disassociate(&sigrdataset);

		dns_rdataset_disassociate(&rdataset);
		result = dns_rdatasetiter_next(rdsiter);
	}
	if (result != DNS_R_NOMORE)
		fatal("rdataset iteration failed");
	dns_rdatasetiter_destroy(&rdsiter);
}

static inline isc_boolean_t
active_node(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node) {
	dns_rdatasetiter_t *rdsiter;
	isc_boolean_t active = ISC_FALSE;
	isc_result_t result;
	dns_rdataset_t rdataset;

	dns_rdataset_init(&rdataset);
	rdsiter = NULL;
	result = dns_db_allrdatasets(db, node, version, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	result = dns_rdatasetiter_first(rdsiter);
	while (result == ISC_R_SUCCESS) {
		dns_rdatasetiter_current(rdsiter, &rdataset);
		if (rdataset.type != dns_rdatatype_nxt)
			active = ISC_TRUE;
		dns_rdataset_disassociate(&rdataset);
		if (!active)
			result = dns_rdatasetiter_next(rdsiter);
		else
			result = DNS_R_NOMORE;
	}
	if (result != DNS_R_NOMORE)
		fatal("rdataset iteration failed");
	dns_rdatasetiter_destroy(&rdsiter);

	if (!active) {
		/*
		 * Make sure there is no NXT record for this node.
		 */
		result = dns_db_deleterdataset(db, node, version,
					       dns_rdatatype_nxt);
		if (result == DNS_R_UNCHANGED)
			result = ISC_R_SUCCESS;
		check_result(result, "dns_db_deleterdataset");
	}

	return (active);
}

static inline isc_result_t
next_active(dns_db_t *db, dns_dbversion_t *version, dns_dbiterator_t *dbiter,
	    dns_name_t *name, dns_dbnode_t **nodep)
{
	isc_result_t result;
	isc_boolean_t active;

	do {
		active = ISC_FALSE;
		result = dns_dbiterator_current(dbiter, nodep, name);
		if (result == ISC_R_SUCCESS) {
			active = active_node(db, version, *nodep);
			if (!active) {
				dns_db_detachnode(db, nodep);
				result = dns_dbiterator_next(dbiter);
			}
		}
	} while (result == ISC_R_SUCCESS && !active);

	return (result);
}

static void
sign(char *filename) {
	isc_result_t result, nxtresult;
	dns_db_t *db;
	dns_dbversion_t *wversion;
	dns_dbnode_t *node, *nextnode, *curnode;
	char *origintext;
	dns_fixedname_t fname, fnextname;
	dns_name_t *name, *nextname, *target, curname;
	isc_buffer_t b;
	size_t len;
	dns_dbiterator_t *dbiter;
	char newfilename[1024];
	dst_key_t *keys[MAXKEYS];
	isc_boolean_t defaultkey[MAXKEYS];
	unsigned char curdata[1024];
	isc_buffer_t curbuf;
	unsigned int nkeys = 0;
	unsigned int i;

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);
	dns_fixedname_init(&fnextname);
	nextname = dns_fixedname_name(&fnextname);

	origintext = strrchr(filename, '/');
	if (origintext == NULL)
		origintext = filename;
	else
		origintext++;	/* Skip '/'. */
	len = strlen(origintext);
	isc_buffer_init(&b, origintext, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&b, len);
	result = dns_name_fromtext(name, &b, dns_rootname, ISC_FALSE, NULL);
	check_result(result, "dns_name_fromtext()");
	db = NULL;
	result = dns_db_create(mctx, "rbt", name, ISC_FALSE,
			       dns_rdataclass_in, 0, NULL, &db);
	check_result(result, "dns_db_create()");
	result = dns_db_load(db, filename);
	check_result(result, "dns_db_load()");

	node = NULL;
	result = dns_db_findnode(db, name, ISC_FALSE, &node);
	check_result(result, "dns_db_findnode()");
	result = find_apex_keys(db, NULL, node, name, mctx, MAXKEYS,
				keys, &nkeys);
	check_result(result, "dns_dnssec_findzonekeys()");	
	dns_db_detachnode(db, &node);
	for (i = 0; i < nkeys; i++)
		defaultkey[i] = ISC_TRUE;

	wversion = NULL;
	result = dns_db_newversion(db, &wversion);
	check_result(result, "dns_db_newversion()");

	dbiter = NULL;
	result = dns_db_createiterator(db, ISC_FALSE, &dbiter);
	check_result(result, "dns_db_createiterator()");
	result = dns_dbiterator_first(dbiter);
	node = NULL;
	result = next_active(db, wversion, dbiter, name, &node);
	while (result == ISC_R_SUCCESS) {
		nextnode = NULL;
		curnode = NULL;
		dns_name_init(&curname, NULL);
		isc_buffer_init(&curbuf, curdata, sizeof(curdata),
				ISC_BUFFERTYPE_BINARY);
		dns_name_setbuffer(&curname, &curbuf);
		dns_dbiterator_current(dbiter, &curnode, &curname);
		result = dns_dbiterator_next(dbiter);
		if (result == ISC_R_SUCCESS)
			result = next_active(db, wversion, dbiter, nextname,
					     &nextnode);
		if (result == ISC_R_SUCCESS)
			target = nextname;
		else if (result == DNS_R_NOMORE)
			target = dns_db_origin(db);
		else {
			target = NULL;	/* Make compiler happy. */
			fatal("db iteration failed");
		}
		nxtresult = dns_buildnxt(db, wversion, node, target);
		check_result(nxtresult, "dns_buildnxt()");		
		generate_sig(db, wversion, node, &curname, keys, defaultkey,
			     nkeys);
		dns_name_invalidate(&curname);
		dns_db_detachnode(db, &node);
		dns_db_detachnode(db, &curnode);
		node = nextnode;
	}
	if (result != DNS_R_NOMORE)
		fatal("db iteration failed");
	dns_dbiterator_destroy(&dbiter);
	/*
	 * XXXRTH  For now, we don't increment the SOA serial.
	 */
	dns_db_closeversion(db, &wversion, ISC_TRUE);
	len = strlen(filename);
	if (len + 4 + 1 > sizeof newfilename)
		fatal("filename too long");
	sprintf(newfilename, "%s.new", filename);
	result = dns_db_dump(db, NULL, newfilename);
	check_result(result, "dns_db_dump");
	dns_db_detach(&db);
	for (i = 0; i < nkeys; i++)
		dst_key_free(keys[i]);
}

int
main(int argc, char *argv[]) {
	int i;
	isc_result_t result;

	dns_result_register();

	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create()");

	argc--;
	argv++;

	for (i = 0; i < argc; i++)
		sign(argv[i]);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
