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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/stdtime.h>
#include <isc/list.h>

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
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/dnssec.h>
#include <dns/keyvalues.h>
#include <dns/secalg.h>
#include <dns/nxt.h>
#include <dns/time.h>
#include <dns/zone.h>
#include <dns/log.h>

#include <dst/dst.h>

#define BUFSIZE 2048
#define is_zone_key(key) ((dst_key_flags(key) & DNS_KEYFLAG_OWNERMASK) \
			  == DNS_KEYOWNER_ZONE)

typedef struct signer_key_struct signer_key_t;
typedef struct signer_array_struct signer_array_t;

struct signer_key_struct {
	dst_key_t *key;
	isc_boolean_t isdefault;
	ISC_LINK(signer_key_t) link;
};

struct signer_array_struct {
	unsigned char array[BUFSIZE];
	ISC_LINK(signer_array_t) link;
};

ISC_LIST(signer_key_t) keylist;
isc_stdtime_t starttime = 0, endtime = 0, now;
int cycle = -1;
int verbose;

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
vbprintf(int level, const char *fmt, ...) {
	va_list ap;
	if (level > verbose)
		return;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* Not thread-safe! */
static char *
nametostr(dns_name_t *name) {
	isc_buffer_t b;
	isc_region_t r;
	static char data[1025];

	isc_buffer_init(&b, data, sizeof(data), ISC_BUFFERTYPE_TEXT);
	dns_name_totext(name, ISC_FALSE, &b);
	isc_buffer_used(&b, &r);
	r.base[r.length] = 0;
	return (char *) r.base;
}

/* Not thread-safe! */
static char *
typetostr(const dns_rdatatype_t type) {
	isc_buffer_t b;
	isc_region_t r;
	static char data[10];

	isc_buffer_init(&b, data, sizeof(data), ISC_BUFFERTYPE_TEXT);
	dns_rdatatype_totext(type, &b);
	isc_buffer_used(&b, &r);
	r.base[r.length] = 0;
	return (char *) r.base;
}

/* Not thread-safe! */
static char *
algtostr(const dns_secalg_t alg) {
	isc_buffer_t b;
	isc_region_t r;
	static char data[10];

	isc_buffer_init(&b, data, sizeof(data), ISC_BUFFERTYPE_TEXT);
	dns_secalg_totext(alg, &b);
	isc_buffer_used(&b, &r);
	r.base[r.length] = 0;
	return (char *) r.base;
}

static inline void
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

static void
signwithkey(dns_name_t *name, dns_rdataset_t *rdataset, dns_rdata_t *rdata,
	    dst_key_t *key, isc_buffer_t *b)
{
	isc_result_t result;

	dns_rdata_init(rdata);
	result = dns_dnssec_sign(name, rdataset, key, &starttime, &endtime,
				 mctx, b, rdata);
	check_result(result, "dns_dnssec_sign()");
#if 0
	/* Verify the data.  This won't work if the start time is reset */
	result = dns_dnssec_verify(name, rdataset, key, mctx, rdata);
	check_result(result, "dns_dnssec_verify()");
#endif
}

static inline isc_boolean_t
issigningkey(signer_key_t *key) {
	return (key->isdefault);
}

static inline isc_boolean_t
iszonekey(signer_key_t *key, dns_db_t *db) {
	char origin[1024];
	isc_buffer_t b;
	isc_result_t result;

	isc_buffer_init(&b, origin, sizeof(origin), ISC_BUFFERTYPE_TEXT);
	result = dns_name_totext(dns_db_origin(db), ISC_FALSE, &b);
	check_result(result, "dns_name_totext()");

	return (ISC_TF(strcasecmp(dst_key_name(key->key), origin) == 0 &&
		(dst_key_flags(key->key) & DNS_KEYFLAG_OWNERMASK) ==
		 DNS_KEYOWNER_ZONE));
}

static signer_key_t *
keythatsigned(dns_rdata_generic_sig_t *sig) {
	char *keyname;
	isc_result_t result;
	dst_key_t *pubkey = NULL, *privkey = NULL;
	signer_key_t *key;

	keyname = nametostr(&sig->signer);

	key = ISC_LIST_HEAD(keylist);
	while (key != NULL) {
		if (sig->keyid == dst_key_id(key->key) &&
		    sig->algorithm == dst_key_alg(key->key) &&
		    strcasecmp(keyname, dst_key_name(key->key)) == 0)
			return key;
		key = ISC_LIST_NEXT(key, link);
	}

	result = dst_key_fromfile(keyname, sig->keyid, sig->algorithm,
				  DST_TYPE_PUBLIC, mctx, &pubkey);
	if (result != ISC_R_SUCCESS)
		return (NULL);

	key = isc_mem_get(mctx, sizeof(signer_key_t));
	if (key == NULL)
		check_result(ISC_R_FAILURE, "isc_mem_get");

	result = dst_key_fromfile(keyname, sig->keyid, sig->algorithm,
				  DST_TYPE_PRIVATE, mctx, &privkey);
	if (result == ISC_R_SUCCESS) {
		key->key = privkey;
		dst_key_free(pubkey);
	}
	else
		key->key = pubkey;
	key->isdefault = ISC_FALSE;
	ISC_LIST_APPEND(keylist, key, link);
	return key;
}

static isc_boolean_t
expecttofindkey(dns_name_t *name, dns_db_t *db, dns_dbversion_t *version) {
	unsigned int options = DNS_DBFIND_NOWILD;
	dns_fixedname_t fname;
	isc_result_t result;

	dns_fixedname_init(&fname);
	result = dns_db_find(db, name, version, dns_rdatatype_key, options,
			     0, NULL, dns_fixedname_name(&fname), NULL, NULL);
	switch (result) {
		case DNS_R_SUCCESS:
		case DNS_R_NXDOMAIN:
		case DNS_R_NXRDATASET:
			return ISC_TRUE;
		case DNS_R_DELEGATION:
		case DNS_R_CNAME:
		case DNS_R_DNAME:
			return ISC_FALSE;
		default:
			check_result(result, "dns_db_find");
			return ISC_FALSE; /* removes a warning */
	}
}

static isc_boolean_t
setverifies(dns_name_t *name, dns_rdataset_t *set, signer_key_t *key,
	    dns_rdata_t *sig)
{
	isc_result_t result = dns_dnssec_verify(name, set, key->key, mctx, sig);
	return (ISC_TF(result == ISC_R_SUCCESS));
}

#define allocbufferandrdata \
	isc_buffer_t b; \
	trdata = isc_mem_get(mctx, sizeof(dns_rdata_t)); \
	tdata = isc_mem_get(mctx, sizeof(signer_array_t)); \
	ISC_LIST_APPEND(arraylist, tdata, link); \
	if (trdata == NULL || tdata == NULL) \
		check_result(ISC_R_FAILURE, "isc_mem_get"); \
	isc_buffer_init(&b, tdata->array, sizeof(tdata->array), \
			ISC_BUFFERTYPE_BINARY);

static void
signset(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
	 dns_name_t *name, dns_rdataset_t *set)
{
	dns_rdatalist_t siglist;
	dns_rdataset_t sigset, oldsigset;
	dns_rdata_t oldsigrdata;
	dns_rdata_t *trdata;
	dns_rdata_generic_sig_t sig;
	signer_key_t *key;
	isc_result_t result;
	isc_boolean_t notsigned = ISC_TRUE, nosigs = ISC_FALSE;
	isc_boolean_t wassignedby[256], nowsignedby[256];
	signer_array_t *tdata;
	ISC_LIST(signer_array_t) arraylist;
	int i;

	ISC_LIST_INIT(siglist.rdata);
	ISC_LIST_INIT(arraylist);

	for (i = 0; i < 256; i++)
		wassignedby[i] = nowsignedby[i] = ISC_FALSE;

	dns_rdataset_init(&oldsigset);
	result = dns_db_findrdataset(db, node, version, dns_rdatatype_sig,
				     set->type, 0, &oldsigset, NULL);
	if (result == ISC_R_NOTFOUND) {
		result = ISC_R_SUCCESS;
		nosigs = ISC_TRUE;
	}
	check_result(result, "dns_db_findrdataset()");

	vbprintf(1, "%s/%s:\n", nametostr(name), typetostr(set->type));

	if (!nosigs) {
		result = dns_rdataset_first(&oldsigset);
		while (result == ISC_R_SUCCESS) {
			isc_boolean_t expired, future;
			isc_boolean_t keep = ISC_FALSE, resign = ISC_FALSE;

			dns_rdataset_current(&oldsigset, &oldsigrdata);

			result = dns_rdata_tostruct(&oldsigrdata, &sig, mctx);
			check_result(result, "dns_rdata_tostruct");

			expired = ISC_TF(now + cycle > sig.timeexpire);
			future = ISC_TF(now < sig.timesigned);

			key = keythatsigned(&sig);

			if (sig.timesigned > sig.timeexpire) {
				/* sig is dropped and not replaced */
				vbprintf(2, "\tsig by %s/%s/%d dropped - "
					 "invalid validity period\n",
					 nametostr(&sig.signer),
					 algtostr(sig.algorithm),
					 sig.keyid);
			}
			else if (key == NULL && !future &&
				 expecttofindkey(&sig.signer, db, version))
			{
				/* sig is dropped and not replaced */
				vbprintf(2, "\tsig by %s/%s/%d dropped - "
					 "private key not found\n",
					 nametostr(&sig.signer),
					 algtostr(sig.algorithm),
					 sig.keyid);
			}
			else if (key == NULL || future) {
				vbprintf(2, "\tsig by %s/%s/%d %s - "
					 "key not found\n",
					 expired ? "retained" : "dropped",
					 nametostr(&sig.signer),
					 algtostr(sig.algorithm),
					 sig.keyid);
				if (!expired)
					keep = ISC_TRUE;
			}
			else if (issigningkey(key)) {
				if (!expired &&
				    setverifies(name, set, key, &oldsigrdata))
				{
					vbprintf(2,
						 "\tsig by %s/%s/%d retained\n",
						 nametostr(&sig.signer),
						 algtostr(sig.algorithm),
						 sig.keyid);
					keep = ISC_TRUE;
					wassignedby[sig.algorithm] = ISC_TRUE;
				}
				else {
					vbprintf(2,
						 "\tsig by %s/%s/%d dropped - "
						 "%s\n",
						 nametostr(&sig.signer),
						 algtostr(sig.algorithm),
						 sig.keyid,
						 expired ? "expired" :
							   "failed to verify");
					wassignedby[sig.algorithm] = ISC_TRUE;
					resign = ISC_TRUE;
				}
			}
			else if (iszonekey(key, db)) {
				if (!expired &&
				    setverifies(name, set, key, &oldsigrdata))
				{
					vbprintf(2,
						 "\tsig by %s/%s/%d retained\n",
						 nametostr(&sig.signer),
						 algtostr(sig.algorithm),
						 sig.keyid);
					keep = ISC_TRUE;
					wassignedby[sig.algorithm] = ISC_TRUE;
					nowsignedby[sig.algorithm] = ISC_TRUE;
				}
				else {
					vbprintf(2,
						 "\tsig by %s/%s/%d dropped - ",
						 "%s\n",
						 nametostr(&sig.signer),
						 algtostr(sig.algorithm),
						 sig.keyid,
						 expired ? "expired" :
							   "failed to verify");
					wassignedby[sig.algorithm] = ISC_TRUE;
					if (dst_key_isprivate(key->key))
						resign = ISC_TRUE;
				}
			}
			else if (!expired) {
				vbprintf(2, "\tsig by %s/%s/%d retained\n",
					 nametostr(&sig.signer),
					 algtostr(sig.algorithm),
					 sig.keyid);
				keep = ISC_TRUE;
			}
			else {
				vbprintf(2, "\tsig by %s/%s/%d expired\n",
					 nametostr(&sig.signer),
					 algtostr(sig.algorithm),
					 sig.keyid);
			}

			if (keep) {
				allocbufferandrdata;
				result = dns_rdata_fromstruct(trdata,
							      set->rdclass,
							      dns_rdatatype_sig,
							      &sig, &b);
				nowsignedby[sig.algorithm] = ISC_TRUE;
				ISC_LIST_APPEND(siglist.rdata, trdata, link);
			}
			else if (resign) {
				allocbufferandrdata;
				vbprintf(1, "\tresigning with key %s/%s/%d\n",
				       dst_key_name(key->key),
				       algtostr(dst_key_alg(key->key)),
				       dst_key_id(key->key));
				signwithkey(name, set, trdata, key->key, &b);
				nowsignedby[sig.algorithm] = ISC_TRUE;
				ISC_LIST_APPEND(siglist.rdata, trdata, link);
			}

			dns_rdata_freestruct(&sig);
			result = dns_rdataset_next(&oldsigset);
		}
		if (result == DNS_R_NOMORE)
			result = ISC_R_SUCCESS;
		check_result(result, "dns_db_dns_rdataset_first()/next()");
		dns_rdataset_disassociate(&oldsigset);
	}

	for (i = 0; i < 256; i++)
		if (wassignedby[i] != 0) {
			notsigned = ISC_FALSE;
			break;
		}

	key = ISC_LIST_HEAD(keylist);
	while (key != NULL) {
		int alg = dst_key_alg(key->key);
		if (key->isdefault &&
		    (notsigned || (wassignedby[alg] && !nowsignedby[alg])))
		{
			allocbufferandrdata;
			signwithkey(name, set, trdata, key->key, &b);
			vbprintf(1, "\tsigning with key %s/%s/%d\n",
			       dst_key_name(key->key),
			       algtostr(dst_key_alg(key->key)),
			       dst_key_id(key->key));
			ISC_LIST_APPEND(siglist.rdata, trdata, link);
		}
		key = ISC_LIST_NEXT(key, link);
	}

	if (!ISC_LIST_EMPTY(siglist.rdata)) {
		siglist.rdclass = set->rdclass;
		siglist.type = dns_rdatatype_sig;
		siglist.covers = set->type;
		if (endtime - starttime < set->ttl)
			siglist.ttl = endtime - starttime;
		else
			siglist.ttl = set->ttl;
		dns_rdataset_init(&sigset);
		result = dns_rdatalist_tordataset(&siglist, &sigset);
		check_result(result, "dns_rdatalist_tordataset");
		result = dns_db_addrdataset(db, node, version, 0, &sigset,
					    0, NULL);
		if (result == DNS_R_UNCHANGED)
			result = ISC_R_SUCCESS;
		check_result(result, "dns_db_addrdataset");
		dns_rdataset_disassociate(&sigset);
	}
	else if (!nosigs) {
	/*
		dns_db_deleterdataset(db, node, version, dns_rdatatype_sig,
				      set->type);
	*/
	}

	trdata = ISC_LIST_HEAD(siglist.rdata);
	while (trdata != NULL) {
		dns_rdata_t *next = ISC_LIST_NEXT(trdata, link);
		isc_mem_put(mctx, trdata, sizeof(dns_rdata_t));
		trdata = next;
	}

	tdata = ISC_LIST_HEAD(arraylist);
	while (tdata != NULL) {
		signer_array_t *next = ISC_LIST_NEXT(tdata, link);
		isc_mem_put(mctx, tdata, sizeof(signer_array_t));
		tdata = next;
	}
}

static isc_boolean_t
hasnullkey(dns_rdataset_t rdataset) {
	isc_result_t result;
	dns_rdata_t rdata;
	isc_uint32_t flags;

	result = dns_rdataset_first(&rdataset);
	while (result == ISC_R_SUCCESS) {
		dst_key_t *key = NULL;

		dns_rdataset_current(&rdataset, &rdata);
		result = dns_dnssec_keyfromrdata(dns_rootname,
						 &rdata, mctx, &key);
		check_result(result, "dns_dnssec_keyfromrdata()");
		flags = dst_key_flags(key);
		dst_key_free(key);
		if (((flags & DNS_KEYFLAG_TYPEMASK) == DNS_KEYTYPE_NOKEY) &&
		    ((flags & DNS_KEYFLAG_OWNERMASK) == DNS_KEYOWNER_ZONE))
			return (ISC_TRUE);
		result = dns_rdataset_next(&rdataset);
	}
	if (result != DNS_R_NOMORE)
		check_result(result, "iteration over keys");
	return (ISC_FALSE);
}

static void
signname(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
	 dns_name_t *name, isc_boolean_t atorigin)
{
	isc_result_t result;
	dns_rdata_t rdata;
	dns_rdataset_t rdataset, nsset;
	dns_rdatasetiter_t *rdsiter;
	isc_boolean_t isdelegation = ISC_FALSE;

	if (!atorigin) {
		dns_rdataset_init(&nsset);
		result = dns_db_findrdataset(db, node, version,
					     dns_rdatatype_ns, 0, 0, &nsset,
					     NULL);
		/* Is this a delegation point? */
		if (result == ISC_R_SUCCESS) {
			isdelegation = ISC_TRUE;
			dns_rdataset_disassociate(&nsset);
		}
	}
	dns_rdataset_init(&rdataset);
	rdsiter = NULL;
	result = dns_db_allrdatasets(db, node, version, 0, &rdsiter);
	check_result(result, "dns_db_allrdatasets()");
	result = dns_rdatasetiter_first(rdsiter);
	while (result == ISC_R_SUCCESS) {
		dns_rdatasetiter_current(rdsiter, &rdataset);

		/* If this is a SIG set, skip it. */
		if (rdataset.type == dns_rdatatype_sig)
			goto skip;

		/* If this is a KEY set at the apex, skip it. */
		if (rdataset.type == dns_rdatatype_key && atorigin)
			goto skip;

		/*
		 * If this name is a delegation point, skip all records
		 * except a KEY set containing a NULL key or an NXT set.
		 */
		if (isdelegation) {
			switch (rdataset.type) {
				case dns_rdatatype_nxt:
					break;
				case dns_rdatatype_key:
					if (hasnullkey(rdataset))
						break;
					goto skip;
				default:
					goto skip;
			}
		}

		/*
		 * There probably should be a dns_nxtsetbit, but it can get
		 * complicated if we need to extend the length of the
		 * bit set.  In this case, since the NXT bit is set and
		 * SIG < NXT, the easy way works.
		 */
		if (rdataset.type == dns_rdatatype_nxt) {
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

		signset(db, version, node, name, &rdataset);

 skip:
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

static inline isc_result_t
next_nonglue(dns_db_t *db, dns_dbversion_t *version, dns_dbiterator_t *dbiter,
	    dns_name_t *name, dns_dbnode_t **nodep, dns_name_t *lastcut)
{
	isc_result_t result;

	if (lastcut == NULL)
		return next_active(db, version, dbiter, name, nodep);
	do {
		result = next_active(db, version, dbiter, name, nodep);
		if (result == ISC_R_SUCCESS) {
			if (!dns_name_issubdomain(name, lastcut))
				return (ISC_R_SUCCESS);
			dns_db_detachnode(db, nodep);
			result = dns_dbiterator_next(dbiter);
		}
	} while (result == ISC_R_SUCCESS);
	return (result);
}

static void
signzone(dns_db_t *db, dns_dbversion_t *version) {
	isc_result_t result, nxtresult;
	dns_dbnode_t *node, *nextnode, *curnode;
	dns_fixedname_t fname, fnextname, fcurname;
	dns_name_t *name, *nextname, *target, *curname, *lastcut;
	dns_dbiterator_t *dbiter;
	isc_boolean_t atorigin = ISC_TRUE;

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);
	dns_fixedname_init(&fnextname);
	nextname = dns_fixedname_name(&fnextname);
	dns_fixedname_init(&fcurname);
	curname = dns_fixedname_name(&fcurname);

	lastcut = NULL;
	dbiter = NULL;
	result = dns_db_createiterator(db, ISC_FALSE, &dbiter);
	check_result(result, "dns_db_createiterator()");
	result = dns_dbiterator_first(dbiter);
	node = NULL;
	dns_name_clone(dns_db_origin(db), name);
	result = next_active(db, version, dbiter, name, &node);
	while (result == ISC_R_SUCCESS) {
		nextnode = NULL;
		curnode = NULL;
		dns_dbiterator_current(dbiter, &curnode, curname);
		if (!atorigin) {
			dns_rdatasetiter_t *rdsiter = NULL;
			dns_rdataset_t set;

			dns_rdataset_init(&set);
			result = dns_db_allrdatasets(db, curnode, version,
						     0, &rdsiter);
			check_result(result, "dns_db_allrdatasets");
			result = dns_rdatasetiter_first(rdsiter);
			while (result == ISC_R_SUCCESS) {
				dns_rdatasetiter_current(rdsiter, &set);
				if (set.type == dns_rdatatype_ns) {
					dns_rdataset_disassociate(&set);
					break;
				}
				dns_rdataset_disassociate(&set);
				result = dns_rdatasetiter_next(rdsiter);
			}
			if (result != ISC_R_SUCCESS && result != ISC_R_NOMORE)
				fatal("rdataset iteration failed");
			if (result == ISC_R_SUCCESS) {
				if (lastcut != NULL)
					dns_name_free(lastcut, mctx);
				else {
					lastcut = isc_mem_get(mctx,
							sizeof(dns_name_t));
					if (lastcut == NULL)
						fatal("allocation failure");
				}
				dns_name_init(lastcut, NULL);
				result = dns_name_dup(curname, mctx, lastcut);
				check_result(result, "dns_name_dup");
			}
			dns_rdatasetiter_destroy(&rdsiter);
		}
		result = dns_dbiterator_next(dbiter);
		if (result == ISC_R_SUCCESS)
			result = next_nonglue(db, version, dbiter, nextname,
					      &nextnode, lastcut);
		if (result == ISC_R_SUCCESS)
			target = nextname;
		else if (result == DNS_R_NOMORE)
			target = dns_db_origin(db);
		else {
			target = NULL;	/* Make compiler happy. */
			fatal("db iteration failed");
		}
		nxtresult = dns_buildnxt(db, version, node, target);
		check_result(nxtresult, "dns_buildnxt()");
		signname(db, version, node, curname, atorigin);
		atorigin = ISC_FALSE;
		dns_db_detachnode(db, &node);
		dns_db_detachnode(db, &curnode);
		node = nextnode;
	}
	if (result != DNS_R_NOMORE)
		fatal("db iteration failed");
	if (lastcut != NULL) {
		dns_name_free(lastcut, mctx);
		isc_mem_put(mctx, lastcut, sizeof(dns_name_t));
	}
	dns_dbiterator_destroy(&dbiter);
}

static void
loadzone(char *file, char *origin, dns_zone_t **zone) {
	isc_buffer_t b, b2;
	unsigned char namedata[1024];
	int len;
	dns_name_t name;
	isc_result_t result;

	len = strlen(origin);
	isc_buffer_init(&b, origin, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&b, len);

	isc_buffer_init(&b2, namedata, sizeof(namedata), ISC_BUFFERTYPE_BINARY);

	dns_name_init(&name, NULL);
	result = dns_name_fromtext(&name, &b, dns_rootname, ISC_FALSE, &b2);
	check_result(result, "dns_name_fromtext()");

	result = dns_zone_create(zone, mctx);
	check_result(result, "dns_zone_create()");

	dns_zone_settype(*zone, dns_zone_master);

	result = dns_zone_setdbtype(*zone, "rbt");
	check_result(result, "dns_zone_setdbtype()");

	result = dns_zone_setdatabase(*zone, file);
	check_result(result, "dns_zone_setdatabase()");

	result = dns_zone_setorigin(*zone, &name);
	check_result(result, "dns_zone_origin()");

	dns_zone_setclass(*zone, dns_rdataclass_in); /* XXX */

	result = dns_zone_load(*zone);
	check_result(result, "dns_zone_load()");
}

static void
getdb(dns_zone_t *zone, dns_db_t **db, dns_dbversion_t **version) {
	isc_result_t result;

	*db = NULL;
	result = dns_zone_getdb(zone, db);
	check_result(result, "dns_zone_getdb()");

	result = dns_db_newversion(*db, version);
	check_result(result, "dns_db_newversion()");
}

static void
loadzonekeys(dns_db_t *db, dns_dbversion_t *version) {
	dns_name_t *origin;
	dns_dbnode_t *node;
	isc_result_t result;
	dst_key_t *keys[20];
	unsigned int nkeys, i;

	origin = dns_db_origin(db);

	node = NULL;
	result = dns_db_findnode(db, origin, ISC_FALSE, &node);
	check_result(result, "dns_db_findnode()");

	result = dns_dnssec_findzonekeys(db, version, node, origin, mctx,
					 20, keys, &nkeys);
	if (result == ISC_R_NOTFOUND)
		result = ISC_R_SUCCESS;
	check_result(result, "dns_dnssec_findzonekeys()");

	for (i = 0; i < nkeys; i++) {
		signer_key_t *key;

		key = isc_mem_get(mctx, sizeof(signer_key_t));
		if (key == NULL)
			check_result(ISC_R_FAILURE, "isc_mem_get(key)");
		key->key = keys[i];
		key->isdefault = ISC_FALSE;

		ISC_LIST_APPEND(keylist, key, link);
	}
	dns_db_detachnode(db, &node);
}

static void
dumpzone(dns_zone_t *zone, char *filename) {
	isc_result_t result;
	FILE *fp;

	fp = fopen(filename, "w");
	if (fp == NULL) {
		fprintf(stderr, "failure opening %s\n", filename);
		exit(-1);
	}
	result = dns_zone_dumptostream(zone, fp);
	check_result(result, "dns_zone_dump");
	fclose(fp);
}

static isc_stdtime_t
strtotime(char *str, isc_int64_t now, isc_int64_t base) {
	isc_int64_t val, offset;
	isc_result_t result;
	char *endp = "";

	if (str[0] == '+') {
		offset = strtol(str + 1, &endp, 0);
		val = base + offset;
	}
	else if (strncmp(str, "now+", 4) == 0) {
		offset = strtol(str + 4, &endp, 0);
		val = now + offset;
	}
	else {
		result = dns_time64_fromtext(str, &val);
		check_result(result, "dns_time64_fromtext()");
	}
	if (*endp != '\0')
		check_result(ISC_R_FAILURE, "strtol()");

	return ((isc_stdtime_t) val);
}

static void
usage() {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tsigner [options] zonefile [keys]\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "Options: (default value in parenthesis) \n");
	fprintf(stderr, "\t-s YYYYMMDDHHMMSS|+ttl:\n");
	fprintf(stderr, "\t\tSIG start time - absolute|offset (now)\n");
	fprintf(stderr, "\t-e YYYYMMDDHHMMSS|+ttl|now+ttl]:\n");
	fprintf(stderr, "\t\tSIG end time  - absolute|from start|from now (now + 30 days)\n");
	fprintf(stderr, "\t-c ttl:\n");
	fprintf(stderr, "\t\tcycle period - regenerate if < cycle from end ( (end-start)/4 )\n");
	fprintf(stderr, "\t-v level:\n");
	fprintf(stderr, "\t\tverbose level (0)\n");
	fprintf(stderr, "\t-l\n");
	fprintf(stderr, "\t\tturn on logging to standard output\n");
	fprintf(stderr, "\t-o origin:\n");
	fprintf(stderr, "\t\tzone origin (name of zonefile)\n");
	fprintf(stderr, "\t-f outfile:\n");
	fprintf(stderr, "\t\tfile the signed zone is written in " \
			"(zonefile + .signed)\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "Signing Keys:\n");
	fprintf(stderr, "\tid:\t\t");
	fprintf(stderr, "zone key with matching keyid\n");
	fprintf(stderr, "\tid/alg:\t\t");
	fprintf(stderr, "zone key with matching keyid and algorithm\n");
	fprintf(stderr, "\tname/id/alg:\t");
	fprintf(stderr, "key with matching name, keyid and algorithm\n");
	fprintf(stderr, "\tnone:\t\t");
	fprintf(stderr, "all zone keys that have private keys\n");
	exit(0);
}

int
main(int argc, char *argv[]) {
	int i, ch;
	char *startstr = NULL, *endstr = NULL;
	char *origin = NULL, *file = NULL, *output = NULL;
	char *endp;
	dns_zone_t *zone;
	dns_db_t *db;
	dns_dbversion_t *version;
	signer_key_t *key;
	isc_result_t result;
	isc_log_t *log = NULL;

	dns_result_register();

	result = isc_mem_create(0, 0, &mctx);
	check_result(result, "isc_mem_create()");

	while ((ch = isc_commandline_parse(argc, argv, "s:e:c:v:o:f:hl")) != -1)
	{
		switch (ch) {
		case 's':
			startstr = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (startstr == NULL)
				check_result(ISC_R_FAILURE, "isc_mem_strdup()");
			break;

		case 'e':
			endstr = isc_mem_strdup(mctx,
						isc_commandline_argument);
			if (endstr == NULL)
				check_result(ISC_R_FAILURE, "isc_mem_strdup()");
			break;

		case 'c':
			endp = NULL;
			cycle = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				check_result(ISC_R_FAILURE, "strtol()");
			break;

		case 'v':
			endp = NULL;
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				check_result(ISC_R_FAILURE, "strtol()");
			break;

		case 'l':
			RUNTIME_CHECK(isc_log_create(mctx, &log) == 
				      ISC_R_SUCCESS);
			RUNTIME_CHECK(dns_log_init(log) == ISC_R_SUCCESS);
	
			RUNTIME_CHECK(isc_log_usechannel(log, "default_stderr",
							 NULL, NULL)
				      == ISC_R_SUCCESS);
			dns_lctx = log;
			break;

		case 'o':
			origin = isc_mem_strdup(mctx,
						isc_commandline_argument);
			if (origin == NULL)
				check_result(ISC_R_FAILURE, "isc_mem_strdup()");
			break;

		case 'f':
			output = isc_mem_strdup(mctx,
						isc_commandline_argument);
			if (output == NULL)
				check_result(ISC_R_FAILURE, "isc_mem_strdup()");
			break;

		case 'h':
			usage();

		}
	}

	isc_stdtime_get(&now);

	if (startstr != NULL) {
		starttime = strtotime(startstr, now, now);
		isc_mem_free(mctx, startstr);
	}
	else
		starttime = now;

	if (endstr != NULL) {
		endtime = strtotime(endstr, now, starttime);
		isc_mem_free(mctx, endstr);
	}
	else
		endtime = starttime + (30 * 24 * 60 * 60);

	if (cycle == -1) {
		cycle = (endtime - starttime) / 4;
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc < 1)
		check_result(ISC_R_FAILURE, "No zones specified");

	file = isc_mem_strdup(mctx, argv[0]);
	if (file == NULL)
		check_result(ISC_R_FAILURE, "isc_mem_strdup()");

	argc -= 1;
	argv += 1;

	if (output == NULL) {
		output = isc_mem_allocate(mctx,
					  strlen(file) + strlen(".signed") + 1);
		if (output == NULL)
			check_result(ISC_R_FAILURE, "isc_mem_allocate()");
		sprintf(output, "%s.signed", file);
	}

	if (origin == NULL) {
		origin = isc_mem_allocate(mctx, strlen(file) + 2);
		if (origin == NULL)
			check_result(ISC_R_FAILURE, "isc_mem_allocate()");
		strcpy(origin, file);
		if (file[strlen(file) - 1] != '.')
			strcat(origin, ".");
	}

	zone = NULL;
	loadzone(file, origin, &zone);

	db = NULL;
	version = NULL;
	getdb(zone, &db, &version);

	ISC_LIST_INIT(keylist);
	loadzonekeys(db, version);

	if (argc == 0) {
		signer_key_t *key;

		key = ISC_LIST_HEAD(keylist);
		while (key != NULL) {
			key->isdefault = ISC_TRUE;
			key = ISC_LIST_NEXT(key, link);
		}
	}
	else {
		for (i = 0; i < argc; i++) {
			int id, alg;
			char *idstr = NULL, *name = NULL, *algstr = NULL, *s;

			idstr = argv[i];
			algstr = strchr(idstr, '/');
			if (algstr != NULL) {
				*algstr++ = 0;
				s = strchr(algstr, '/');
				if (s != NULL) {
					*s++ = 0;
					name = idstr;
					idstr = algstr;
					algstr = s;
				}
			}

			endp = NULL;
			id = strtol(idstr, &endp, 0);
			if (*endp != '\0')
				check_result(ISC_R_FAILURE, "strtol");

			if (algstr != NULL) {
				endp = NULL;
				alg = strtol(algstr, &endp, 0);
				if (*endp != '\0')
					check_result(ISC_R_FAILURE, "strtol");
			}
			else
				alg = 0;

			if (name == NULL)
				name = origin;
			key = ISC_LIST_HEAD(keylist);
			while (key != NULL) {
				dst_key_t *dkey = key->key;
				if (dst_key_id(dkey) == id &&
				    (alg == 0 || dst_key_alg(dkey) == alg) &&
				    strcasecmp(name, dst_key_name(dkey)) == 0)
				{
					key->isdefault = ISC_TRUE;
					if (!dst_key_isprivate(dkey))
						check_result
							(DST_R_NOTPRIVATEKEY,
							 "key specify");
					if (alg == 0)
						alg = dst_key_alg(dkey);
					break;
				}
				key = ISC_LIST_NEXT(key, link);
			}
			if (key == NULL && alg != 0) {
				dst_key_t *dkey = NULL;
				result = dst_key_fromfile(name, id, alg,
							  DST_TYPE_PRIVATE,
							  mctx, &dkey);
				check_result (result, "dst_key_fromfile");
				key = isc_mem_get(mctx, sizeof(signer_key_t));
				if (key == NULL)
					check_result(ISC_R_FAILURE,
						     "isc_mem_get");
				key->key = dkey;
				key->isdefault = ISC_TRUE;
				ISC_LIST_APPEND(keylist, key, link);
			}
			else
				printf("Ignoring key with algorithm 0\n");
		}
	}

	signzone(db, version);

	/* should we update the SOA serial? */
	dns_db_closeversion(db, &version, ISC_TRUE);
	dumpzone(zone, output);
	dns_db_detach(&db);
	dns_zone_detach(&zone);

	key = ISC_LIST_HEAD(keylist);
	while (key != NULL) {
		signer_key_t *next = ISC_LIST_NEXT(key, link);
		dst_key_free(key->key);
		isc_mem_put(mctx, key, sizeof(signer_key_t));
		key = next;
	}

	isc_mem_free(mctx, origin);
	isc_mem_free(mctx, file);
	isc_mem_free(mctx, output);

	if (log != NULL)
		isc_log_destroy(&log);
/*	isc_mem_stats(mctx, stdout);*/
	isc_mem_destroy(&mctx);

	return (0);
}
