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
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/serial.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/ncache.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/time.h>
#include <dns/types.h>

#define MAX_SHUFFLE 100
thread_local dns_rdata_t dns__rdataset_rdatas[MAX_SHUFFLE];

static const char *trustnames[] = {
	"none",		  "pending-additional",
	"pending-answer", "additional",
	"glue",		  "answer",
	"authauthority",  "authanswer",
	"secure",	  "local" /* aka ultimate */
};

const char *
dns_trust_totext(dns_trust_t trust) {
	if (trust >= sizeof(trustnames) / sizeof(*trustnames)) {
		return "bad";
	}
	return trustnames[trust];
}

void
dns_rdataset_init(dns_rdataset_t *rdataset) {
	/*
	 * Make 'rdataset' a valid, disassociated rdataset.
	 */

	REQUIRE(rdataset != NULL);

	*rdataset = (dns_rdataset_t){
		.magic = DNS_RDATASET_MAGIC,
		.link = ISC_LINK_INITIALIZER,
	};
}

void
dns_rdataset_invalidate(dns_rdataset_t *rdataset) {
	/*
	 * Invalidate 'rdataset'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);

	*rdataset = (dns_rdataset_t){
		.magic = 0,
		.link = ISC_LINK_INITIALIZER,
	};
}

void
dns__rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	/*
	 * Disassociate 'rdataset' from its rdata, allowing it to be reused.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->disassociate != NULL) {
		(rdataset->methods->disassociate)(rdataset DNS__DB_FLARG_PASS);
	}
	*rdataset = (dns_rdataset_t){
		.magic = DNS_RDATASET_MAGIC,
		.link = ISC_LINK_INITIALIZER,
	};
}

bool
dns_rdataset_isassociated(const dns_rdataset_t *rdataset) {
	/*
	 * Is 'rdataset' associated?
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	if (rdataset->methods != NULL) {
		return true;
	}

	return false;
}

static isc_result_t
question_cursor(dns_rdataset_t *rdataset ISC_ATTR_UNUSED) {
	return ISC_R_NOMORE;
}

static void
question_clone(const dns_rdataset_t *source,
	       dns_rdataset_t *target DNS__DB_FLARG) {
	*target = *source;
}

static dns_rdatasetmethods_t question_methods = {
	.first = question_cursor,
	.next = question_cursor,
	.clone = question_clone,
};

void
dns_rdataset_makequestion(dns_rdataset_t *rdataset, dns_rdataclass_t rdclass,
			  dns_rdatatype_t type) {
	/*
	 * Make 'rdataset' a valid, associated, question rdataset, with a
	 * question class of 'rdclass' and type 'type'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);

	rdataset->methods = &question_methods;
	rdataset->rdclass = rdclass;
	rdataset->type = type;
	rdataset->attributes.question = true;
}

unsigned int
dns_rdataset_count(dns_rdataset_t *rdataset) {
	/*
	 * Return the number of records in 'rdataset'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	REQUIRE(rdataset->methods->count != NULL);

	return (rdataset->methods->count)(rdataset);
}

void
dns__rdataset_clone(const dns_rdataset_t *source,
		    dns_rdataset_t *target DNS__DB_FLARG) {
	/*
	 * Make 'target' refer to the same rdataset as 'source'.
	 */

	REQUIRE(DNS_RDATASET_VALID(source));
	REQUIRE(source->methods != NULL);
	REQUIRE(DNS_RDATASET_VALID(target));
	REQUIRE(target->methods == NULL);

	(source->methods->clone)(source, target DNS__DB_FLARG_PASS);
}

isc_result_t
dns_rdataset_first(dns_rdataset_t *rdataset) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	REQUIRE(rdataset->methods->first != NULL);

	isc_result_t result = rdataset->methods->first(rdataset);
	ENSURE(result == ISC_R_SUCCESS || result == ISC_R_NOMORE);
	return result;
}

isc_result_t
dns_rdataset_next(dns_rdataset_t *rdataset) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	REQUIRE(rdataset->methods->next != NULL);

	isc_result_t result = rdataset->methods->next(rdataset);
	ENSURE(result == ISC_R_SUCCESS || result == ISC_R_NOMORE);
	return result;
}

void
dns_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	/*
	 * Make 'rdata' refer to the current rdata.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	REQUIRE(rdataset->methods->current != NULL);

	(rdataset->methods->current)(rdataset, rdata);
}

#define WANT_CYCLIC(r) (((r)->attributes.order == dns_order_cyclic))

static isc_result_t
towire_addtypeclass(dns_rdataset_t *rdataset, const dns_name_t *name,
		    dns_compress_t *cctx, isc_buffer_t *target,
		    isc_buffer_t *rrbuffer, size_t extralen) {
	isc_region_t r;
	isc_result_t result;
	size_t headlen;

	*rrbuffer = *target;
	dns_compress_setpermitted(cctx, true);
	result = dns_name_towire(name, cctx, target);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	headlen = sizeof(dns_rdataclass_t) + sizeof(dns_rdatatype_t) + extralen;
	isc_buffer_availableregion(target, &r);
	if (r.length < headlen) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putuint16(target, rdataset->type);
	isc_buffer_putuint16(target, rdataset->rdclass);
	return ISC_R_SUCCESS;
}

static void
towire_addttl(dns_rdataset_t *rdataset, isc_buffer_t *target,
	      isc_buffer_t *rdlen) {
	isc_buffer_putuint32(target, rdataset->ttl);

	/* Save space for rdlen. */
	*rdlen = *target;
	isc_buffer_add(target, 2);
}

static isc_result_t
towire_addrdata(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target,
		isc_buffer_t *rdlen) {
	isc_result_t result = dns_rdata_towire(rdata, cctx, target);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	INSIST((target->used >= rdlen->used + 2) &&
	       (target->used - rdlen->used - 2 < 65536));
	isc_buffer_putuint16(rdlen, (uint16_t)(target->used - rdlen->used - 2));
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_question(dns_rdataset_t *rdataset, const dns_name_t *name,
		dns_compress_t *cctx, isc_buffer_t *target,
		isc_buffer_t *rrbuffer, unsigned int *countp) {
	isc_result_t result;

	result = dns_rdataset_first(rdataset);
	INSIST(result == ISC_R_NOMORE);

	result = towire_addtypeclass(rdataset, name, cctx, target, rrbuffer, 0);
	if (result != ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	*countp += 1;

	return ISC_R_SUCCESS;
}

static isc_result_t
towire_answer(dns_rdataset_t *rdataset, const dns_name_t *name,
	      dns_compress_t *cctx, isc_buffer_t *target,
	      isc_buffer_t *rrbuffer, uint16_t id, unsigned int *countp) {
	isc_result_t result;
	size_t start = 0, count = 0, added = 0;
	isc_buffer_t rdlen;
	dns_rdata_t *rdatas = dns__rdataset_rdatas;

	count = dns_rdataset_count(rdataset);
	result = dns_rdataset_first(rdataset);
	if (result == ISC_R_NOMORE) {
		return ISC_R_SUCCESS;
	} else if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (WANT_CYCLIC(rdataset) && rdataset->type != dns_rdatatype_rrsig) {
		start = id % count;

		/* Do we need larger buffer? */
		if (start > ARRAY_SIZE(dns__rdataset_rdatas)) {
			rdatas = isc_mem_cget(cctx->mctx, start,
					      sizeof(rdatas[0]));
		}
	}

	/*
	 * Save the rdata up until the start.  If we are not
	 * doing cyclic, the start == 0, so this is no-op.
	 */
	for (size_t i = 0; i < start; i++) {
		dns_rdata_init(&rdatas[i]);
		dns_rdataset_current(rdataset, &rdatas[i]);

		result = dns_rdataset_next(rdataset);
		if (result == ISC_R_NOMORE) {
			result = ISC_R_SUCCESS;
			break;
		} else if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
	}

	for (size_t i = start; i < count; i++) {
		dns_rdata_t rdata = DNS_RDATA_INIT;

		CHECK(towire_addtypeclass(rdataset, name, cctx, target,
					  rrbuffer, sizeof(dns_ttl_t) + 2));
		towire_addttl(rdataset, target, &rdlen);

		dns_rdataset_current(rdataset, &rdata);
		CHECK(towire_addrdata(&rdata, cctx, target, &rdlen));
		added++;

		result = dns_rdataset_next(rdataset);
		if (result == ISC_R_NOMORE) {
			result = ISC_R_SUCCESS;
			break;
		} else if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
	}

	for (size_t i = 0; i < start; i++) {
		CHECK(towire_addtypeclass(rdataset, name, cctx, target,
					  rrbuffer, sizeof(dns_ttl_t) + 2));
		towire_addttl(rdataset, target, &rdlen);

		CHECK(towire_addrdata(&rdatas[i], cctx, target, &rdlen));
		added++;
	}

	INSIST(added == count);

cleanup:
	*countp += added;
	if (rdatas != dns__rdataset_rdatas) {
		isc_mem_cput(cctx->mctx, rdatas, start, sizeof(rdatas[0]));
	}

	return result;
}

isc_result_t
dns_rdataset_towire(dns_rdataset_t *rdataset, const dns_name_t *owner_name,
		    uint16_t id, dns_compress_t *cctx, isc_buffer_t *target,
		    bool partial, unsigned int options, unsigned int *countp) {
	isc_result_t result;
	isc_buffer_t savedbuffer = *target;
	isc_buffer_t rrbuffer = *target;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;

	/*
	 * Convert 'rdataset' to wire format, compressing names as specified
	 * in cctx, and storing the result in 'target'.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	REQUIRE(countp != NULL);
	REQUIRE(cctx != NULL && cctx->mctx != NULL);

	if (rdataset->attributes.negative) {
		/*
		 * This is a negative caching rdataset.
		 */
		unsigned int ncache_opts = 0;
		if ((options & DNS_RDATASETTOWIRE_OMITDNSSEC) != 0) {
			ncache_opts |= DNS_NCACHETOWIRE_OMITDNSSEC;
		}
		return dns_ncache_towire(rdataset, cctx, target, ncache_opts,
					 countp);
	}

	name = dns_fixedname_initname(&fixed);
	dns_name_copy(owner_name, name);
	dns_rdataset_getownercase(rdataset, name);
	dns_compress_setmultiuse(cctx, true);

	name->attributes.nocompress |= owner_name->attributes.nocompress;

	if (rdataset->attributes.question) {
		result = towire_question(rdataset, name, cctx, target,
					 &rrbuffer, countp);
		if (result != ISC_R_SUCCESS) {
			goto rollback;
		}
	} else {
		result = towire_answer(rdataset, name, cctx, target, &rrbuffer,
				       id, countp);
		if (result != ISC_R_SUCCESS) {
			goto rollback;
		}
	}

	return ISC_R_SUCCESS;

rollback:
	if (partial && result == ISC_R_NOSPACE) {
		dns_compress_rollback(cctx, rrbuffer.used);
		*target = rrbuffer;
		return result;
	}
	dns_compress_rollback(cctx, savedbuffer.used);
	*countp = 0;
	*target = savedbuffer;

	return result;
}

isc_result_t
dns_rdataset_additionaldata(dns_rdataset_t *rdataset,
			    const dns_name_t *owner_name,
			    dns_additionaldatafunc_t add, void *arg,
			    size_t limit) {
	/*
	 * For each rdata in rdataset, call 'add' for each name and type in the
	 * rdata which is subject to additional section processing.
	 */

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(!rdataset->attributes.question);

	if (limit != 0 && dns_rdataset_count(rdataset) > limit) {
		return DNS_R_TOOMANYRECORDS;
	}

	DNS_RDATASET_FOREACH(rdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(rdataset, &rdata);
		RETERR(dns_rdata_additionaldata(&rdata, owner_name, add, arg));
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_rdataset_addnoqname(dns_rdataset_t *rdataset, dns_name_t *name) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	if (rdataset->methods->addnoqname == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}
	return (rdataset->methods->addnoqname)(rdataset, name);
}

isc_result_t
dns__rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
			 dns_rdataset_t *neg,
			 dns_rdataset_t *negsig DNS__DB_FLARG) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->getnoqname == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}
	return (rdataset->methods->getnoqname)(rdataset, name, neg,
					       negsig DNS__DB_FLARG_PASS);
}

isc_result_t
dns_rdataset_addclosest(dns_rdataset_t *rdataset, dns_name_t *name) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);
	if (rdataset->methods->addclosest == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}
	return (rdataset->methods->addclosest)(rdataset, name);
}

isc_result_t
dns__rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
			 dns_rdataset_t *neg,
			 dns_rdataset_t *negsig DNS__DB_FLARG) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->getclosest == NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}
	return (rdataset->methods->getclosest)(rdataset, name, neg,
					       negsig DNS__DB_FLARG_PASS);
}

void
dns_rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->settrust != NULL) {
		(rdataset->methods->settrust)(rdataset, trust);
	} else {
		rdataset->trust = trust;
	}
}

void
dns__rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->expire != NULL) {
		(rdataset->methods->expire)(rdataset DNS__DB_FLARG_PASS);
	}
}

void
dns_rdataset_clearprefetch(dns_rdataset_t *rdataset) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->clearprefetch != NULL) {
		(rdataset->methods->clearprefetch)(rdataset);
	}
}

void
dns_rdataset_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->setownercase != NULL &&
	    !rdataset->attributes.keepcase)
	{
		(rdataset->methods->setownercase)(rdataset, name);
	}
}

void
dns_rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods != NULL);

	if (rdataset->methods->getownercase != NULL &&
	    !rdataset->attributes.keepcase)
	{
		(rdataset->methods->getownercase)(rdataset, name);
	}
}

void
dns_rdataset_trimttl(dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_rdata_rrsig_t *rrsig, isc_stdtime_t now,
		     bool acceptexpired) {
	uint32_t ttl = 0;

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(DNS_RDATASET_VALID(sigrdataset));
	REQUIRE(rrsig != NULL);

	/*
	 * If we accept expired RRsets keep them for no more than 120 seconds.
	 */
	if (acceptexpired &&
	    (isc_serial_le(rrsig->timeexpire, (now + 120) & 0xffffffff) ||
	     isc_serial_le(rrsig->timeexpire, now)))
	{
		ttl = 120;
	} else if (isc_serial_ge(rrsig->timeexpire, now)) {
		ttl = rrsig->timeexpire - now;
	}

	ttl = ISC_MIN(ISC_MIN(rdataset->ttl, sigrdataset->ttl),
		      ISC_MIN(rrsig->originalttl, ttl));
	rdataset->ttl = ttl;
	sigrdataset->ttl = ttl;
}

isc_stdtime_t
dns_rdataset_minresign(dns_rdataset_t *rdataset) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_rrsig_t sig;
	int64_t when;
	isc_result_t result;

	REQUIRE(DNS_RDATASET_VALID(rdataset));

	result = dns_rdataset_first(rdataset);
	INSIST(result == ISC_R_SUCCESS);
	dns_rdataset_current(rdataset, &rdata);
	(void)dns_rdata_tostruct(&rdata, &sig, NULL);
	if ((rdata.flags & DNS_RDATA_OFFLINE) != 0) {
		when = 0;
	} else {
		when = dns_time64_from32(sig.timeexpire);
	}
	dns_rdata_reset(&rdata);

	result = dns_rdataset_next(rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(rdataset, &rdata);
		(void)dns_rdata_tostruct(&rdata, &sig, NULL);
		if ((rdata.flags & DNS_RDATA_OFFLINE) != 0) {
			goto next_rr;
		}
		if (when == 0 || dns_time64_from32(sig.timeexpire) < when) {
			when = dns_time64_from32(sig.timeexpire);
		}
	next_rr:
		dns_rdata_reset(&rdata);
		result = dns_rdataset_next(rdataset);
	}
	INSIST(result == ISC_R_NOMORE);
	return (isc_stdtime_t)when;
}
