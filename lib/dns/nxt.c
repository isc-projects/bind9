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

#include <string.h>

#include <isc/assertions.h>

#include <dns/types.h>
#include <dns/name.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatalist.h>
#include <dns/nxt.h>

#define check_result(op, msg) \
	do { result = (op); \
		if (result != DNS_R_SUCCESS) { \
			fprintf(stderr, "%s: %s\n", msg, \
				isc_result_totext(result)); \
			goto failure; \
		} \
	} while (0)

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

static unsigned int
bit_isset(unsigned char *array, unsigned int index) {
	unsigned int byte, shift, mask;
	
	byte = array[index / 8];
	shift = 7 - (index % 8);
	mask = 1 << shift;
	return ((array[index / 8] & mask) != 0);
}

isc_result_t
dns_buildnxtrdata(dns_db_t *db, dns_dbversion_t *version,
		  dns_dbnode_t *node, dns_name_t *target,
		  unsigned char *buffer, dns_rdata_t *rdata)
{
	isc_result_t result;
	dns_rdataset_t rdataset;
	isc_region_t r;
	int i;

	unsigned char *nxt_bits;
	unsigned int max_type;
	dns_rdatasetiter_t *rdsiter;

	memset(buffer, 0, DNS_NXT_BUFFERSIZE);
	dns_name_toregion(target, &r);
	memcpy(buffer, r.base, r.length);
	r.base = buffer;
	nxt_bits = r.base + r.length;
	set_bit(nxt_bits, dns_rdatatype_nxt, 1);
	max_type = dns_rdatatype_nxt;
	dns_rdataset_init(&rdataset);
	rdsiter = NULL;
	result = dns_db_allrdatasets(db, node, version, 0, &rdsiter);
	if (result != DNS_R_SUCCESS)
		return (result);
	for (result = dns_rdatasetiter_first(rdsiter);
	     result == ISC_R_SUCCESS;
	     result = dns_rdatasetiter_next(rdsiter))
	{
		dns_rdatasetiter_current(rdsiter, &rdataset);
		if (rdataset.type > 127)
			return DNS_R_RANGE; /* XXX "rdataset type too large" */
		if (rdataset.type != dns_rdatatype_nxt) {
			if (rdataset.type > max_type)
				max_type = rdataset.type;
			set_bit(nxt_bits, rdataset.type, 1);
		}
		dns_rdataset_disassociate(&rdataset);
	}

	/* At zone cuts, deny the existence of glue in the parent zone. */
	if (bit_isset(nxt_bits, dns_rdatatype_ns) &&
	    ! bit_isset(nxt_bits, dns_rdatatype_soa)) {
		for (i = 0; i < 128; i++) {
			if (bit_isset(nxt_bits, i) &&
			    ! dns_rdatatype_iszonecutauth((dns_rdatatype_t)i))
				set_bit(nxt_bits, i, 0);
		}
	}

	dns_rdatasetiter_destroy(&rdsiter);
	if (result != DNS_R_NOMORE)
		return (result);

	r.length += ((max_type + 7) / 8);
	INSIST(r.length <= DNS_NXT_BUFFERSIZE);
	dns_rdata_fromregion(rdata, 
			     dns_db_class(db),
			     dns_rdatatype_nxt,
			     &r);

	return (DNS_R_SUCCESS);
}


isc_result_t
dns_buildnxt(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
	     dns_name_t *target)
{
	isc_result_t result;
	dns_rdata_t rdata;
	unsigned char data[DNS_NXT_BUFFERSIZE];
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	
	dns_rdataset_init(&rdataset);

	result = dns_buildnxtrdata(db, version, node,
					  target, data, &rdata);
	check_result(result, "dns_buildnxtrdata");
	
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_nxt;
	rdatalist.covers = 0;
	rdatalist.ttl = 3600;			/* XXXRTH */
	ISC_LIST_INIT(rdatalist.rdata);
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);
	result = dns_rdatalist_tordataset(&rdatalist, &rdataset);
	check_result(result, "dns_rdatalist_tordataset");
	result = dns_db_addrdataset(db, node, version, 0, &rdataset,
				    0, NULL);
	if (result == DNS_R_UNCHANGED)
		result = ISC_R_SUCCESS;
	check_result(result, "dns_db_addrdataset");
 failure:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	return (result);
}
