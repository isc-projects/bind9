/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: opt.c,v 1.4 2000/10/25 04:26:42 marka Exp $ */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/ncache.h>
#include <dns/opt.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/result.h>

#define ADD_STRING(b, s, g)        {if (strlen(s) >= \
                                   isc_buffer_availablelength(b)) \
                                       { result = ISC_R_NOSPACE; \
                                         goto g; } else \
                                       isc_buffer_putstr(b, s);}
static isc_result_t
optget(dns_optlist_t *optlist, dns_rdataset_t *optset,
       isc_uint16_t code, isc_boolean_t getall)
{
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	unsigned int location;
	isc_region_t rdataregion;
	isc_buffer_t rdatabuf;
	isc_uint16_t thiscode, thislength;

	REQUIRE(DNS_RDATASET_VALID(optset));
	REQUIRE(optset->type == dns_rdatatype_opt);

	result = dns_rdataset_first(optset);
	if (result != ISC_R_SUCCESS)
		return(result);
	dns_rdataset_current(optset, &rdata);

	dns_rdata_toregion(&rdata, &rdataregion);
	isc_buffer_init(&rdatabuf, rdataregion.base, rdataregion.length);
	isc_buffer_add(&rdatabuf, rdataregion.length);

	optlist->used = 0;
	location = 0;
	/*
	 * We don't do the test in the while loop, since I want to
	 * actually keep searching the list for more data until I reach
	 * the first one I *can't* fit in.  This way, I can correctly
	 * decide between MOREDATA and SUCCESS.
	 */
	while (1) {
		if (isc_buffer_remaininglength(&rdatabuf) == 0) {
			optlist->next = 0;
			return (ISC_R_SUCCESS);
		}
		if (isc_buffer_remaininglength(&rdatabuf) < 4)
			return (ISC_R_UNEXPECTEDEND);
		thiscode = isc_buffer_getuint16(&rdatabuf);
		thislength = isc_buffer_getuint16(&rdatabuf);
		if (isc_buffer_remaininglength(&rdatabuf) < thislength)
			return (ISC_R_UNEXPECTEDEND);
		if ((thiscode == code || getall) &&
		    (location >= optlist->next)) {
			if (optlist->used >= optlist->size) {
				optlist->next = location;
				return(DNS_R_MOREDATA);
			}
			optlist->attrs[optlist->used].code = thiscode;
			optlist->attrs[optlist->used].value.base = 
				isc_buffer_current(&rdatabuf);
			optlist->attrs[optlist->used].value.length =
				thislength;
			optlist->used++;
		}
		isc_buffer_forward(&rdatabuf, thislength);
		location++;
	}
	/* This location can never be reached. */
}

isc_result_t
dns_opt_decode(dns_optlist_t *optlist, dns_rdataset_t *optset,
	       isc_uint16_t code)
{
	return (optget(optlist, optset, code, ISC_FALSE));
}

isc_result_t
dns_opt_decodeall(dns_optlist_t *optlist, dns_rdataset_t *optset) {
	return (optget(optlist, optset, 0, ISC_TRUE));
}

isc_result_t
dns_opt_add(dns_rdata_t *rdata, dns_optlist_t *optlist,
	    isc_buffer_t *target)
{
	unsigned char *base;
	unsigned int i;

	REQUIRE(rdata->length == 0);

	base = isc_buffer_current(target);
	if (optlist != NULL) {
		for (i = 0; i < optlist->used; i++) {
			rdata->length += optlist->attrs[i].value.length;
			rdata->length += 4;
		}
		if (isc_buffer_availablelength(target) < rdata->length) {
			rdata->length = 0;
			return (ISC_R_NOSPACE);
		}
		for (i = 0; i < optlist->used; i++) {
			isc_buffer_putuint16(target, optlist->attrs[i].code);
			isc_buffer_putuint16(target,
					     optlist->attrs[i].value.length);
			isc_buffer_putmem(target,
					  optlist->attrs[i].value.base,
					  optlist->attrs[i].value.length);
		}
		rdata->data = base;
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_opt_attrtotext(dns_optattr_t *attr, isc_buffer_t *target,
		   dns_messagetextflag_t flags) {
	isc_result_t result = ISC_R_SUCCESS;
	char store[sizeof("012345678")];
	isc_boolean_t omit_final_dot;
#ifdef DNS_OPT_NEWCODES
	dns_decompress_t dctx;
	dns_fixedname_t fname;
	isc_buffer_t source;

#else /* DNS_OPT_NEWCODES */
	UNUSED (flags);
#endif /* DNS_OPT_NEWCODES */

	omit_final_dot = ISC_TF((flags & DNS_MESSAGETEXTFLAG_OMITDOT) != 0);
	switch (attr->code) {
#ifdef DNS_OPT_NEWCODES
	case DNS_OPTCODE_ZONE:
		ADD_STRING(target, "; ZONE attribute: ", zonefail0);
		dns_fixedname_init(&fname);
		dns_decompress_init(&dctx, 0, ISC_FALSE);
		isc_buffer_init(&source, attr->value.base, attr->value.length);
		isc_buffer_add(&source, attr->value.length);
		isc_buffer_setactive(&source, attr->value.length);
		result = dns_name_fromwire(&fname.name, &source, &dctx,
					   ISC_FALSE, NULL);
		if (result != ISC_R_SUCCESS)
			goto zonefail1;
		result = dns_name_totext(&fname.name, omit_final_dot,
					 target);
		ADD_STRING(target, "\n", zonefail1);
	zonefail1:
		dns_decompress_invalidate(&dctx);
		dns_fixedname_invalidate(&fname);
	zonefail0:
		return (result);
	case DNS_OPTCODE_VIEW:
		ADD_STRING(target, "; VIEW attribute: ", viewfail0);
		if (attr->value.length >= isc_buffer_availablelength(target))
			return(ISC_R_NOSPACE);
		else
			isc_buffer_putmem(target, attr->value.base,
					  attr->value.length);
		ADD_STRING(target, "\n", viewfail0);
        viewfail0:
		return (result);
#endif /* DNS_OPT_NEWCODES */
	/*
	 * This routine is a placekeeper, awaiting assignment of
	 * OPT attribute values from IANA.
	 */
	default:
		ADD_STRING(target, "; Unknown EDNS attribute ", deffail);
		sprintf(store,"%d",attr->code);
		ADD_STRING(target, store, deffail);
		ADD_STRING(target, "\n", deffail);
		result = DNS_R_UNKNOWNOPT;
	deffail:
		return (result);
	}
}

isc_result_t
dns_opt_totext(dns_rdataset_t *opt, isc_buffer_t *target, 
	       dns_messagetextflag_t flags) {
	isc_result_t result, iresult;
	char buf[sizeof("1234567890")];
	isc_boolean_t omit_final_dot;
	dns_optattr_t attr;
	dns_optlist_t list;

	REQUIRE(DNS_RDATASET_VALID(opt));
	REQUIRE(target != NULL);

	omit_final_dot = ISC_TF((flags & DNS_MESSAGETEXTFLAG_OMITDOT) != 0);

	if ((flags & DNS_MESSAGETEXTFLAG_NOCOMMENTS) == 0)
		ADD_STRING(target, ";; OPT PSEUDOSECTION:\n", fail);
	ADD_STRING(target, "; EDNS: version: ", fail);
	sprintf(buf, "%4u",
		(unsigned int)((opt->ttl &
				0x00ff0000 >> 16)));
	ADD_STRING(target, buf, fail);
	ADD_STRING(target, ", udp=", fail);
	sprintf(buf, "%7u\n",
		(unsigned int)opt->rdclass);
	ADD_STRING(target, buf, fail);

	list.attrs = &attr;
	list.size = 1;
	list.used = 0;
	list.next = 0;
	do {
		result = dns_opt_decodeall(&list, opt);
		if ((result == ISC_R_SUCCESS || result == DNS_R_MOREDATA)
		    && list.used != 0) {
			iresult = dns_opt_attrtotext(list.attrs, target,
						    flags);
			if (iresult != ISC_R_SUCCESS &&
			    iresult != DNS_R_UNKNOWNOPT)
				result = iresult;
		}
	} while (result == DNS_R_MOREDATA);
 fail:
	return (result);
}
