/*
 * Copyright (C) 1998  Internet Software Consortium.
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

#include <isc/buffer.h>
#include <isc/lex.h>
#include <dns/types.h>
#include <dns/result.h>
#include <dns/rdata.h>
#include <dns/region.h>
#include <stdio.h>
#include <isc/assertions.h>

static dns_result_t	txt_totext(isc_region_t *source, isc_buffer_t *target);
static dns_result_t	txt_fromtext(isc_textregion_t *source,
				     isc_buffer_t *target);
static dns_result_t	txt_fromwire(isc_buffer_t *source,
				    isc_buffer_t *target);
static isc_boolean_t	name_prefix(dns_name_t *name, dns_name_t *origin,
				    dns_name_t *target);
static unsigned int 	name_length(dns_name_t *name);
static dns_result_t	str_totext(char *source, isc_buffer_t *target);
static isc_boolean_t	buffer_empty(isc_buffer_t *source);
static void		buffer_fromregion(isc_buffer_t *buffer,
					  isc_region_t *region,
					  unsigned int type);
static isc_result_t	uint32_fromtext(unsigned long value,
					isc_buffer_t *target);
static isc_result_t	uint16_fromtext(unsigned long value,
					isc_buffer_t *target);
static unsigned long	uint32_fromregion(isc_region_t *region);
static unsigned short	uint16_fromregion(isc_region_t *region);

#include "code.h"

/***
 *** Initialization
 ***/

void
dns_rdata_init(dns_rdata_t *rdata) {

	REQUIRE(rdata != NULL);

	rdata->data = NULL;
	rdata->length = 0;
	rdata->class = 0;
	rdata->type = 0;
	ISC_LINK_INIT(rdata, link);
	/* ISC_LIST_INIT(rdata->list); */
}

/***
 *** Comparisons
 ***/

int
dns_rdata_compare(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	int result;
	int l;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->data != NULL);
	REQUIRE(rdata2->data != NULL);

	if (rdata1->class != rdata2->class)
		return (rdata1->class < rdata2->class ? -1 : 1);

	if (rdata1->type != rdata2->type)
		return (rdata1->type < rdata2->type ? -1 : 1);

	COMPARESWITCH

	if (result == -2) {
		l = (rdata1->length > rdata2->length) ?
			rdata1->length : rdata2->length;
		if ((result = memcmp(rdata1->data, rdata2->data, l)) == 0)
			result = (result < 0) ? -1 : 1;
		else
			result = (rdata1->length < rdata2->length) ? -1 : 1;
	}
	return (result);
}

/***
 *** Conversions
 ***/

void
dns_rdata_fromregion(dns_rdata_t *rdata,
			  dns_rdataclass_t class, dns_rdatatype_t type,
			  isc_region_t *r) {
			  
	rdata->data = r->base;
	rdata->length = r->length;
	rdata->class = class;
	rdata->type = type;
}

void
dns_rdata_toregion(dns_rdata_t *rdata, isc_region_t *r) {

	r->base = rdata->data;
	r->length = rdata->length;
}

dns_result_t
dns_rdata_fromwire(dns_rdata_t *rdata,
		   dns_rdataclass_t class, dns_rdatatype_t type,
		   isc_buffer_t *source,
		   dns_decompress_t *dctx,
		   isc_boolean_t downcase,
		   isc_buffer_t *target) {
	dns_result_t result;
	isc_region_t region;
	isc_buffer_t ss;
	isc_buffer_t st;

	ss = *source;
	st = *target;
	region.base = target->base + target->used;

	FROMWIRESWITCH

	if (result == DNS_R_DEFAULT)
		result = DNS_R_NOTIMPLEMENTED;

	/* We should have consumed all out buffer */
	if (!buffer_empty(source))
		result = DNS_R_WIRE;

	if (rdata && result == DNS_R_SUCCESS) {
		region.length = target->used - st.used;
		dns_rdata_fromregion(rdata, class, type, &region);
	}

	if (result != DNS_R_SUCCESS) {
		*source = ss;
		*target = st;
	}
	return (result);
}

dns_result_t
dns_rdata_towire(dns_rdata_t *rdata, dns_compress_t *cctx,
	         isc_buffer_t *target) {
	dns_result_t result;

	TOWIRESWITCH
	
	if (result == DNS_R_DEFAULT) {
		if (target->length < rdata->length) 
			return (DNS_R_NOSPACE);
		memcpy(target->base, rdata->data, rdata->length);
		target->length = rdata->length;
		return (DNS_R_SUCCESS);
	}
	return (result);
}

dns_result_t
dns_rdata_fromtext(dns_rdata_t *rdata,
		   dns_rdataclass_t class, dns_rdatatype_t type,
		   isc_lex_t *lexer, dns_name_t *origin,
		   isc_boolean_t downcase,
		   isc_buffer_t *target) {
	dns_result_t result;
	isc_region_t region;
	isc_buffer_t st;

	st = *target;
	region.base = target->base + target->used;

	FROMTEXTSWITCH

	if (result == DNS_R_DEFAULT)
		result = DNS_R_NOTIMPLEMENTED;

	if (rdata != NULL && result == DNS_R_SUCCESS) {
		region.length = target->used - st.used;
		dns_rdata_fromregion(rdata, class, type, &region);
	}
	if (result != DNS_R_SUCCESS) {
		*target = st;
	}
	return (result);
}

dns_result_t
dns_rdata_totext(dns_rdata_t *rdata, isc_buffer_t *target) {
	dns_result_t result;
	dns_name_t *origin = NULL;
	
	TOTEXTSWITCH

	if (result == DNS_R_DEFAULT)
		result = DNS_R_NOTIMPLEMENTED;
	return (result);
}

dns_result_t
dns_rdata_fromstruct(dns_rdata_t *rdata,
		     dns_rdataclass_t class, dns_rdatatype_t type,
		     void *source,
		     isc_buffer_t *target) {
	dns_result_t result;
	isc_buffer_t st;
	isc_region_t region;

	region.base = target->base + target->used;
	st = *target;

	FROMSTRUCTSWITCH

	if (result == DNS_R_DEFAULT)
		result = DNS_R_NOTIMPLEMENTED;

	if (rdata != NULL && result == DNS_R_SUCCESS) {
		region.length = target->used - st.used;
		dns_rdata_fromregion(rdata, class, type, &region);
	}
	if (result != DNS_R_SUCCESS)
		*target = st;
	return (result);
}

dns_result_t
dns_rdata_tostruct(dns_rdata_t *rdata, void *target) {
	dns_result_t result;

	TOSTRUCTSWITCH

	if (result == DNS_R_DEFAULT)
		result = DNS_R_NOTIMPLEMENTED;
	return (result);
}

static unsigned int
name_length(dns_name_t *name) {
	return (name->length);
}

static dns_result_t
txt_totext(isc_region_t *source, isc_buffer_t *target) {
	unsigned int tl;
	unsigned int n;
	unsigned char *sp;
	unsigned char *tp;
	isc_region_t region;

	isc_buffer_available(target, &region);
	sp = source->base;
	tp = region.base;
	tl = region.length;

	n = *sp++;

	INSIST(n + 1 <= source->length);

	if (tl < 1)
		return (DNS_R_NOSPACE);
	*tp++ = '"';
	tl--;
	while (n--) {
		if (*sp < 0x20 || *sp > 0x7f) {
			if (tl < 4)
				return (DNS_R_NOSPACE);
			sprintf(tp, "\\%03u", *sp++);
			tp += 4;
			tl -= 4;
			continue;
		}
		if (*sp == 0x22 || *sp == 0x3b || *sp == 0x5c) {
			if (tl < 2)
				return (DNS_R_NOSPACE);
			*tp++ = '\\';
			tl--;
		}
		if (tl < 1)
			return (DNS_R_NOSPACE);
		*tp++ = *sp++;
		tl--;
	}
	if (tl < 1)
		return (DNS_R_NOSPACE);
	*tp++ = '"';
	tl--;
	isc_buffer_add(target, tp - region.base);
	isc_region_consume(source, *source->base + 1);
	return (DNS_R_SUCCESS);
}

static dns_result_t
txt_fromtext(isc_textregion_t *source, isc_buffer_t *target) {
	isc_region_t tregion;

	isc_buffer_available(target, &tregion);
	if (tregion.length < source->length + 1)
		return (DNS_R_NOSPACE);
	if (source->length > 255)
		return (DNS_R_UNKNOWN);
	*tregion.base = source->length;
	memcpy(tregion.base + 1, source->base, source->length);
	isc_buffer_add(target, source->length + 1);
	return (DNS_R_SUCCESS);
}

static dns_result_t
txt_fromwire(isc_buffer_t *source, isc_buffer_t *target) {
	unsigned int n;
	isc_region_t sregion;
	isc_region_t tregion;

	isc_buffer_remaining(source, &sregion);
	n = *sregion.base + 1;
	if (n > sregion.length)
		return (DNS_R_UNKNOWN);
	
	isc_buffer_available(target, &tregion);
	if (n < tregion.length)
		return (DNS_R_NOSPACE);

	memcpy(tregion.base, sregion.base, n);
	isc_buffer_forward(source, n);
	isc_buffer_add(target, n);
	return (DNS_R_SUCCESS);
}

static isc_boolean_t
name_prefix(dns_name_t *name, dns_name_t *origin, dns_name_t *target) {
	int l1, l2;

	if (origin == NULL)
		goto return_false;

	if (dns_name_compare(origin, dns_rootname) == 0)
		goto return_false;

	if (!dns_name_issubdomain(name, origin))
		goto return_false;

	l1 = dns_name_countlabels(name);
	l2 = dns_name_countlabels(origin);
	
	if (l1 == l2)
		goto return_false;

	dns_name_getlabelsequence(name, 0, l1 - l2, target);
	return (ISC_TRUE);

return_false:
	*target = *name;
	return (ISC_FALSE);
}

static dns_result_t
str_totext(char *source, isc_buffer_t *target) {
	unsigned int l;
	isc_region_t region;

	isc_buffer_available(target, &region);
	l = strlen(source);

	if (l > region.length)
		return (DNS_R_NOSPACE);

	memcpy(region.base, source, l);
	isc_buffer_add(target, l);
	return (DNS_R_SUCCESS);
}

static isc_boolean_t
buffer_empty(isc_buffer_t *source) {
	return((source->current == source->used) ? ISC_TRUE : ISC_FALSE);
}

static void
buffer_fromregion(isc_buffer_t *buffer, isc_region_t *region,
		  unsigned int type) {

	isc_buffer_init(buffer, region->base, region->length, type);
	isc_buffer_add(buffer, region->length);
}

static isc_result_t
uint32_fromtext(unsigned long value, isc_buffer_t *target) {
	isc_region_t region;

	isc_buffer_available(target, &region);
	if (region.length < 4)
		return (DNS_R_NOSPACE);
	region.base[0] = (value >> 24) & 0xff;
	region.base[1] = (value >> 16) & 0xff;
	region.base[2] = (value >> 8) & 0xff;
	region.base[3] = value & 0xff;
	isc_buffer_add(target, 4);
	return (DNS_R_SUCCESS);
}

static isc_result_t
uint16_fromtext(unsigned long value, isc_buffer_t *target) {
	isc_region_t region;

	isc_buffer_available(target, &region);
	if (region.length < 2)
		return (DNS_R_NOSPACE);
	region.base[0] = (value >> 8) & 0xff;
	region.base[1] = value & 0xff;
	isc_buffer_add(target, 2);
	return (DNS_R_SUCCESS);
}

static unsigned long
uint32_fromregion(isc_region_t *region) {
	unsigned long value;
	
	INSIST(region->length >= 4);
	value = region->base[0] << 24;
	value |= region->base[1] << 16;
	value |= region->base[2] << 8;
	value |= region->base[3];
	return(value);
}

static unsigned short
uint16_fromregion(isc_region_t *region) {
	
	INSIST(region->length >= 2);

	return ((region->base[0] << 8) | region->base[1]);
}
