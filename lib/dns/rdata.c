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

 /* $Id: rdata.c,v 1.17 1999/01/29 08:04:12 marka Exp $ */

#include <config.h>

#include <stdio.h>
#include <time.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/assertions.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/rdata.h>
#include <dns/region.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>

#define RETERR(x) do { \
	dns_result_t __r = (x); \
	if (__r != DNS_R_SUCCESS) \
		return (__r); \
	} while (0)

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
static dns_result_t	uint32_tobuffer(unsigned long value,
					isc_buffer_t *target);
static dns_result_t	uint16_tobuffer(unsigned long value,
					isc_buffer_t *target);
static unsigned long	uint32_fromregion(isc_region_t *region);
static unsigned short	uint16_fromregion(isc_region_t *region);
static dns_result_t	gettoken(isc_lex_t *lexer, isc_token_t *token,
				 isc_tokentype_t expect, isc_boolean_t eol);
static dns_result_t	mem_tobuffer(isc_buffer_t *target, void *base,
				     unsigned int length);
static int		compare_region(isc_region_t *r1, isc_region_t *r2);
static int		hexvalue(char value);
static dns_result_t	base64_totext(isc_region_t *source,
				      isc_buffer_t *target);
static dns_result_t	base64_tobuffer(isc_lex_t *lexer,
					isc_buffer_t *target);
static dns_result_t	time_totext(unsigned long value,
				    isc_buffer_t *target);
static dns_result_t	time_tobuffer(char *source, isc_buffer_t *target);

static const char hexdigits[] = "0123456789abcdef";
static const char decdigits[] = "0123456789";
static const char octdigits[] = "01234567";

#include "code.h"

#define META 0x0001
#define RESERVED 0x0002

#define METATYPES \
	{ 0, "NONE", META }, \
	{ 23, "NSAP-PTR", RESERVED }, \
	{ 100, "UINFO", RESERVED }, \
	{ 101, "UID", RESERVED }, \
	{ 102, "GID", RESERVED }, \
	{ 103, "UNSPEC", RESERVED }, \
	{ 249, "TKEY", META }, \
	{ 250, "TSIG", META }, \
	{ 251, "IXFR", META }, \
	{ 252, "AXFR", META }, \
	{ 253, "MAILB", META }, \
	{ 254, "MAILA", META }, \
	{ 255, "ANY", META },

#define METACLASSES \
	{ 0, "NONE", META }, \
	{ 255, "ANY", META },

struct tbl {
	int	value;
	char	*name;
	int	flags;
} types[] = { TYPENAMES METATYPES {0, NULL, 0} },
classes[] = { CLASSNAMES METACLASSES { 0, NULL, 0} };
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
	int result = 0;
	isc_boolean_t use_default = ISC_FALSE;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->data != NULL);
	REQUIRE(rdata2->data != NULL);

	if (rdata1->class != rdata2->class)
		return (rdata1->class < rdata2->class ? -1 : 1);

	if (rdata1->type != rdata2->type)
		return (rdata1->type < rdata2->type ? -1 : 1);

	COMPARESWITCH

	if (use_default) {
		isc_region_t r1;
		isc_region_t r2;

		dns_rdata_toregion(rdata1, &r1);
		dns_rdata_toregion(rdata2, &r2);
		result = compare_region(&r1, &r2);
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
	dns_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_region_t region;
	isc_buffer_t ss;
	isc_buffer_t st;
	isc_boolean_t use_default = ISC_FALSE;

	ss = *source;
	st = *target;
	region.base = (unsigned char *)(target->base) + target->used;

	FROMWIRESWITCH

	if (use_default)
		(void)NULL;

	/* We should have consumed all out buffer */
	if (result == DNS_R_SUCCESS && !buffer_empty(source))
		result = DNS_R_EXTRADATA;

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
	dns_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;
	isc_region_t tr;

	TOWIRESWITCH
	
	if (use_default) {
		isc_buffer_available(target, &tr);
		if (tr.length < rdata->length) 
			return (DNS_R_NOSPACE);
		memcpy(tr.base, rdata->data, rdata->length);
		isc_buffer_add(target, rdata->length);
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
	dns_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_region_t region;
	isc_buffer_t st;
	isc_boolean_t use_default = ISC_FALSE;
	isc_token_t token;
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			       ISC_LEXOPT_DNSMULTILINE;

	st = *target;
	region.base = (unsigned char *)(target->base) + target->used;

	FROMTEXTSWITCH

	if (use_default)
		(void)NULL;

	/*
	 * Consume to end of line / file.
	 * If not at end of line initially set error code.
	 */
	do {
		if (isc_lex_gettoken(lexer, options, &token)
		    != ISC_R_SUCCESS) {
			if (result == DNS_R_SUCCESS)
				result = DNS_R_UNEXPECTED;
			break;
		} else if (token.type != isc_tokentype_eol &&
			   token.type != isc_tokentype_eof) {
			if (result == DNS_R_SUCCESS)
				result = DNS_R_EXTRATOKEN;
		} else
			break;
	} while (1);

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
	dns_result_t result = DNS_R_NOTIMPLEMENTED;
	dns_name_t *origin = NULL;
	isc_boolean_t use_default = ISC_FALSE;
	
	TOTEXTSWITCH

	if (use_default)
		(void)NULL;

	return (result);
}

dns_result_t
dns_rdata_fromstruct(dns_rdata_t *rdata,
		     dns_rdataclass_t class, dns_rdatatype_t type,
		     void *source,
		     isc_buffer_t *target) {
	dns_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_buffer_t st;
	isc_region_t region;
	isc_boolean_t use_default = ISC_FALSE;

	region.base = (unsigned char *)(target->base) + target->used;
	st = *target;

	FROMSTRUCTSWITCH

	if (use_default)
		(void)NULL;

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
	dns_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;

	TOSTRUCTSWITCH

	if (use_default)
		(void)NULL;

	return (result);
}

dns_result_t
dns_rdataclass_fromtext(dns_rdataclass_t *classp, isc_textregion_t *source) {
	int i = 0;
	unsigned int n;

	while (classes[i].name != NULL) {
		n = strlen(classes[i].name);
		if (n == source->length &&
		    strncasecmp(source->base, classes[i].name, n) == 0) {
			*classp = classes[i].value;
			if ((classes[i].flags & RESERVED) != 0)
				return (DNS_R_NOTIMPLEMENTED);
			return (DNS_R_SUCCESS);
		}
		i++;
	}
	return (DNS_R_UNKNOWN);
}

dns_result_t
dns_rdataclass_totext(dns_rdataclass_t class, isc_buffer_t *target) {
	int i = 0;
	unsigned int n;
	isc_region_t region;

	while (classes[i].name != NULL) {
		if (classes[i].value == class) {
			isc_buffer_available(target, &region);
			if ((n = strlen(classes[i].name)) > region.length)
				return (DNS_R_NOSPACE);
			memcpy(region.base, classes[i].name, n);
			isc_buffer_add(target, n);
			return (DNS_R_SUCCESS);
		}
		i++;
	}
	return (DNS_R_UNKNOWN);
}

dns_result_t
dns_rdatatype_fromtext(dns_rdatatype_t *typep, isc_textregion_t *source) {
	int i = 0;
	unsigned int n;

	while (types[i].name != NULL) {
		n = strlen(types[i].name);
		if (n == source->length &&
		    strncasecmp(source->base, types[i].name, n) == 0) {
			*typep = types[i].value;
			if ((types[i].flags & RESERVED) != 0)
				return (DNS_R_NOTIMPLEMENTED);
			return (DNS_R_SUCCESS);
		}
		i++;
	}
	return (DNS_R_UNKNOWN);
}

dns_result_t
dns_rdatatype_totext(dns_rdatatype_t type, isc_buffer_t *target) {
	int i = 0;
	unsigned int n;
	isc_region_t region;

	while (types[i].name != NULL) {
		if (types[i].value == type) {
			isc_buffer_available(target, &region);
			if ((n = strlen(types[i].name)) > region.length)
				return (DNS_R_NOSPACE);
			memcpy(region.base, types[i].name, n);
			isc_buffer_add(target, n);
			return (DNS_R_SUCCESS);
		}
		i++;
	}
	return (DNS_R_UNKNOWN);
}

 /* Private function */

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
		return (DNS_R_TEXTTOLONG);
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

	isc_buffer_active(source, &sregion);
	if (sregion.length == 0)
		return(DNS_R_UNEXPECTEDEND);
	n = *sregion.base + 1;
	if (n > sregion.length)
		return (DNS_R_UNEXPECTEDEND);
	
	isc_buffer_available(target, &tregion);
	if (n > tregion.length)
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
	return((source->current == source->active) ? ISC_TRUE : ISC_FALSE);
}

static void
buffer_fromregion(isc_buffer_t *buffer, isc_region_t *region,
		  unsigned int type) {

	isc_buffer_init(buffer, region->base, region->length, type);
	isc_buffer_add(buffer, region->length);
	isc_buffer_setactive(buffer, region->length);
}

static dns_result_t
uint32_tobuffer(unsigned long value, isc_buffer_t *target) {
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

static dns_result_t
uint16_tobuffer(unsigned long value, isc_buffer_t *target) {
	isc_region_t region;

	if (value > 0xffff)
		return (DNS_R_RANGE);
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

static dns_result_t
gettoken(isc_lex_t *lexer, isc_token_t *token, isc_tokentype_t expect,
	 isc_boolean_t eol) {
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			       ISC_LEXOPT_DNSMULTILINE;
	
	if (expect == isc_tokentype_qstring)
		options |= ISC_LEXOPT_QSTRING;
	if (expect == isc_tokentype_number)
		options |= ISC_LEXOPT_NUMBER;
        if (isc_lex_gettoken(lexer, options, token) != ISC_R_SUCCESS)
                return (DNS_R_UNEXPECTED);
	if (eol && ((token->type == isc_tokentype_eol) || 
		    (token->type == isc_tokentype_eof)))
		return (DNS_R_SUCCESS);
	if (token->type == isc_tokentype_string &&
	    expect == isc_tokentype_qstring)
		return (DNS_R_SUCCESS);
        if (token->type != expect) {
                isc_lex_ungettoken(lexer, token);
                if (token->type == isc_tokentype_eol ||
                    token->type == isc_tokentype_eof)
                        return(DNS_R_UNEXPECTEDEND);
                return (DNS_R_UNEXPECTED);
        }
	return (DNS_R_SUCCESS);
}

static dns_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	isc_buffer_available(target, &tr);
        if (length > tr.length)
		return (DNS_R_NOSPACE);
	memcpy(tr.base, base, length);
	isc_buffer_add(target, length);
	return (DNS_R_SUCCESS);
}

static int
compare_region(isc_region_t *r1, isc_region_t *r2) {
	unsigned int l;
	int result;

	l = (r1->length < r2->length) ? r1->length : r2->length;

	if ((result = memcmp(r1->base, r2->base, l)) != 0)
		return ((result < 0) ? -1 : 1);
	else
		return ((r1->length < r2->length) ? -1 : 1);
}

static int
hexvalue(char value) {
	char *s;
	if (!isascii(value&0xff))
		return (-1);
	if (isupper(value))
		value = tolower(value);
	if ((s = strchr(hexdigits, value)) == NULL)
		return (-1);
	return (s - hexdigits);
}

static const char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

static dns_result_t
base64_totext(isc_region_t *source, isc_buffer_t *target) {
	char buf[5];
	int loops = 0;

	memset(buf, 0, sizeof buf);
	RETERR(str_totext("( " /*)*/, target));
	while (source->length > 2) {
		buf[0] = base64[(source->base[0]>>2)&0x3f];
		buf[1] = base64[((source->base[0]<<4)&0x30)|
				((source->base[1]>>4)&0x0f)];
		buf[2] = base64[((source->base[1]<<2)&0x3c)|
				((source->base[2]>>6)&0x03)];
		buf[3] = base64[source->base[2]&0x3f];
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 3);
		if (source->length != 0 && ++loops == 15) {
			loops = 0;
			RETERR(str_totext(" ", target));
		}
	}
	if (source->length == 2) {
		buf[0] = base64[(source->base[0]>>2)&0x3f];
		buf[1] = base64[((source->base[0]<<4)&0x30)|
				((source->base[1]>>4)&0x0f)];
		buf[2] = base64[((source->base[1]<<4)&0x3c)];
		buf[3] = '=';
		RETERR(str_totext(buf, target));
	} else if (source->length == 1) {
		buf[0] = base64[(source->base[0]>>2)&0x3f];
		buf[1] = base64[((source->base[0]<<4)&0x30)];
		buf[2] = buf[3] = '=';
		RETERR(str_totext(buf, target));
	}
	RETERR(str_totext(" )", target));
	return (DNS_R_SUCCESS);
}

static dns_result_t
base64_tobuffer(isc_lex_t *lexer, isc_buffer_t *target) {
	int digits = 0;
	isc_textregion_t *tr;
	int val[4];
	unsigned char buf[3];
	int seen_end = 0;
	unsigned int i;
	isc_token_t token;
	char *s;
	int n;

	
	while (1) {
		RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_TRUE));
		if (token.type != isc_tokentype_string)
			break;
		tr = &token.value.as_textregion;
		for (i = 0 ;i < tr->length; i++) {
			if (seen_end)
				return (DNS_R_SYNTAX);
			if ((s = strchr(base64, tr->base[i])) == NULL)
				return (DNS_R_SYNTAX);
			val[digits++] = s - base64;
			if (digits == 4) {
				if (val[1] == 64 || val[2] == 64)
					return (DNS_R_SYNTAX);
				if (val[2] == 64 && val[3] != 64)
					return (DNS_R_SYNTAX);
				n = (val[2] == 64) ? 1 :
				    (val[3] == 64) ? 2 : 3;
				if (n != 3) {
					seen_end = 1;
					if (val[2] == 64)
						val[2] = 0;
					if (val[3] == 64)
						val[3] = 0;
				}
				buf[0] = (val[0]<<2)|(val[1]>>4);
				buf[1] = (val[1]<<4)|(val[2]>>2);
				buf[2] = (val[2]<<6)|(val[3]);
				RETERR(mem_tobuffer(target, buf, n));
				digits = 0;
			}
		}
	}
	isc_lex_ungettoken(lexer, &token);
	if (digits)
		return (DNS_R_SYNTAX);
	return (DNS_R_SUCCESS);
}

static int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static dns_result_t
time_totext(unsigned long value, isc_buffer_t *target) {
	long long start;
	long long base;
	long long t;
	struct tm tm;
	char buf[sizeof "YYYYMMDDHHMMSS"];
	int secs;

	/* find the right epoch */
	start = time(NULL);
	start -= 0x7fffffff;
	base = 0;
	while ((t = (base + value)) < start) {
		base += 0x80000000;
		base += 0x80000000;
	}

#define is_leap(y) ((((y) % 4) == 0 && ((y) % 100) != 0) || ((y) % 400) == 0)
#define year_secs(y) ((is_leap(y) ? 366 : 365 ) * 86400)
#define month_secs(m, y) ((days[m] + ((m == 1 && is_leap(y)) ? 1 : 0 )) * 86400)


	tm.tm_year = 70;
	while ((secs = year_secs(tm.tm_year + 1900 + 1)) <= t) {
		t -= secs;
		tm.tm_year++;
	}
	tm.tm_mon = 0;
	while ((secs = month_secs(tm.tm_mon, tm.tm_year + 1900)) <= t) {
		t -= secs;
		tm.tm_mon++;
	}
	tm.tm_mday = 1;
	while (86400 <= t) {
		t -= 86400;
		tm.tm_mday++;
	}
	tm.tm_hour = 0;
	while (3600 <= t) {
		t -= 3600;
		tm.tm_hour++;
	}
	tm.tm_min = 0;
	while (60 <= t) {
		t -= 60;
		tm.tm_min++;
	}
	tm.tm_sec = t;
		    /* yy  mm  dd  HH  MM  SS */
	sprintf(buf, "%04d%02d%02d%02d%02d%02d",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	return (str_totext(buf, target));
}

static dns_result_t
time_tobuffer(char *source, isc_buffer_t *target) {
	int year, month, day, hour, minute, second;
	unsigned long value;
	int secs;
	int i;

#define RANGE(min, max, value) \
	do { \
		if (value < (min) || value > (max)) \
			return (DNS_R_RANGE); \
	} while (0)

	if (strlen(source) != 14)
		return (DNS_R_SYNTAX);
	if (sscanf(source, "%4d%2d%2d%2d%2d%2d",
		   &year, &month, &day, &hour, &minute, &second) != 6)
		return (DNS_R_SYNTAX);

	RANGE(1970, 9999, year);
	RANGE(1, 12, month);
	RANGE(1, days[month - 1] +
		 ((month == 2 && is_leap(year)) ? 1 : 0), day);
	RANGE(0, 23, hour);
	RANGE(0, 59, minute);
	RANGE(0, 60, second);	/* leap second */

	/* calulate seconds since epoch */
	value = second + (60 * minute) + (3600 * hour) + ((day - 1) * 86400);
	for (i = 0; i < (month - 1) ; i++)
		value += days[i] * 86400;
	if (is_leap(year) && month > 2)
		value += 86400;
	for (i = 1970; i < year; i++) {
		secs = (is_leap(i) ? 366 : 365) * 86400;
		value += secs;
	}
	
	return (uint32_tobuffer(value, target));
}
