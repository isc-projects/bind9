/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

/* $Id: rdata.c,v 1.72 2000/03/22 17:28:57 gson Exp $ */

#include <config.h>

#include <stdarg.h>
#include <stdio.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/region.h>
#include <isc/util.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rcode.h>
#include <dns/cert.h>
#include <dns/secalg.h>
#include <dns/secproto.h>
#include <dns/keyflags.h>
#include <dns/fixedname.h>
#include <dns/rdatastruct.h>
#include <dns/time.h>
#include <dns/ttl.h>

#define RETERR(x) do { \
	isc_result_t __r = (x); \
	if (__r != DNS_R_SUCCESS) \
		return (__r); \
	} while (0)

/*
 * Context structure for the totext_ functions.  
 * Contains formatting options for rdata-to-text
 * conversion.
 */
typedef struct dns_rdata_textctx {
	dns_name_t *origin;	/* Current origin, or NULL. */
	unsigned int flags;	/* DNS_STYLEFLAG_* */
	unsigned int width;	/* Width of rdata column. */
  	char *linebreak;	/* Line break string. */
} dns_rdata_textctx_t;

static isc_result_t	txt_totext(isc_region_t *source, isc_buffer_t *target);
static isc_result_t	txt_fromtext(isc_textregion_t *source,
				     isc_buffer_t *target);
static isc_result_t	txt_fromwire(isc_buffer_t *source,
				    isc_buffer_t *target);
static isc_boolean_t	name_prefix(dns_name_t *name, dns_name_t *origin,
				    dns_name_t *target);
static unsigned int 	name_length(dns_name_t *name);
static isc_result_t	str_totext(char *source, isc_buffer_t *target);
static isc_boolean_t	buffer_empty(isc_buffer_t *source);
static void		buffer_fromregion(isc_buffer_t *buffer,
					  isc_region_t *region,
					  unsigned int type);
static isc_result_t	uint32_tobuffer(isc_uint32_t,
					isc_buffer_t *target);
static isc_result_t	uint16_tobuffer(isc_uint32_t,
					isc_buffer_t *target);
static isc_result_t	uint8_tobuffer(isc_uint32_t value,
				       isc_buffer_t *target);
static isc_uint32_t	uint32_fromregion(isc_region_t *region);
static isc_uint16_t	uint16_fromregion(isc_region_t *region);
static isc_uint8_t	uint8_fromregion(isc_region_t *region);
static isc_result_t	gettoken(isc_lex_t *lexer, isc_token_t *token,
				 isc_tokentype_t expect, isc_boolean_t eol);
static isc_result_t	mem_tobuffer(isc_buffer_t *target, void *base,
				     unsigned int length);
static int		compare_region(isc_region_t *r1, isc_region_t *r2);
static int		hexvalue(char value);
static int		decvalue(char value);
static isc_result_t	btoa_totext(unsigned char *inbuf, int inbuflen,
				    isc_buffer_t *target);
static isc_result_t	atob_tobuffer(isc_lex_t *lexer, isc_buffer_t *target);
static void		default_fromtext_callback(
					    dns_rdatacallbacks_t *callbacks,
						  char *, ...);

static void		fromtext_error(void (*callback)(dns_rdatacallbacks_t *,
							char *, ...),
				       dns_rdatacallbacks_t *callbacks,
				       char *name, int line,
				       isc_token_t *token,
				       isc_result_t result);

static isc_result_t	 rdata_totext(dns_rdata_t *rdata,
				      dns_rdata_textctx_t *tctx,
				      isc_buffer_t *target);

static const char hexdigits[] = "0123456789abcdef";
static const char decdigits[] = "0123456789";
static const char octdigits[] = "01234567";

#include "code.h"

#define META 0x0001
#define RESERVED 0x0002

#define METATYPES \
	{ 0, "RESERVED0", META }, \
	{ 31, "EID", RESERVED }, \
	{ 32, "NIMLOC", RESERVED }, \
	{ 34, "ATMA", RESERVED }, \
	{ 100, "UINFO", RESERVED }, \
	{ 101, "UID", RESERVED }, \
	{ 102, "GID", RESERVED }, \
	{ 249, "TKEY", META }, \
	{ 250, "TSIG", META }, \
	{ 251, "IXFR", META }, \
	{ 252, "AXFR", META }, \
	{ 253, "MAILB", META }, \
	{ 254, "MAILA", META }, \
	{ 255, "ANY", META },

/*
 * Empty classes are those without any types of their own.
 */
#define EMPTYCLASSES \
	{ 3, "CHAOS", 0 },

#define METACLASSES \
	{ 0, "RESERVED0", META }, \
	{ 254, "NONE", META }, \
	{ 255, "ANY", META },

#define RCODENAMES \
	/* standard rcodes */ \
	{ dns_rcode_noerror, "NOERROR", 0}, \
	{ dns_rcode_formerr, "FORMERR", 0}, \
	{ dns_rcode_servfail, "SERVFAIL", 0}, \
	{ dns_rcode_nxdomain, "NXDOMAIN", 0}, \
	{ dns_rcode_notimp, "NOTIMP", 0}, \
	{ dns_rcode_refused, "REFUSED", 0}, \
	{ dns_rcode_yxdomain, "YXDOMAIN", 0}, \
	{ dns_rcode_yxrrset, "YXRRSET", 0}, \
	{ dns_rcode_nxrrset, "NXRRSET", 0}, \
	{ dns_rcode_notauth, "NOTAUTH", 0}, \
	{ dns_rcode_notzone, "NOTZONE", 0}, \
	/* extended rcodes */ \
	{ dns_rcode_badvers, "BADVERS", 0}, \
	{ 0, NULL, 0 }

#define CERTNAMES \
	{ 1, "SKIX", 0}, \
	{ 2, "SPKI", 0}, \
	{ 3, "PGP", 0}, \
	{ 253, "URI", 0}, \
	{ 254, "OID", 0}, \
	{ 0, NULL, 0}

/* RFC2535 section 7 */

#define SECALGNAMES \
	{ 1, "RSAMD5", 0 }, \
	{ 2, "DH", 0 }, \
	{ 3, "DSA", 0 }, \
	{ 4, "ECC", 0 }, \
	{ 252, "INDIRECT", 0 }, \
	{ 253, "PRIVATEDNS", 0 }, \
	{ 254, "PRIVATEOID", 0 }, \
	{ 0, NULL, 0}

/* RFC2535 section 7.1 */

#define SECPROTONAMES \
	{   0,    "NONE", 0 }, \
	{   1,    "TLS", 0 }, \
	{   2,    "EMAIL", 0 }, \
	{   3,    "DNSSEC", 0 }, \
	{   4,    "IPSEC", 0 }, \
	{ 255,    "ALL", 0 }, \
	{ 0, NULL, 0}

static struct tbl {
	unsigned int	value;
	char	*name;
	int	flags;
} types[] = { TYPENAMES METATYPES {0, NULL, 0} },
classes[] = { METACLASSES CLASSNAMES EMPTYCLASSES { 0, NULL, 0} },
rcodes[] = { RCODENAMES },
certs[] = { CERTNAMES },
secalgs[] = { SECALGNAMES },
secprotos[] = { SECPROTONAMES };

static struct keyflag {
	char *name;
	unsigned int value;
	unsigned int mask;
} keyflags[] = {
	{ "NOCONF", 0x4000, 0xC000 },
	{ "NOAUTH", 0x8000, 0xC000 },
	{ "NOKEY",  0xC000, 0xC000 },
	{ "FLAG2",  0x2000, 0x2000 },
	{ "EXTEND", 0x1000, 0x1000 },
	{ "FLAG4",  0x0800, 0x0800 },
	{ "FLAG5",  0x0400, 0x0400 },
	{ "USER",   0x0000, 0x0300 },
	{ "ZONE",   0x0100, 0x0300 },
	{ "HOST",   0x0200, 0x0300 },
	{ "NTYP3",  0x0300, 0x0300 },
	{ "FLAG8",  0x0080, 0x0080 },
	{ "FLAG9",  0x0040, 0x0040 },
	{ "FLAG10", 0x0020, 0x0020 },
	{ "FLAG11", 0x0010, 0x0010 },
	{ "SIG0",   0x0000, 0x000F },
	{ "SIG1",   0x0001, 0x000F },
	{ "SIG2",   0x0002, 0x000F },
	{ "SIG3",   0x0003, 0x000F },
	{ "SIG4",   0x0004, 0x000F },
	{ "SIG5",   0x0005, 0x000F },
	{ "SIG6",   0x0006, 0x000F },
	{ "SIG7",   0x0007, 0x000F },
	{ "SIG8",   0x0008, 0x000F },
	{ "SIG9",   0x0009, 0x000F },
	{ "SIG10",  0x000A, 0x000F },
	{ "SIG11",  0x000B, 0x000F },
	{ "SIG12",  0x000C, 0x000F },
	{ "SIG13",  0x000D, 0x000F },
	{ "SIG14",  0x000E, 0x000F },
	{ "SIG15",  0x000F, 0x000F },
	{ NULL,     0, 0 } 
};

/***
 *** Initialization
 ***/

void
dns_rdata_init(dns_rdata_t *rdata) {

	REQUIRE(rdata != NULL);

	rdata->data = NULL;
	rdata->length = 0;
	rdata->rdclass = 0;
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

	if (rdata1->rdclass != rdata2->rdclass)
		return (rdata1->rdclass < rdata2->rdclass ? -1 : 1);

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
dns_rdata_fromregion(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, isc_region_t *r)
{
			  
	REQUIRE(rdata != NULL);
	REQUIRE(r != NULL);

	rdata->data = r->base;
	rdata->length = r->length;
	rdata->rdclass = rdclass;
	rdata->type = type;
}

void
dns_rdata_toregion(dns_rdata_t *rdata, isc_region_t *r) {

	REQUIRE(rdata != NULL);
	REQUIRE(r != NULL);

	r->base = rdata->data;
	r->length = rdata->length;
}

isc_result_t
dns_rdata_fromwire(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, isc_buffer_t *source,
		   dns_decompress_t *dctx, isc_boolean_t downcase,
		   isc_buffer_t *target)
{
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_region_t region;
	isc_buffer_t ss;
	isc_buffer_t st;
	isc_boolean_t use_default = ISC_FALSE;

	REQUIRE(isc_buffer_type(source) == ISC_BUFFERTYPE_BINARY);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);
	REQUIRE(dctx != NULL);

	ss = *source;
	st = *target;
	/* XXX */
	region.base = (unsigned char *)(target->base) + target->used;

	FROMWIRESWITCH

	if (use_default)
		(void)NULL;

	/* We should have consumed all of our buffer. */
	if (result == DNS_R_SUCCESS && !buffer_empty(source))
		result = DNS_R_EXTRADATA;

	if (rdata && result == DNS_R_SUCCESS) {
		region.length = target->used - st.used;
		dns_rdata_fromregion(rdata, rdclass, type, &region);
	}

	if (result != DNS_R_SUCCESS) {
		*source = ss;
		*target = st;
	}
	return (result);
}

isc_result_t
dns_rdata_towire(dns_rdata_t *rdata, dns_compress_t *cctx,
	         isc_buffer_t *target)
{
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;
	isc_region_t tr;
	isc_buffer_t st;

	REQUIRE(rdata != NULL);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);
	st = *target;

	TOWIRESWITCH
	
	if (use_default) {
		isc_buffer_available(target, &tr);
		if (tr.length < rdata->length) 
			return (DNS_R_NOSPACE);
		memcpy(tr.base, rdata->data, rdata->length);
		isc_buffer_add(target, rdata->length);
		return (DNS_R_SUCCESS);
	}
	if (result != DNS_R_SUCCESS) {
		*target = st;
		INSIST(target->used < 65536);
		dns_compress_rollback(cctx, (isc_uint16_t)target->used);
	}
	return (result);
}

isc_result_t
dns_rdata_fromtext(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, isc_lex_t *lexer,
		   dns_name_t *origin, isc_boolean_t downcase,
		   isc_buffer_t *target, dns_rdatacallbacks_t *callbacks)
{
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_region_t region;
	isc_buffer_t st;
	isc_boolean_t use_default = ISC_FALSE;
	isc_token_t token;
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			       ISC_LEXOPT_DNSMULTILINE | ISC_LEXOPT_ESCAPE;
	char *name;
	int line;
	void (*callback)(dns_rdatacallbacks_t *, char *, ...);
	isc_result_t iresult;

	if (origin != NULL)
		REQUIRE(dns_name_isabsolute(origin) == ISC_TRUE);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);

	st = *target;
	region.base = (unsigned char *)(target->base) + target->used;

	FROMTEXTSWITCH

	if (use_default)
		(void)NULL;

	if (callbacks == NULL)
		callback = NULL;
	else
		callback = callbacks->error;

	if (callback == NULL)
		callback = default_fromtext_callback;
	/*
	 * Consume to end of line / file.
	 * If not at end of line initially set error code.
	 * Call callback via fromtext_error once if there was an error.
	 */
	do {
		name = isc_lex_getsourcename(lexer);
		line = isc_lex_getsourceline(lexer);
		iresult = isc_lex_gettoken(lexer, options, &token);
		if (iresult != ISC_R_SUCCESS) {
			if (result == DNS_R_SUCCESS) {
				switch (iresult) {
				case ISC_R_NOMEMORY:
					result = DNS_R_NOMEMORY;
					break;
				case ISC_R_NOSPACE:
					result = DNS_R_NOSPACE;
					break;
				default:
					UNEXPECTED_ERROR(__FILE__, __LINE__,
					    "isc_lex_gettoken() failed: %s",
					    isc_result_totext(result));
					result = DNS_R_UNEXPECTED;
					break;
				}
			}
			if (callback != NULL)
				fromtext_error(callback, callbacks, name,
					       line, NULL, result);
			break;
		} else if (token.type != isc_tokentype_eol &&
			   token.type != isc_tokentype_eof) {
			if (result == DNS_R_SUCCESS)
				result = DNS_R_EXTRATOKEN;
			if (callback != NULL) {
				fromtext_error(callback, callbacks, name,
					       line, &token, result);
				callback = NULL;
			}
		} else if (result != DNS_R_SUCCESS && callback != NULL) {
			fromtext_error(callback, callbacks, name, line,
				       &token, result);
			break;
		} else
			break;
	} while (1);

	if (rdata != NULL && result == DNS_R_SUCCESS) {
		region.length = target->used - st.used;
		dns_rdata_fromregion(rdata, rdclass, type, &region);
	}
	if (result != DNS_R_SUCCESS) {
		*target = st;
	}
	return (result);
}

static isc_result_t
rdata_totext(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	     isc_buffer_t *target)
{
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;
	
	REQUIRE(rdata != NULL);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_TEXT);
	if (tctx->origin != NULL)
		REQUIRE(dns_name_isabsolute(tctx->origin) == ISC_TRUE);

	/* Some DynDNS meta-RRs have empty rdata. */
	if (rdata->length == 0)
		return (DNS_R_SUCCESS);

	TOTEXTSWITCH

	if (use_default)
		(void)NULL;

	return (result);
}

isc_result_t
dns_rdata_totext(dns_rdata_t *rdata, dns_name_t *origin,
		 isc_buffer_t *target)
{
	/* Set up formatting options for single-line output. */
	dns_rdata_textctx_t tctx;
	tctx.origin = origin;
	tctx.flags = 0;
	tctx.width = 60;
	tctx.linebreak = " ";
	return (rdata_totext(rdata, &tctx, target));
}

isc_result_t
dns_rdata_tofmttext(dns_rdata_t *rdata, dns_name_t *origin,
		    unsigned int flags, unsigned int width,
		    char *linebreak, isc_buffer_t *target)
{
	/* Set up formatting options for formatted output. */
	dns_rdata_textctx_t tctx;
	tctx.origin = origin;
	tctx.flags = flags;
	if ((flags & DNS_STYLEFLAG_MULTILINE) != 0) {
		tctx.width = width;
		tctx.linebreak = linebreak;
	} else {
		tctx.width = 60; /* Used for base64 word length only. */
		tctx.linebreak = " ";
	}
	return (rdata_totext(rdata, &tctx, target));
}

isc_result_t
dns_rdata_fromstruct(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, void *source,
		     isc_buffer_t *target)
{
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_buffer_t st;
	isc_region_t region;
	isc_boolean_t use_default = ISC_FALSE;

	REQUIRE(source != NULL);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);

	region.base = (unsigned char *)(target->base) + target->used;
	st = *target;

	FROMSTRUCTSWITCH

	if (use_default)
		(void)NULL;

	if (rdata != NULL && result == DNS_R_SUCCESS) {
		region.length = target->used - st.used;
		dns_rdata_fromregion(rdata, rdclass, type, &region);
	}
	if (result != DNS_R_SUCCESS)
		*target = st;
	return (result);
}

isc_result_t
dns_rdata_tostruct(dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;

	REQUIRE(rdata != NULL);

	TOSTRUCTSWITCH

	if (use_default)
		(void)NULL;

	return (result);
}

void
dns_rdata_freestruct(void *source) {
	dns_rdatacommon_t *common = source;
	REQUIRE(source != NULL);

	FREESTRUCTSWITCH
}

isc_result_t
dns_rdata_additionaldata(dns_rdata_t *rdata, dns_additionaldatafunc_t add,
			 void *arg)
{
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;

	/*
	 * Call 'add' for each name and type from 'rdata' which is subject to
	 * additional section processing.
	 */

	REQUIRE(rdata != NULL);
	REQUIRE(add != NULL);

	ADDITIONALDATASWITCH

	if (use_default)
		(void)NULL;

	return (result);
}

isc_result_t
dns_rdata_digest(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_result_t result = DNS_R_NOTIMPLEMENTED;
	isc_boolean_t use_default = ISC_FALSE;

	/*
	 * Send 'rdata' in DNSSEC canonical form to 'digest'.
	 */

	REQUIRE(rdata != NULL);
	REQUIRE(digest != NULL);

	DIGESTSWITCH

	if (use_default)
		(void)NULL;

	return (result);
}

#define NUMBERSIZE sizeof("037777777777") /* 2^32-1 octal + NUL */ 

static isc_result_t
dns_mnemonic_fromtext(unsigned int *valuep, isc_textregion_t *source,
		      struct tbl *table, unsigned int max)
{
	int i;

	if (isdigit(source->base[0] & 0xff) &&
            source->length <= NUMBERSIZE - 1) {
		unsigned int n;
		char *e;
		char buffer[NUMBERSIZE];
		/*
		 * We have a potential number.  Try to parse it with strtoul().
		 * strtoul() requires null termination, so we must make
		 * a copy.
		 */
		strncpy(buffer, source->base, NUMBERSIZE);
		INSIST(buffer[source->length] == '\0');
		
		n = strtoul(buffer, &e, 10);
		if (*e == 0) {
			if (n > max)
				return (DNS_R_RANGE);
			*valuep = n;
			return (DNS_R_SUCCESS);
		}
		/* It was not a number after all; fall through. */
	}
	
	for (i = 0; table[i].name != NULL; i++) {
		unsigned int n;		
		n = strlen(table[i].name);
		if (n == source->length &&
		    strncasecmp(source->base, table[i].name, n) == 0) {
			*valuep = table[i].value;
			return (DNS_R_SUCCESS);
		}
	}
	return (DNS_R_UNKNOWN);
}

static isc_result_t
dns_mnemonic_totext(unsigned int value, isc_buffer_t *target,
		    struct tbl *table)
{
	int i = 0;
	char buf[sizeof "4294967296"];
	while (table[i].name != NULL) {
		if (table[i].value == value) {
			return (str_totext(table[i].name, target));
		}
		i++;
	}
	sprintf(buf, "%u", value);
	return (str_totext(buf, target));
}

isc_result_t
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

/* XXXRTH  This should probably be a switch() */

isc_result_t
dns_rdataclass_totext(dns_rdataclass_t rdclass, isc_buffer_t *target) {
	return (dns_mnemonic_totext(rdclass, target, classes));	
}

/* XXXRTH  Should we use a hash table here? */

isc_result_t
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

/* XXXRTH  This should probably be a switch() */

isc_result_t
dns_rdatatype_totext(dns_rdatatype_t type, isc_buffer_t *target) {
	return (dns_mnemonic_totext(type, target, types));
}

/* XXXRTH  Should we use a hash table here? */

isc_result_t
dns_rcode_fromtext(dns_rcode_t *rcodep, isc_textregion_t *source) {
	int i = 0;
	unsigned int n;

	while (rcodes[i].name != NULL) {
		n = strlen(rcodes[i].name);
		if (n == source->length &&
		    strncasecmp(source->base, rcodes[i].name, n) == 0) {
			*rcodep = rcodes[i].value;
			return (DNS_R_SUCCESS);
		}
		i++;
	}
	return (DNS_R_UNKNOWN);
}

isc_result_t
dns_rcode_totext(dns_rcode_t rcode, isc_buffer_t *target) {
	return (dns_mnemonic_totext(rcode, target, rcodes));	
}

isc_result_t
dns_cert_fromtext(dns_cert_t *certp, isc_textregion_t *source) {
	unsigned int value;
	RETERR(dns_mnemonic_fromtext(&value, source, certs, 0xffff));
	*certp = value;
	return (DNS_R_SUCCESS);
}	

isc_result_t
dns_cert_totext(dns_cert_t cert, isc_buffer_t *target) {
	return (dns_mnemonic_totext(cert, target, certs));	
}

isc_result_t
dns_secalg_fromtext(dns_secalg_t *secalgp, isc_textregion_t *source) {
	unsigned int value;
	RETERR(dns_mnemonic_fromtext(&value, source, secalgs, 0xff));
	*secalgp = value;
	return (DNS_R_SUCCESS);
}

isc_result_t
dns_secalg_totext(dns_secalg_t secalg, isc_buffer_t *target) {
	return (dns_mnemonic_totext(secalg, target, secalgs));
}

isc_result_t
dns_secproto_fromtext(dns_secproto_t *secprotop, isc_textregion_t *source) {
	unsigned int value;
	RETERR(dns_mnemonic_fromtext(&value, source, secprotos, 0xff));
	*secprotop = value;
	return (DNS_R_SUCCESS);
}

isc_result_t
dns_secproto_totext(dns_secproto_t secproto, isc_buffer_t *target) {
	return (dns_mnemonic_totext(secproto, target, secprotos));
}

isc_result_t
dns_keyflags_fromtext(dns_keyflags_t *flagsp, isc_textregion_t *source)
{
	char *text, *end;
	unsigned int value, mask;

	if (isdigit(source->base[0] & 0xff) &&
	    source->length <= NUMBERSIZE - 1) {
		unsigned int n;
		char *e;
		char buffer[NUMBERSIZE];
		/*
		 * We have a potential number.  Try to parse it with strtoul().
		 * strtoul() requires null termination, so we must make
		 * a copy.
		 */
		strncpy(buffer, source->base, NUMBERSIZE);
		INSIST(buffer[source->length] == '\0');
		
		n = strtoul(buffer, &e, 0); /* Allow hex/octal. */
		if (*e == 0) {
			if (n > 0xffff)
				return (DNS_R_RANGE);
			*flagsp = n;
			return (DNS_R_SUCCESS);
		}
		/* It was not a number after all; fall through. */
	}

	text = source->base;	
	end = source->base + source->length;
	value = mask = 0;
	
	while (text < end) {
		struct keyflag *p;
		unsigned int len;
		char *delim = memchr(text, '|', end - text);
		if (delim != NULL)
			len = delim - text;
		else
			len = end - text;
		for (p = keyflags; p->name != NULL; p++) {
			if (strncasecmp(p->name, text, len) == 0)
				break;
		}
		if (p->name == NULL)
			return (DNS_R_UNKNOWN);
		value |= p->value;
#ifdef notyet
		if ((mask & p->mask) != 0)
			warn("overlapping key flags");
#endif
		mask |= p->mask;		
		text += len;
		if (delim != NULL)
			text++;	/* Skip "|" */
	}
	*flagsp = value;
	return (DNS_R_SUCCESS);
}

/* Private function */

static unsigned int
name_length(dns_name_t *name) {
	return (name->length);
}

static isc_result_t
txt_totext(isc_region_t *source, isc_buffer_t *target) {
	unsigned int tl;
	unsigned int n;
	unsigned char *sp;
	char *tp;
	isc_region_t region;

	isc_buffer_available(target, &region);
	sp = source->base;
	tp = (char *)region.base;
	tl = region.length;

	n = *sp++;

	REQUIRE(n + 1 <= source->length);

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
	isc_buffer_add(target, tp - (char *)region.base);
	isc_region_consume(source, *source->base + 1);
	return (DNS_R_SUCCESS);
}

static isc_result_t
txt_fromtext(isc_textregion_t *source, isc_buffer_t *target) {
	isc_region_t tregion;
	isc_boolean_t escape;
	unsigned int n, nrem;
	char *s;
	unsigned char *t;
	int d;
	int c;

	isc_buffer_available(target, &tregion);
	s = source->base;
	n = source->length;
	t = tregion.base;
	nrem = tregion.length;
	escape = ISC_FALSE;
	if (nrem < 1)
		return (DNS_R_NOSPACE);
	/* Length byte. */
	nrem--;
	t++;
	/* Maximum text string length. */
	if (nrem > 255)
		nrem = 255;
	while (n-- != 0) {
		c = (*s++)&0xff;
		if (escape && (d = decvalue((char)c)) != -1) {
			c = d;
			if (n == 0)
				return (DNS_R_SYNTAX);
			n--;
			if ((d = decvalue(*s++)) != -1)
				c = c * 10 + d;
			else
				return (DNS_R_SYNTAX);
			if (n == 0)
				return (DNS_R_SYNTAX);
			n--;
			if ((d = decvalue(*s++)) != -1)
				c = c * 10 + d;
			else
				return (DNS_R_SYNTAX);
			if (c > 255)
				return (DNS_R_SYNTAX);
		} else if (!escape && c == '\\') {
			escape = ISC_TRUE;
			continue;
		}
		escape = ISC_FALSE;
		if (nrem == 0) 
			return (DNS_R_NOSPACE);
		*t++ = c;
		nrem--;
	}
	if (escape)
		return (DNS_R_SYNTAX);
	*tregion.base = t - tregion.base - 1;
	isc_buffer_add(target, *tregion.base + 1);
	return (DNS_R_SUCCESS);
}

static isc_result_t
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

static isc_result_t
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

static isc_result_t
uint32_tobuffer(isc_uint32_t value, isc_buffer_t *target) {
	isc_region_t region;

	isc_buffer_available(target, &region);
	if (region.length < 4)
		return (DNS_R_NOSPACE);
	isc_buffer_putuint32(target, value);
	return (DNS_R_SUCCESS);
}

static isc_result_t
uint16_tobuffer(isc_uint32_t value, isc_buffer_t *target) {
	isc_region_t region;

	if (value > 0xffff)
		return (DNS_R_RANGE);
	isc_buffer_available(target, &region);
	if (region.length < 2)
		return (DNS_R_NOSPACE);
	isc_buffer_putuint16(target, (isc_uint16_t)value);
	return (DNS_R_SUCCESS);
}

static isc_result_t
uint8_tobuffer(isc_uint32_t value, isc_buffer_t *target) {
	isc_region_t region;

	if (value > 0xff)
		return (DNS_R_RANGE);
	isc_buffer_available(target, &region);
	if (region.length < 1)
		return (DNS_R_NOSPACE);
	isc_buffer_putuint8(target, (isc_uint8_t)value);
	return (DNS_R_SUCCESS);
}

static isc_uint32_t
uint32_fromregion(isc_region_t *region) {
	unsigned long value;
	
	REQUIRE(region->length >= 4);
	value = region->base[0] << 24;
	value |= region->base[1] << 16;
	value |= region->base[2] << 8;
	value |= region->base[3];
	return(value);
}

static isc_uint16_t
uint16_fromregion(isc_region_t *region) {
	
	REQUIRE(region->length >= 2);

	return ((region->base[0] << 8) | region->base[1]);
}

static isc_uint8_t
uint8_fromregion(isc_region_t *region) {
	
	REQUIRE(region->length >= 1);

	return (region->base[0]);
}

static isc_result_t
gettoken(isc_lex_t *lexer, isc_token_t *token, isc_tokentype_t expect,
	 isc_boolean_t eol)
{
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			       ISC_LEXOPT_DNSMULTILINE | ISC_LEXOPT_ESCAPE;
	isc_result_t result;
	
	if (expect == isc_tokentype_qstring)
		options |= ISC_LEXOPT_QSTRING;
	else if (expect == isc_tokentype_number)
		options |= ISC_LEXOPT_NUMBER;
	result = isc_lex_gettoken(lexer, options, token);
	switch (result) {
	case ISC_R_SUCCESS:
		break;
	case ISC_R_NOMEMORY:
		return (DNS_R_NOMEMORY);
	case ISC_R_NOSPACE:
		return (DNS_R_NOSPACE);
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_lex_gettoken() failed: %s",
				 isc_result_totext(result));
                return (DNS_R_UNEXPECTED);
	}
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
                        return (DNS_R_UNEXPECTEDEND);
                return (DNS_R_UNEXPECTEDTOKEN);
        }
	return (DNS_R_SUCCESS);
}

static isc_result_t
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
		return ((r1->length == r2->length) ? 0 :
			(r1->length < r2->length) ? -1 : 1);
}

static int
hexvalue(char value) {
	char *s;
	if (!isascii(value & 0xff))
		return (-1);
	if (isupper(value & 0xff))
		value = tolower(value);
	if ((s = strchr(hexdigits, value)) == NULL)
		return (-1);
	return (s - hexdigits);
}

static int
decvalue(char value) {
	char *s;
	if (!isascii(value&0xff))
		return (-1);
	if ((s = strchr(decdigits, value)) == NULL)
		return (-1);
	return (s - decdigits);
}

static const char atob_digits[86] =
"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
/*
 * Subroutines to convert between 8 bit binary bytes and printable ASCII.
 * Computes the number of bytes, and three kinds of simple checksums.
 * Incoming bytes are collected into 32-bit words, then printed in base 85:
 *	exp(85,5) > exp(2,32)
 * The ASCII characters used are between '!' and 'u';
 * 'z' encodes 32-bit zero; 'x' is used to mark the end of encoded data.
 *
 * Originally by Paul Rutter (philabs!per) and Joe Orost (petsd!joe) for
 * the atob/btoa programs, released with the compress program, in mod.sources.
 * Modified by Mike Schwartz 8/19/86 for use in BIND.
 * Modified to be re-entrant 3/2/99.
 */


struct state {
	isc_int32_t Ceor;
	isc_int32_t Csum;
	isc_int32_t Crot;
	isc_int32_t word;
	isc_int32_t bcount;
};

#define Ceor state->Ceor
#define Csum state->Csum
#define Crot state->Crot
#define word state->word
#define bcount state->bcount

#define times85(x)	((((((x<<2)+x)<<2)+x)<<2)+x)

static isc_result_t	byte_atob(int c, isc_buffer_t *target,
				  struct state *state);
static isc_result_t	putbyte(int c, isc_buffer_t *, struct state *state);
static isc_result_t	byte_btoa(int c, isc_buffer_t *, struct state *state);

/* Decode ASCII-encoded byte c into binary representation and 
 * place into *bufp, advancing bufp 
 */
static isc_result_t
byte_atob(int c, isc_buffer_t *target, struct state *state) {
	char *s;
	if (c == 'z') {
		if (bcount != 0)
			return(DNS_R_SYNTAX);
		else {
			RETERR(putbyte(0, target, state));
			RETERR(putbyte(0, target, state));
			RETERR(putbyte(0, target, state));
			RETERR(putbyte(0, target, state));
		}
	} else if ((s = strchr(atob_digits, c)) != NULL) {
		if (bcount == 0) {
			word = s - atob_digits;
			++bcount;
		} else if (bcount < 4) {
			word = times85(word);
			word += s - atob_digits;
			++bcount;
		} else {
			word = times85(word);
			word += s - atob_digits;
			RETERR(putbyte((word >> 24) & 0xff, target, state));
			RETERR(putbyte((word >> 16) & 0xff, target, state));
			RETERR(putbyte((word >> 8) & 0xff, target, state));
			RETERR(putbyte(word & 0xff, target, state));
			word = 0;
			bcount = 0;
		}
	} else
		return(DNS_R_SYNTAX);
	return(DNS_R_SUCCESS);
}

/* Compute checksum info and place c into target */
static isc_result_t
putbyte(int c, isc_buffer_t *target, struct state *state) {
	isc_region_t tr;

	Ceor ^= c;
	Csum += c;
	Csum += 1;
	if ((Crot & 0x80000000)) {
		Crot <<= 1;
		Crot += 1;
	} else {
		Crot <<= 1;
	}
	Crot += c;
	isc_buffer_available(target, &tr);
	if (tr.length < 1)
		return (DNS_R_NOSPACE);
	tr.base[0] = c;
	isc_buffer_add(target, 1);
	return (DNS_R_SUCCESS);
}

/* Read the ASCII-encoded data from inbuf, of length inbuflen, and convert
   it into T_UNSPEC (binary data) in outbuf, not to exceed outbuflen bytes;
   outbuflen must be divisible by 4.  (Note: this is because outbuf is filled
   in 4 bytes at a time.  If the actual data doesn't end on an even 4-byte
   boundary, there will be no problem...it will be padded with 0 bytes, and
   numbytes will indicate the correct number of bytes.  The main point is
   that since the buffer is filled in 4 bytes at a time, even if there is
   not a full 4 bytes of data at the end, there has to be room to 0-pad the
   data, so the buffer must be of size divisible by 4).  Place the number of
   output bytes in numbytes, and return a failure/success status  */

static isc_result_t
atob_tobuffer(isc_lex_t *lexer, isc_buffer_t *target) {
	isc_int32_t oeor, osum, orot;
	struct state statebuf, *state= &statebuf;
	isc_token_t token;
	char c;
	char *e;

	Ceor = Csum = Crot = word = bcount = 0;

	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	while (token.value.as_textregion.length != 0) {
		if ((c = token.value.as_textregion.base[0]) == 'x') {
			break;
		} else
			RETERR(byte_atob(c, target, state));
		isc_textregion_consume(&token.value.as_textregion, 1);
	}

	/* number of bytes */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if ((token.value.as_ulong % 4) != 0)
		isc_buffer_subtract(target,  4 - (token.value.as_ulong % 4));

	/* checksum */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	oeor = strtoul(token.value.as_pointer, &e, 16);
	if (*e != 0)
		return (DNS_R_SYNTAX);

	/* checksum */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	osum = strtoul(token.value.as_pointer, &e, 16);
	if (*e != 0)
		return (DNS_R_SYNTAX);

	/* checksum */
	RETERR(gettoken(lexer, &token, isc_tokentype_string, ISC_FALSE));
	orot = strtoul(token.value.as_pointer, &e, 16);
	if (*e != 0)
		return (DNS_R_SYNTAX);

	if ((oeor != Ceor) || (osum != Csum) || (orot != Crot))
		return(DNS_R_BADCKSUM);
	return(DNS_R_SUCCESS);
}

/* Encode binary byte c into ASCII representation and place into *bufp,
   advancing bufp */
static isc_result_t
byte_btoa(int c, isc_buffer_t *target, struct state *state) {
	isc_region_t tr;

	isc_buffer_available(target, &tr);
	Ceor ^= c;
	Csum += c;
	Csum += 1;
	if ((Crot & 0x80000000)) {
		Crot <<= 1;
		Crot += 1;
	} else {
		Crot <<= 1;
	}
	Crot += c;

	word <<= 8;
	word |= c;
	if (bcount == 3) {
		if (word == 0) {
			if (tr.length < 1)
				return (DNS_R_NOSPACE);
			tr.base[0] = 'z';
			isc_buffer_add(target, 1);
		} else {
		    register int tmp = 0;
		    register isc_int32_t tmpword = word;
			
		    if (tmpword < 0) {	
			   /* Because some don't support u_long */
		    	tmp = 32;
		    	tmpword -= (isc_int32_t)(85 * 85 * 85 * 85 * 32);
		    }
		    if (tmpword < 0) {
		    	tmp = 64;
		    	tmpword -= (isc_int32_t)(85 * 85 * 85 * 85 * 32);
		    }
			if (tr.length < 5)
				return (DNS_R_NOSPACE);
		    	tr.base[0] = atob_digits[(tmpword /
					      (isc_int32_t)(85 * 85 * 85 * 85))
						+ tmp];
			tmpword %= (isc_int32_t)(85 * 85 * 85 * 85);
			tr.base[1] = atob_digits[tmpword / (85 * 85 * 85)];
			tmpword %= (85 * 85 * 85);
			tr.base[2] = atob_digits[tmpword / (85 * 85)];
			tmpword %= (85 * 85);
			tr.base[3] = atob_digits[tmpword / 85];
			tmpword %= 85;
			tr.base[4] = atob_digits[tmpword];
			isc_buffer_add(target, 5);
		}
		bcount = 0;
	} else {
		bcount += 1;
	}
	return (DNS_R_SUCCESS);
}


/*
 * Encode the binary data from inbuf, of length inbuflen, into a
 * target.  Return success/failure status
 */
static isc_result_t
btoa_totext(unsigned char *inbuf, int inbuflen, isc_buffer_t *target) {
	int inc;
	struct state statebuf, *state = &statebuf;
	char buf[sizeof "x 2000000000 ffffffff ffffffff ffffffff"];

	Ceor = Csum = Crot = word = bcount = 0;
	for (inc = 0; inc < inbuflen; inbuf++, inc++)
		RETERR(byte_btoa(*inbuf, target, state));
	
	while (bcount != 0)
		RETERR(byte_btoa(0, target, state));
	
	/*
	 * Put byte count and checksum information at end of buffer,
	 * delimited by 'x'
	 */
	sprintf(buf, "x %d %x %x %x", inbuflen, Ceor, Csum, Crot);
	return (str_totext(buf, target));
}


static void
default_fromtext_callback(dns_rdatacallbacks_t *callbacks, char *fmt, ...) {
	va_list ap;

	callbacks = callbacks; /*unused*/

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
fromtext_error(void (*callback)(dns_rdatacallbacks_t *, char *, ...),
	       dns_rdatacallbacks_t *callbacks, char *name, int line,
	       isc_token_t *token, isc_result_t result)
{
	if (name == NULL)
		name = "UNKNOWN";

	if (token != NULL) {
		switch (token->type) {
		case isc_tokentype_eol:
			(*callback)(callbacks, "%s: %s:%d: near eol: %s",
				    "dns_rdata_fromtext", name, line,
				    dns_result_totext(result));
			break;
		case isc_tokentype_eof:
			(*callback)(callbacks, "%s: %s:%d: near eof: %s",
				    "dns_rdata_fromtext", name, line,
				    dns_result_totext(result));
			break;
		case isc_tokentype_number:
			(*callback)(callbacks, "%s: %s:%d: near %lu: %s",
				    "dns_rdata_fromtext", name, line,
				    token->value.as_ulong,
				    dns_result_totext(result));
			break;
		case isc_tokentype_string:
		case isc_tokentype_qstring:
			(*callback)(callbacks, "%s: %s:%d: near '%s': %s",
				    "dns_rdata_fromtext", name, line,
				    (char *)token->value.as_pointer,
				    dns_result_totext(result));
			break;
		default:
			(*callback)(callbacks, "%s: %s:%d: %s",
				    "dns_rdata_fromtext", name, line,
				    dns_result_totext(result));
			break;
		}
	} else {
		(*callback)(callbacks, "dns_rdata_fromtext: %s:%d: %s",
			    name, line, dns_result_totext(result));
	}
}

dns_rdatatype_t
dns_rdata_covers(dns_rdata_t *rdata) {
	return (covers_sig(rdata));
}

static isc_boolean_t
ismeta(unsigned int code, struct tbl *table) {
	struct tbl *t;
	REQUIRE(code < 65536);
	/* XXXBEW Yes, this is a hack.  But otherwise TKEY will not work */
	if (code == dns_rdatatype_tsig || code == dns_rdatatype_tkey)
		return (ISC_TRUE);
	for (t = table; t->name != NULL; t++) {
		if (code == t->value)
			return ((t->flags & META) ? ISC_TRUE : ISC_FALSE);
	}
	return (ISC_FALSE); /* Unknown, assume non-meta. */
}

isc_boolean_t
dns_rdatatype_ismeta(dns_rdatatype_t type) {
	return (ismeta(type, types));
}	

isc_boolean_t
dns_rdataclass_ismeta(dns_rdataclass_t rdclass) {
	return (ismeta(rdclass, classes));
}

isc_boolean_t
dns_rdatatype_isdnssec(dns_rdatatype_t type) {
	return ((type == dns_rdatatype_sig ||
		 type == dns_rdatatype_key ||
		 type == dns_rdatatype_nxt) ?
		ISC_TRUE : ISC_FALSE);
}

isc_boolean_t
dns_rdatatype_iszonecutauth(dns_rdatatype_t type) {
	return (type == dns_rdatatype_ns ||
		dns_rdatatype_isdnssec(type) ?
		ISC_TRUE : ISC_FALSE);
}
