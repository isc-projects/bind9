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

/* $Id: base64.c,v 1.14 2000/06/01 17:20:18 tale Exp $ */

#include <config.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/string.h>
#include <isc/util.h>

#define RETERR(x) do { \
	isc_result_t _r = (x); \
	if (_r != ISC_R_SUCCESS) \
		return (_r); \
	} while (0)


/*
 * These static functions are also present in lib/dns/rdata.c.  I'm not
 * sure where they should go. -- bwelling
 */
static isc_result_t
str_totext(const char *source, isc_buffer_t *target);

static isc_result_t
gettoken(isc_lex_t *lexer, isc_token_t *token, isc_tokentype_t expect,
	 isc_boolean_t eol);

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

static const char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

isc_result_t
isc_base64_totext(isc_region_t *source, int wordlength,
		  const char *wordbreak, isc_buffer_t *target)
{
	char buf[5];
	unsigned int loops = 0;

	if (wordlength < 4)
		wordlength = 4;

	memset(buf, 0, sizeof buf);
	while (source->length > 2) {
		buf[0] = base64[(source->base[0]>>2)&0x3f];
		buf[1] = base64[((source->base[0]<<4)&0x30)|
				((source->base[1]>>4)&0x0f)];
		buf[2] = base64[((source->base[1]<<2)&0x3c)|
				((source->base[2]>>6)&0x03)];
		buf[3] = base64[source->base[2]&0x3f];
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 3);

		loops++;
		if (source->length != 0 &&
		    (int)((loops + 1) * 4) >= wordlength)
		{
			loops = 0;
			RETERR(str_totext(wordbreak, target));
		}
	}
	if (source->length == 2) {
		buf[0] = base64[(source->base[0]>>2)&0x3f];
		buf[1] = base64[((source->base[0]<<4)&0x30)|
				((source->base[1]>>4)&0x0f)];
		buf[2] = base64[((source->base[1]<<2)&0x3c)];
		buf[3] = '=';
		RETERR(str_totext(buf, target));
	} else if (source->length == 1) {
		buf[0] = base64[(source->base[0]>>2)&0x3f];
		buf[1] = base64[((source->base[0]<<4)&0x30)];
		buf[2] = buf[3] = '=';
		RETERR(str_totext(buf, target));
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_base64_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length) {
	int digits = 0;
	isc_textregion_t *tr;
	int val[4];
	unsigned char buf[3];
	int seen_end = 0;
	unsigned int i;
	isc_token_t token;
	char *s;
	int n;

	
	while (!seen_end && (length != 0)) {
		if (length > 0)
			RETERR(gettoken(lexer, &token, isc_tokentype_string,
					ISC_FALSE));
		else
			RETERR(gettoken(lexer, &token, isc_tokentype_string,
					ISC_TRUE));
		if (token.type != isc_tokentype_string)
			break;
		tr = &token.value.as_textregion;
		for (i = 0 ;i < tr->length; i++) {
			if (seen_end)
				return (ISC_R_BADBASE64);
			if ((s = strchr(base64, tr->base[i])) == NULL)
				return (ISC_R_BADBASE64);
			val[digits++] = s - base64;
			if (digits == 4) {
				if (val[0] == 64 || val[1] == 64)
					return (ISC_R_BADBASE64);
				if (val[2] == 64 && val[3] != 64)
					return (ISC_R_BADBASE64);
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
				if (length >= 0) {
					if (n > length)
						return (ISC_R_BADBASE64);
					else
						length -= n;
				}
				digits = 0;
			}
		}
	}
	if (length < 0 && !seen_end)
		isc_lex_ungettoken(lexer, &token);
	if (length > 0)
		return (ISC_R_UNEXPECTEDEND);
	if (digits != 0)
		return (ISC_R_BADBASE64);
	return (ISC_R_SUCCESS);
}

static isc_result_t
str_totext(const char *source, isc_buffer_t *target) {
	unsigned int l;
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	l = strlen(source);

	if (l > region.length)
		return (ISC_R_NOSPACE);

	memcpy(region.base, source, l);
	isc_buffer_add(target, l);
	return (ISC_R_SUCCESS);
}

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	isc_buffer_availableregion(target, &tr);
	if (length > tr.length)
		return (ISC_R_NOSPACE);
	memcpy(tr.base, base, length);
	isc_buffer_add(target, length);
	return (ISC_R_SUCCESS);
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
		return (ISC_R_NOMEMORY);
	case ISC_R_NOSPACE:
		return (ISC_R_NOSPACE);
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_lex_gettoken() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	if (eol && ((token->type == isc_tokentype_eol) ||
		    (token->type == isc_tokentype_eof)))
		return (ISC_R_SUCCESS);
	if (token->type == isc_tokentype_string &&
	    expect == isc_tokentype_qstring)
		return (ISC_R_SUCCESS);
	if (token->type != expect) {
		isc_lex_ungettoken(lexer, token);
		if (token->type == isc_tokentype_eol ||
		    token->type == isc_tokentype_eof)
			return (ISC_R_UNEXPECTEDEND);
		return (ISC_R_UNEXPECTEDTOKEN);
	}
	return (ISC_R_SUCCESS);
}
