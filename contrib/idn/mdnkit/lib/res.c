#ifndef lint
static char *rcsid = "$Id: res.c,v 1.1 2002/01/02 02:46:46 marka Exp $";
#endif

/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/checker.h>
#include <mdn/mapper.h>
#include <mdn/mapselector.h>
#include <mdn/delimitermap.h>
#include <mdn/resconf.h>
#include <mdn/res.h>
#include <mdn/util.h>
#include <mdn/debug.h>

static mdn_result_t	nameconv_l(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_L(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_d(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_M(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_m(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_n(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_p(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_u(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_N(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_I(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_i(mdn_resconf_t ctx, const char *from,
				   char *to, size_t tolen);
static mdn_result_t	nameconv_xm(mdn_resconf_t ctx, const char *from,
				    char *to, size_t tolen);
static mdn_result_t	nameconv_xn(mdn_resconf_t ctx, const char *from,
				    char *to, size_t tolen);
static mdn_result_t	nameconv_xp(mdn_resconf_t ctx, const char *from,
				    char *to, size_t tolen);
static mdn_result_t	nameconv_xu(mdn_resconf_t ctx, const char *from,
				    char *to, size_t tolen);
static mdn_result_t	nameconv_xN(mdn_resconf_t ctx, const char *from,
				    char *to, size_t tolen);
static mdn_result_t	copy_verbatim(const char *from, char *to,
				      size_t tolen);

mdn_result_t
mdn_res_nameconv(mdn_resconf_t ctx, const char *insn, const char *from,
		 char *to, size_t tolen)
{
	mdn_result_t r;
	char *src, *dst;
	char static_buffers[2][1024];	/* large enough */
	char *dynamic_buffers[2];
	size_t dynamic_buflen[2];
	const char *ap;
	size_t dstlen;
	int dstidx;

	assert(ctx != NULL && from != NULL && to != NULL);

	TRACE(("mdn_res_nameconv(insn=%s, from=\"%s\", tolen=%d)\n",
	        insn, mdn_debug_xstring(from, 256), tolen));

	/*
	 * Initialize the buffers to use the local
	 * storage (stack memory).
	 */
	dynamic_buffers[0] = NULL;
	dynamic_buffers[1] = NULL;
	dynamic_buflen[0] = 0;
	dynamic_buflen[1] = 0;

	/*
	 * Convert.
	 */
	src = (void *)from;
	dstlen = sizeof(static_buffers[0]) + 1;
	ap = insn;

	while (*ap != '\0') {
		if (*ap == ' ' || *ap == '\t') {
			ap++;
			continue;
		}

		/*
		 * Choose destination area to restore the result of a mapping.
		 */
		if (dstlen <= sizeof(static_buffers[0])) {
			if (src == static_buffers[0])
				dstidx = 1;
			else
				dstidx = 0;

			dst = static_buffers[dstidx];
		} else {
			void *newbuf;

			if (src == dynamic_buffers[0])
				dstidx = 1;
			else
				dstidx = 0;

			newbuf = (char *)realloc(dynamic_buffers[dstidx],
						 dstlen);
			if (newbuf == NULL) {
				r = mdn_nomemory;
				goto failure;
			}
			dynamic_buffers[dstidx] = newbuf;
			dynamic_buflen[dstidx] = dstlen;

			dst = dynamic_buffers[dstidx];
		}

		/*
		 * Perform a conversion or check.
		 * If buffer size is not enough, we double it and try again.
		 */
		switch (*ap) {
		case 'l':
			r = nameconv_l(ctx, src, dst, dstlen);
			break;
		case 'L':
			r = nameconv_L(ctx, src, dst, dstlen);
			break;
		case 'd':
			r = nameconv_d(ctx, src, dst, dstlen);
			break;
		case 'M':
			r = nameconv_M(ctx, src, dst, dstlen);
			break;
		case 'm':
			r = nameconv_m(ctx, src, dst, dstlen);
			break;
		case 'n':
			r = nameconv_n(ctx, src, dst, dstlen);
			break;
		case 'p':
			r = nameconv_p(ctx, src, dst, dstlen);
			break;
		case 'u':
			r = nameconv_u(ctx, src, dst, dstlen);
			break;
		case 'N':
			r = nameconv_N(ctx, src, dst, dstlen);
			break;
		case 'I':
			r = nameconv_I(ctx, src, dst, dstlen);
			break;
		case 'i':
			r = nameconv_i(ctx, src, dst, dstlen);
			break;
		case '!':
			ap++;
			switch (*ap) {
			case 'm':
				r = nameconv_xm(ctx, src, dst, dstlen);
				break;
			case 'n':
				r = nameconv_xn(ctx, src, dst, dstlen);
				break;
			case 'p':
				r = nameconv_xp(ctx, src, dst, dstlen);
				break;
			case 'u':
				r = nameconv_xu(ctx, src, dst, dstlen);
				break;
			case 'N':
				r = nameconv_xN(ctx, src, dst, dstlen);
				break;
			default:
				r = mdn_invalid_action;
				break;
			}
			break;
		default:
			r = mdn_invalid_action;
			break;
		}

		if (r == mdn_buffer_overflow) {
			dstlen *= 2;
			continue;
		} else if (r != mdn_success)
			goto failure;

		ap++;
		src = dst;
	}

	r = copy_verbatim(src, to, tolen);
	if (r != mdn_success)
		goto failure;

	TRACE(("mdn_res_nameconv: to=\"%s\"\n",
		mdn_debug_xstring(to, 256)));

	free(dynamic_buffers[0]);
	free(dynamic_buffers[1]);
	return (mdn_success);

failure:
	TRACE(("mdn_res_nameconv() failed, %s\n", mdn_result_tostring(r)));
	free(dynamic_buffers[0]);
	free(dynamic_buffers[1]);
	return (r);
}

static mdn_result_t
nameconv_l(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t local_converter;

	local_converter = mdn_resconf_getlocalconverter(ctx);
	if (local_converter != NULL) {
		r = mdn_converter_localtoutf8(local_converter, from, to,
					      tolen);
		mdn_converter_destroy(local_converter);
	} else {
		r = copy_verbatim(from, to, tolen);
	}

	return (r);
}

static mdn_result_t
nameconv_L(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t local_converter;

	local_converter = mdn_resconf_getlocalconverter(ctx);
	if (local_converter != NULL) {
		r = mdn_converter_utf8tolocal(local_converter, from, to,
					      tolen);
		mdn_converter_destroy(local_converter);
	} else {
		r = copy_verbatim(from, to, tolen);
	}
	if (r == mdn_nomapping)
		r = nameconv_I(ctx, from, to, tolen);

	return (r);
}

static mdn_result_t
nameconv_d(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_delimitermap_t delimiter_mapper;

	delimiter_mapper = mdn_resconf_getdelimitermap(ctx);
	if (delimiter_mapper != NULL) {
		r = mdn_delimitermap_map(delimiter_mapper, from, to, tolen);
		mdn_delimitermap_destroy(delimiter_mapper);
	} else {
		r = copy_verbatim(from, to, tolen);
	}

	return (r);
}

static mdn_result_t
nameconv_M(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_mapselector_t local_mapper;

	local_mapper = mdn_resconf_getlocalmapselector(ctx);
	if (local_mapper != NULL) {
		r = mdn_mapselector_map(local_mapper, from, to, tolen);
		mdn_mapselector_destroy(local_mapper);
	} else {
		r = copy_verbatim(from, to, tolen);
	}

	return (r);
}

static mdn_result_t
nameconv_m(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_mapper_t mapper = NULL;
	mdn_result_t r;
	size_t fromlen;
	size_t steplen;
	char static_buffer[1024];	/* large enough */
	char *dynamic_buffer = NULL;
	char *label;
	char *dot;

	fromlen = strlen(from);

	mapper = mdn_resconf_getmapper(ctx);
	if (mapper == NULL) {
		r = copy_verbatim(from, to, tolen);
		return (r);
	}

	if (fromlen + 1 > sizeof(static_buffer)) {
		dynamic_buffer = (char *) malloc(fromlen + 1);
		if (dynamic_buffer == NULL) {
			r = mdn_nomemory;
			goto failure;
		}
		label = dynamic_buffer;
	} else {
		label = static_buffer;
	}

	strcpy(label, from);

	for (;;) {
		dot = strchr(label, '.');
		if (dot != NULL)
			*dot = '\0';

		if (*label == '\0' || mdn_util_validstd13(label, NULL)) {
			r = copy_verbatim(label, to, tolen);
		} else {
			r = mdn_mapper_map(mapper, label, to, tolen);
		}
		if (r != mdn_success)
			goto failure;

		steplen = strlen(to);
		tolen -= steplen;
		to += steplen;

		if (dot == NULL)
			break;

		if (tolen <= 1) {
			r = mdn_buffer_overflow;
			return (r);
		}
		*to++ = '.';
		tolen--;

		label = dot + 1;
		if (*label == '\0')
			break;
	}

	/*
	 * Don't delete the following.  If `from' ends with ".", `to' is
	 * terminated by this line.
	 */
	*to = '\0';

	free(dynamic_buffer);
	mdn_mapper_destroy(mapper);
	return (mdn_success);

failure:
	free(dynamic_buffer);
	if (mapper != NULL)
		mdn_mapper_destroy(mapper);
	return (r);
}

static mdn_result_t
nameconv_n(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_normalizer_t normalizer = NULL;
	mdn_result_t r;
	size_t fromlen;
	size_t steplen;
	char static_buffer[1024];	/* large enough */
	char *dynamic_buffer = NULL;
	char *label;
	char *dot;

	fromlen = strlen(from);

	normalizer = mdn_resconf_getnormalizer(ctx);
	if (normalizer == NULL) {
		r = copy_verbatim(from, to, tolen);
		return (r);
	}

	if (fromlen + 1 > sizeof(static_buffer)) {
		dynamic_buffer = (char *) malloc(fromlen + 1);
		if (dynamic_buffer == NULL) {
			r = mdn_nomemory;
			goto failure;
		}
		label = dynamic_buffer;
	} else {
		label = static_buffer;
	}

	strcpy(label, from);

	for (;;) {
		dot = strchr(label, '.');
		if (dot != NULL)
			*dot = '\0';

		if (*label == '\0' || mdn_util_validstd13(label, NULL)) {
			r = copy_verbatim(label, to, tolen);
		} else {
			r = mdn_normalizer_normalize(normalizer, label, to,
				tolen);
		}
		if (r != mdn_success)
			goto failure;

		steplen = strlen(to);
		tolen -= steplen;
		to += steplen;

		if (dot == NULL)
			break;

		if (tolen <= 1) {
			r = mdn_buffer_overflow;
			return (r);
		}
		*to++ = '.';
		tolen--;

		label = dot + 1;
		if (*label == '\0')
			break;
	}

	/*
	 * Don't delete the following.  If `from' ends with ".", `to' is
	 * terminated by this line.
	 */
	*to = '\0';

	free(dynamic_buffer);
	mdn_normalizer_destroy(normalizer);
	return (mdn_success);

failure:
	free(dynamic_buffer);
	if (normalizer != NULL)
		mdn_normalizer_destroy(normalizer);
	return (r);
}

static mdn_result_t
nameconv_p(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	const char *found;
	mdn_checker_t prohibit_checker;

	prohibit_checker = mdn_resconf_getprohibitchecker(ctx);
	if (prohibit_checker != NULL) {
		r = mdn_checker_lookup(prohibit_checker, from, &found);
		mdn_checker_destroy(prohibit_checker);
		if (r == mdn_success && found != NULL)
			r = mdn_prohibited;
		if (r != mdn_success)
			return (r);
	}

	r = copy_verbatim(from, to, tolen);

	return (r);
}

static mdn_result_t
nameconv_u(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_checker_t unassigned_checker;
	const char *found;

	unassigned_checker = mdn_resconf_getunassignedchecker(ctx);
	if (unassigned_checker != NULL) {
		r = mdn_checker_lookup(unassigned_checker, from, &found);
		mdn_checker_destroy(unassigned_checker);
		if (r == mdn_success && found != NULL)
			r = mdn_prohibited;
		if (r != mdn_success)
			return (r);
	}

	r = copy_verbatim(from, to, tolen);

	return (r);
}

static mdn_result_t
nameconv_N(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	char static_buffer1[1024];	/* large enough */
	char static_buffer2[1024];	/* large enough */
	char *dynamic_buffer1 = NULL;
	char *dynamic_buffer2 = NULL;
	char *work1, *work2;

	if (tolen <= sizeof(static_buffer1)) {
		work1 = static_buffer1;
		work2 = static_buffer2;
	} else {
		dynamic_buffer1 = (char *)malloc(tolen);
		dynamic_buffer2 = (char *)malloc(tolen);
		if (dynamic_buffer1 == NULL || dynamic_buffer2 == NULL) {
			r = mdn_nomemory;
			goto failure;
		}
		work1 = dynamic_buffer1;
		work2 = dynamic_buffer2;
	}

	r = nameconv_m(ctx, from, work1, tolen);
	if (r != mdn_success)
		goto failure;

	r = nameconv_n(ctx, work1, work2, tolen);
	if (r != mdn_success)
		goto failure;

	r = nameconv_p(ctx, work2, to, tolen);
	if (r != mdn_success)
		goto failure;

	free(dynamic_buffer1);
	free(dynamic_buffer2);
	return (r);

failure:
	free(dynamic_buffer1);
	free(dynamic_buffer2);
	return (r);
}

static mdn_result_t
nameconv_I(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		r = mdn_converter_utf8tolocal(idn_converter, from, to, tolen);
		mdn_converter_destroy(idn_converter);
	} else {
		r = copy_verbatim(from, to, tolen);
	}

	return (r);
}

static mdn_result_t
nameconv_i(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		r = mdn_converter_localtoutf8(idn_converter, from, to, tolen);
		mdn_converter_destroy(idn_converter);
	} else {
		r = copy_verbatim(from, to, tolen);
	}

	return (r);
}

static mdn_result_t
nameconv_xm(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;
	int encoding_type;
	int isvalid;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		encoding_type = mdn_converter_encodingtype(idn_converter);
		mdn_converter_destroy(idn_converter);
	} else {
		encoding_type = MDN_NONACE;
	}

	r = nameconv_m(ctx, from, to, tolen);
	if (r != mdn_success)
		return (r);

	if (encoding_type == MDN_ACE_STRICTCASE)
		isvalid = mdn_util_casematch(from, to, tolen);
	else
		isvalid = (strcmp(from, to) == 0);

	if (isvalid || encoding_type == MDN_NONACE)
		r = copy_verbatim(from, to, tolen);
	else
		r = nameconv_I(ctx, from, to, tolen);

	return (r);
}

static mdn_result_t
nameconv_xn(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;
	int encoding_type;
	int isvalid;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		encoding_type = mdn_converter_encodingtype(idn_converter);
		mdn_converter_destroy(idn_converter);
	} else {
		encoding_type = MDN_NONACE;
	}

	r = nameconv_n(ctx, from, to, tolen);
	if (r != mdn_success)
		return (r);

	if (encoding_type == MDN_ACE_STRICTCASE)
		isvalid = mdn_util_casematch(from, to, tolen);
	else
		isvalid = (strcmp(from, to) == 0);

	if (isvalid || encoding_type == MDN_NONACE)
		r = copy_verbatim(from, to, tolen);
	else
		r = nameconv_I(ctx, from, to, tolen);

	return (r);
}

static mdn_result_t
nameconv_xp(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;
	int encoding_type;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		encoding_type = mdn_converter_encodingtype(idn_converter);
		mdn_converter_destroy(idn_converter);
	} else {
		encoding_type = MDN_NONACE;
	}

	r = nameconv_p(ctx, from, to, tolen);
	if (r == mdn_prohibited) {
		if (encoding_type == MDN_NONACE)
			r = copy_verbatim(from, to, tolen);
		else
			r = nameconv_I(ctx, from, to, tolen);
	}

	return (r);
}

static mdn_result_t
nameconv_xu(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;
	int encoding_type;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		encoding_type = mdn_converter_encodingtype(idn_converter);
		mdn_converter_destroy(idn_converter);
	} else {
		encoding_type = MDN_NONACE;
	}

	r = nameconv_u(ctx, from, to, tolen);
	if (r == mdn_prohibited) {
		if (encoding_type == MDN_NONACE)
			r = copy_verbatim(from, to, tolen);
		else
			r = nameconv_I(ctx, from, to, tolen);
	}

	return (mdn_success);
}

static mdn_result_t
nameconv_xN(mdn_resconf_t ctx, const char *from, char *to, size_t tolen)
{
	mdn_result_t r;
	mdn_converter_t idn_converter;
	int encoding_type;
	int isvalid;

	idn_converter = mdn_resconf_getidnconverter(ctx);
	if (idn_converter != NULL) {
		encoding_type = mdn_converter_encodingtype(idn_converter);
		mdn_converter_destroy(idn_converter);
	} else {
		encoding_type = MDN_NONACE;
	}

	r = nameconv_N(ctx, from, to, tolen);
	if (r == mdn_success) {
		if (encoding_type == MDN_ACE_STRICTCASE)
			isvalid = mdn_util_casematch(from, to, tolen);
		else
			isvalid = (strcmp(from, to) == 0);
	} else if (r == mdn_prohibited) {
		isvalid = 0;
	} else {
		return (r);
	}

	if (isvalid || encoding_type == MDN_NONACE)
		r = copy_verbatim(from, to, tolen);
	else
		r = nameconv_I(ctx, from, to, tolen);

	return (r);
}

static mdn_result_t
copy_verbatim(const char *from, char *to, size_t tolen) {
	size_t fromlen = strlen(from);

	if (fromlen + 1 > tolen)
		return (mdn_buffer_overflow);
	(void)memcpy(to, from, fromlen + 1);
	return (mdn_success);
}

#undef mdn_res_localtoucs
#undef mdn_res_ucstolocal
#undef mdn_res_map
#undef mdn_res_normalize
#undef mdn_res_prohibitcheck
#undef mdn_res_nameprep
#undef mdn_res_nameprepcheck
#undef mdn_res_unassignedcheck
#undef mdn_res_delimitermap
#undef mdn_res_localmap
#undef mdn_res_ucstodns
#undef mdn_res_dnstoucs

mdn_result_t
mdn_res_localtoucs(mdn_resconf_t ctx, const char *from, char *to,
		   size_t tolen) {
	return mdn_res_nameconv(ctx, "l", from, to, tolen);
}

mdn_result_t
mdn_res_ucstolocal(mdn_resconf_t ctx, const char *from, char *to,
		   size_t tolen) {
	return mdn_res_nameconv(ctx, "L", from, to, tolen);
}

mdn_result_t
mdn_res_map(mdn_resconf_t ctx, const char *from, char *to, size_t tolen) {
	return mdn_res_nameconv(ctx, "m", from, to, tolen);
}


mdn_result_t
mdn_res_normalize(mdn_resconf_t ctx, const char *from, char *to,
		  size_t tolen) {
	return mdn_res_nameconv(ctx, "n", from, to, tolen);
}

mdn_result_t
mdn_res_prohibitcheck(mdn_resconf_t ctx, const char *from, char *to,
		      size_t tolen) {
	return mdn_res_nameconv(ctx, "p", from, to, tolen);
}

mdn_result_t
mdn_res_nameprep(mdn_resconf_t ctx, const char *from, char *to,
		 size_t tolen) {
	return mdn_res_nameconv(ctx, "N", from, to, tolen);
}

mdn_result_t
mdn_res_nameprepcheck(mdn_resconf_t ctx, const char *from, char *to,
		      size_t tolen) {
	return mdn_res_nameconv(ctx, "!N", from, to, tolen);
}

mdn_result_t
mdn_res_unassignedcheck(mdn_resconf_t ctx, const char *from, char *to,
			size_t tolen) {
	return mdn_res_nameconv(ctx, "u", from, to, tolen);
}

mdn_result_t
mdn_res_delimitermap(mdn_resconf_t ctx, const char *from, char *to,
		     size_t tolen) {
	return mdn_res_nameconv(ctx, "d", from, to, tolen);
}

mdn_result_t
mdn_res_localmap(mdn_resconf_t ctx, const char *from, char *to, size_t tolen) {
	return mdn_res_nameconv(ctx, "M", from, to, tolen);
}

mdn_result_t
mdn_res_ucstodns(mdn_resconf_t ctx, const char *from, char *to,
		 size_t tolen) {
	return mdn_res_nameconv(ctx, "I", from, to, tolen);
}

mdn_result_t
mdn_res_dnstoucs(mdn_resconf_t ctx, const char *from, char *to,
		 size_t tolen) {
	return mdn_res_nameconv(ctx, "i", from, to, tolen);
}

