#ifndef lint
static char *rcsid = "$Id: ace.c,v 1.1.2.1 2002/02/08 12:13:36 marka Exp $";
#endif

/*
 * Copyright (c) 2000,2001 Japan Network Information Center.
 * All rights reserved.
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
#include <mdn/converter.h>
#include <mdn/util.h>
#include <mdn/ace.h>

static mdn_result_t	l2u(mdn__ace_t *ctx, const char *from, const char *end,
			    char *to, size_t tolen, size_t *clenp);
static mdn_result_t	u2l(mdn__ace_t *ctx, const char *from, const char *end,
			    char *to, size_t tolen, size_t *clenp);

mdn_result_t
mdn__ace_convert(mdn__ace_t *ctx, mdn_converter_dir_t dir,
		 const char *from, char *to, size_t tolen)
{
	assert(ctx != NULL && ctx->encoder != NULL && ctx->decoder != NULL &&
	       from != NULL && to != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	for (;;) {
		const char *end;
		size_t convlen = 0;
		mdn_result_t r;

		/*
		 * Find the end of this component (label).
		 */
		if ((end = strchr(from, '.')) == NULL)
			end = from + strlen(from);

		/*
		 * Convert it.
		 */
		if (end > from) {
			if (dir == mdn_converter_l2u)
				r = l2u(ctx, from, end, to, tolen, &convlen);
			else
				r = u2l(ctx, from, end, to, tolen, &convlen);
			if (r != mdn_success)
				return (r);
		}

		/*
		 * Copy '.' or NUL.
		 */
		if (tolen <= convlen)
			return (mdn_buffer_overflow);

		to += convlen;
		*to++ = *end;
		tolen -= convlen + 1;

		/*
		 * Finished?
		 */
		if (*end == '\0') {
			break;
		} else if (*(end + 1) == '\0') {
			/* End with '.' */
			if (tolen < 1)
				return (mdn_buffer_overflow);
			*to++ = '\0';
			tolen--;
			break;
		}

		from = end + 1;
	}

	return (mdn_success);
}

static mdn_result_t
l2u(mdn__ace_t *ctx, const char *from, const char *end,
    char *to, size_t tolen, size_t *clenp)
{
	size_t acelen = end - from;
	size_t idlen = strlen(ctx->id_str);
	size_t utflen;
	const char *top;
	mdn_result_t r;
	char *buf;
	char local_buf[256];

	if (ctx->id_type == mdn__ace_prefix &&
	    acelen >= idlen &&
	    mdn_util_casematch(from, ctx->id_str, idlen)) {
		/*
		 * Prefix found.
		 */
		top = from + idlen;
		acelen -= idlen;
	} else if (ctx->id_type == mdn__ace_suffix &&
		   acelen >= idlen &&
		   mdn_util_casematch(end - idlen, ctx->id_str, idlen)) {
		/*
		 * Suffix found.
		 */
		top = from;
		acelen -= idlen;
	} else {
		/*
		 * Not ACE encoded.
		 */
	copy:
		/*
		 * Check if it comforms to STD-13.
		 */
		if (!mdn_util_validstd13(from, end)) {
			/* invalid character found */
			return (mdn_invalid_encoding);
		}

		/*
		 * Copy verbatim.
		 */
		acelen = end - from;
		if (tolen < acelen)
			return (mdn_buffer_overflow);
		(void)memcpy(to, from, acelen);

		*clenp = acelen;
		return (mdn_success);
	}

	/*
	 * Now, top and acelen refers the ACE encoded name
	 * without prefix/suffix.
	 */

	/* Decode it. */
	r = (*ctx->decoder)(top, acelen, to, tolen);
	if (r == mdn_invalid_encoding)
		goto copy;
	else if (r != mdn_success)
		return (r);

	*clenp = utflen = strlen(to);

	/*
	 * Check if the decode result is a STD13 conforming name.
	 */
	if (mdn_util_validstd13(to, to + utflen))
		return (mdn_invalid_encoding);

	/*
	 * Do round-trip conversion check.  Encode the decoded result,
	 * and compare it with the original.  If they don't match,
	 * the original name must be illegally encoded.
	 *
	 * We need a buffer at least acelen+1 (for the NUL byte) bytes long.
	 */
	if (acelen >= sizeof(local_buf)) {
		if ((buf = malloc(acelen + 1)) == NULL)
			return (mdn_nomemory);
	} else {
		buf = local_buf;
	}
	if ((*ctx->encoder)(to, utflen, buf, acelen + 1) != mdn_success ||
	    strlen(buf) != acelen ||
	    !mdn_util_casematch(buf, top, acelen)) {
		r = mdn_invalid_encoding;
	}
	if (buf != local_buf)
		free(buf);

	return (r);
}

static mdn_result_t
u2l(mdn__ace_t *ctx, const char *from, const char *end,
    char *to, size_t tolen, size_t *clenp)
{
	size_t len = end - from;

	/*
	 * See if encoding is really necessary.
	 */
	if (!mdn_util_validstd13(from, end)) {
		/*
		 * Conversion is necessary.
		 */
		mdn_result_t r;
		size_t idlen = strlen(ctx->id_str);
		size_t acelen;

		if (ctx->id_type == mdn__ace_prefix) {
			/* Prepend prefix. */
			if (tolen < idlen)
				return (mdn_buffer_overflow);
			(void)memcpy(to, ctx->id_str, idlen);
			to += idlen;
			tolen -= idlen;
		}

		r = (*ctx->encoder)(from, len, to, tolen);
		if (r != mdn_success)
			return (r);
		acelen = strlen(to);

		if (ctx->id_type == mdn__ace_suffix) {
			/* Append suffix. */
			if (acelen + idlen > tolen)
				return (mdn_buffer_overflow);
			(void)memcpy(to + acelen, ctx->id_str, idlen);
		}

		len = idlen + acelen;
	} else {
		/*
		 * Conversion is NOT necessary.
		 * Copy verbatim.
		 */

		if (tolen < len)
			return (mdn_buffer_overflow);

		(void)memcpy(to, from, len);
	}
	*clenp = len;
	return (mdn_success);
}
