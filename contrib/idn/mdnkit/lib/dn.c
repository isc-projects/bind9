#ifndef lint
static char *rcsid = "$Id: dn.c,v 1.1 2002/01/02 02:46:41 marka Exp $";
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

/*
 * Domain name compression/expansion.
 *
 * Similar to the functionality of dn_comp/dn_expand in the resolv library.
 * In fact, the loop detection in mdn__dn_expand is borrowed from
 * ns_name_unpack.
 */

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/dn.h>

#define COMPRESS_MASK	0xc0
#define COMPRESS_FLAG	0xc0
#define MAX_OFFSET	0x3fff

#define MAXNAMELEN	1024
#define MAXLABEL	63
#define MAXCOMPRESS	255

/*
 * uppercase -> lowercase conversion table, to be initialized
 * by init_lcase().
 */
static char lcase[128];

static mdn_result_t	split_name(const char *name, unsigned char *namebuf);
static int		find_label(const unsigned char *p, int limit,
				   mdn__dn_t *ctx);
static int		match(const unsigned char *p, const unsigned char *q,
			      mdn__dn_t *ctx);
static void		append_ptr(mdn__dn_t *ctx, unsigned char *ptr);
static int		get_offset(const unsigned char *p);
static void		init_lcase(void);


mdn_result_t
mdn__dn_expand(const char *msg, size_t msglen, const char *compressed,
	       char *expanded, size_t buflen, size_t *complenp)
{
	const unsigned char *p = (const unsigned char *)compressed;
	const unsigned char *ueom = (const unsigned char *)(msg + msglen);
	int compress_len = 0;
	size_t checked = 0;

	assert(msg != NULL && expanded != NULL && complenp != NULL);

	/*
	 * Sanity check.
	 */
	if (compressed < msg || msg + msglen <= compressed)
		return (mdn_invalid_message);

	if (*p == 0) {
		/* Root label */
		if (buflen < 2)
			return (mdn_buffer_overflow);
		(void)strcpy(expanded, ".");
		*complenp = 1;
		return (mdn_success);
	}

	while (p < ueom) {
		int c = *p++;
		size_t len;

		len = c & ~COMPRESS_MASK;

		if (c == 0) {
			if (compress_len == 0)
				compress_len = (const char *)p - compressed;
			*complenp = compress_len;
			return (mdn_success);
		} else if ((c & COMPRESS_MASK) == 0) {
			if (p + len > ueom)
				return (mdn_invalid_message);
			if (buflen < len + 2)
				return (mdn_buffer_overflow);
			(void)memcpy(expanded, p, len);
			(void)strcpy(expanded + len, "."); /* dot and NUL */
			p += len;
			checked += len + 1;
			expanded += len + 1;
			buflen -= len + 1;
		} else if ((c & COMPRESS_MASK) == COMPRESS_FLAG) {
			if (p >= ueom)
				return (mdn_invalid_message);
			len = (len << 8) + *p++;
			if (compress_len == 0)
				compress_len = (const char *)p - compressed;
			p = (const unsigned char *)(msg + len);

			/*
			 * Loop detection.
			 */
			checked += 2;
			if (checked >= msglen) {
				WARNING(("mdn__dn_expand: loop detected\n"));
				return (mdn_invalid_message);
			}
		} else {
			return (mdn_invalid_message);
		}
	}
	return (mdn_invalid_message);
}

void
mdn__dn_initcompress(mdn__dn_t *ctx, const char *msg) {
	ctx->msg = (const unsigned char *)msg;
	ctx->cur = 0;
}

mdn_result_t
mdn__dn_compress(const char *name, char *sptr, size_t length,
		 mdn__dn_t *ctx, size_t *complenp)
{
	unsigned char namebuf[MAXNAMELEN+1];
	unsigned char *ptr, *p;
	mdn_result_t r;
	int offset_limit;
	static int initialized = 0;

	if (!initialized) {
		init_lcase();
		initialized = 1;
	}

	/*
	 * Split domain name into labels.
	 */
	if ((r = split_name(name, namebuf)) != mdn_success)
		return (r);

	p = namebuf;
	ptr = (unsigned char *)sptr;
	offset_limit = ctx->cur;
	while (*p != 0) {
		int off;

		if ((off = find_label(p, offset_limit, ctx)) >= 0) {
			if (length < 2)
				return (mdn_buffer_overflow);

			ptr[0] = COMPRESS_FLAG | (off >> 8);
			ptr[1] = off & 0xff;
			ptr += 2;
			if ((*complenp = (char *)ptr - sptr) > MAXCOMPRESS)
				return (mdn_invalid_name);
			return (mdn_success);
		} else {
			int l = *p + 1;

			if (length < l)
				return (mdn_buffer_overflow);

			(void)memcpy(ptr, p, l);
			append_ptr(ctx, ptr);

			ptr += l;
			length -= l;
		}
		p += *p + 1;
	}
	if (length < 1)
		return (mdn_buffer_overflow);
	*ptr++ = 0;
	if ((*complenp = (char *)ptr - sptr) > MAXCOMPRESS)
		return (mdn_invalid_name);
	return (mdn_success);
}

static mdn_result_t
split_name(const char *name, unsigned char *namebuf) {
	const unsigned char *p = (const unsigned char *)name;
	const unsigned char *end = p + MAXNAMELEN;
	unsigned char *q, *qtop;

	q = namebuf;
	qtop = q++;
	while (p < end) {
		if (*p == '.' || *p == '\0') {
			int len = q - qtop - 1;
			if (len > MAXLABEL)
				return (mdn_invalid_name);
			*qtop = len;
			qtop = q++;
			if (*p == '\0') {
				*qtop = 0;
				return (mdn_success);
			}
			p++;
		} else {
			*q++ = *p++;
		}
	}
	/* Name too long. */
	return (mdn_invalid_name);
}

static int
find_label(const unsigned char *p, int limit, mdn__dn_t *ctx) {
	int i;

	assert(limit <= ctx->cur);

	if (ctx == NULL)
		return (-1);

	for (i = 0; i < limit; i++) {
		if (match(p, ctx->msg + ctx->offset[i], ctx))
			return (ctx->offset[i]);
	}
	return (-1);
}

static int
match(const unsigned char *p, const unsigned char *q, mdn__dn_t *ctx) {
	for (;;) {
		int len, l;

		/* Dereference 'q'. */
		while ((*q & COMPRESS_FLAG) != 0) {
			int offset = get_offset(q);

			if (offset < 0 || offset > MAX_OFFSET)
				return (0);
			q = ctx->msg + offset;
		}

		/* Check length. */
		len = *p++;
		if (*q++ != len)
			return (0);

		if (len == 0)
			return (1);

		/* Compare labels. */
		for (l = 0; l < len; l++, p++, q++) {
			if (*p == *q)
				continue;
			else if (*p < 128 && *q < 128 &&
				 lcase[*p] == lcase[*q])
				continue;
			else
				return (0);
		}
	}
}

static void
append_ptr(mdn__dn_t *ctx, unsigned char *ptr) {
	if (ctx != NULL && ctx->cur < MDN_DN_NPTRS &&
	    ptr >= ctx->msg && (ptr - ctx->msg) <= MAX_OFFSET)
		ctx->offset[ctx->cur++] = ptr - ctx->msg;
}

static int
get_offset(const unsigned char *p) {
	return (((p[0] & ~COMPRESS_MASK) << 8) | p[1]);
}

static void
init_lcase(void) {
	int i;

	for (i = 0; i < 128; i++)
		lcase[i] = i;
	for (i = 'A'; i <= 'Z'; i++)
		lcase[i] += 'a' - 'A';
}
