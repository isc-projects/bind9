#ifndef lint
static char *rcsid = "$Id: delimitermap.c,v 1.1.2.1 2002/02/08 12:13:52 marka Exp $";
#endif

/*
 * Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
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
#include <mdn/delimitermap.h>
#include <mdn/util.h>
#include <mdn/debug.h>
#include <mdn/utf8.h>

/*
 * Mapper object type.
 */
struct mdn_delimitermap {
	int ndelimiters;
	int delimiter_size;
	unsigned long *delimiters;
	int reference_count;
};

#define DELIMITERMAP_INITIAL_DELIMITER_SIZE	4

mdn_result_t
mdn_delimitermap_create(mdn_delimitermap_t *ctxp) {
	mdn_delimitermap_t ctx = NULL;
	mdn_result_t r;

	assert(ctxp != NULL);
	TRACE(("mdn_delimitermap_create()\n"));

	ctx = (mdn_delimitermap_t) malloc(sizeof(struct mdn_delimitermap));
	if (ctx == NULL) {
		WARNING(("mdn_mapper_create: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	ctx->delimiters = (unsigned long *) malloc(sizeof(unsigned long)
		* DELIMITERMAP_INITIAL_DELIMITER_SIZE);
	if (ctx->delimiters == NULL) {
		WARNING(("mdn_delimitermap_create: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}
	ctx->ndelimiters = 0;
	ctx->delimiter_size = DELIMITERMAP_INITIAL_DELIMITER_SIZE;
	ctx->reference_count = 1;
	*ctxp = ctx;

	return (mdn_success);

failure:
	free(ctx);
	return (r);
}

void
mdn_delimitermap_destroy(mdn_delimitermap_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_delimitermap_destroy()\n"));
	TRACE(("mdn_delimitermap_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_mapper_destroy: the object is destroyed\n"));
		free(ctx->delimiters);
		free(ctx);
	}
}

void
mdn_delimitermap_incrref(mdn_delimitermap_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_delimitermap_incrref()\n"));
	TRACE(("mdn_delimitermap_incrref: update reference count (%d->%d)\n",
		ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
}

mdn_result_t
mdn_delimitermap_add(mdn_delimitermap_t ctx, unsigned long delimiter) {
	mdn_result_t r;

	assert(ctx != NULL && ctx->ndelimiters <= ctx->delimiter_size);
	TRACE(("mdn_delimitermap_add(delimiter=%lX)\n", delimiter));

	if (ctx->ndelimiters == ctx->delimiter_size) {
		unsigned long *new_delimiters;

		new_delimiters = (unsigned long *) realloc(ctx->delimiters,
			sizeof(unsigned long) * ctx->delimiter_size * 2);
		if (new_delimiters == NULL) {
			WARNING(("mdn_checker_add: malloc failed\n"));
			r = mdn_nomemory;
			goto failure;
		}
		ctx->delimiters = new_delimiters;
		ctx->delimiter_size *= 2;
	}

	ctx->delimiters[ctx->ndelimiters] = delimiter;
	ctx->ndelimiters++;

	return (mdn_success);

failure:
	if (ctx != NULL)
		free(ctx->delimiters);
	free(ctx);
	return (r);
}

mdn_result_t
mdn_delimitermap_addall(mdn_delimitermap_t ctx, unsigned long *delimiters,
			int ndelimiters) {
	mdn_result_t r;
	int i;

	assert(ctx != NULL && delimiters != NULL);

	TRACE(("mdn_delimitermap_addall(ndelimiters=%d)\n", ndelimiters));

	for (i = 0; i < ndelimiters; i++) {
		r = mdn_delimitermap_add(ctx, *delimiters);
		if (r != mdn_success)
			return (r);
		delimiters++;
	}

	return (mdn_success);
}

mdn_result_t
mdn_delimitermap_map(mdn_delimitermap_t ctx, const char *from, char *to,
		     size_t tolen) {
	size_t fromlen;
	size_t mblen;
	unsigned long wc;
	int i, j;

	assert(ctx != NULL && from != NULL && to != NULL);

	TRACE(("mdn_delimitermap_map(from=\"%s\")\n",
		mdn_debug_xstring(from, 20)));

	fromlen = strlen(from);

	/*
	 * Copy the string if no delimiter is added.
	 */
	if (ctx->ndelimiters == 0) {
		if (fromlen + 1 > tolen)
			return (mdn_buffer_overflow);
		memcpy(to, from, fromlen + 1);
		return (mdn_success);
	}

	/*
	 * Map.
	 */
	while (fromlen > 0) {
		mblen = mdn_utf8_getwc(from, fromlen, &wc);
		if (mblen == 0)
			return (mdn_invalid_encoding);

		for (i = 0; i < ctx->ndelimiters; i++) {
			if (ctx->delimiters[i] == wc)
				break;
		}
		if (i < ctx->ndelimiters) {
			if (tolen < 1)
				return (mdn_buffer_overflow);
			from += mblen;
			*to++ = '.';
			tolen--;
		} else {
			if (tolen < mblen)
				return (mdn_buffer_overflow);
			for (j = 0; j < mblen; j++)
				*to++ = *from++;
			tolen -= mblen;
		}

		fromlen -= mblen;
	}

	if (tolen < 1)
		return (mdn_buffer_overflow);
	*to = '\0';

	return (mdn_success);
}

#ifdef TEST
#include <stdio.h>
#include <mdn/converter.h>

/*
 * Test program for this module.
 *
 * The test program repeatedly prompt you to input a command.  The
 * following command is currently recognized.
 *
 *    tolen N		set the length of output buffer. (1...1024)
 *    DOMANNAME         try mapping DOMANNAME.
 *
 * Input EOF to exit.
 */
int
main(int ac, char **av) {
	mdn_delimitermap_t mapper;
	mdn_converter_t converter;
	char local[1024], utf8[1024];
	size_t locallen, utf8len = sizeof(utf8);
	mdn_result_t r;

	if (ac != 2) {
		fprintf(stderr, "usage: %s local-encoding-name\n", av[0]);
		exit(EXIT_FAILURE);
	}

	mdn_log_setlevel(mdn_log_level_trace);
	mdn_converter_initialize();

	r = mdn_converter_create(av[1], &converter, 0);
	if (r != mdn_success) {
		fprintf(stderr, "mdn_converter_create: %s\n",
			mdn_result_tostring(r));
		return 1;
	}

	r = mdn_delimitermap_create(&mapper);
	if (r != mdn_success) {
		fprintf(stderr, "mdn_delimitermap_create: %s\n",
			mdn_result_tostring(r));
		return 1;
	}

	r = mdn_delimitermap_add(mapper, 0x3002);
	if (r != mdn_success) {
		fprintf(stderr, "mdn_delimitermap_add: %s\n",
			mdn_result_tostring(r));
		return 1;
	}
	mdn_delimitermap_fix(mapper);

	while (fgets(local, sizeof(local), stdin) != NULL) {
		locallen = strlen(local);
		if (local[locallen - 1] == '\n')
			local[locallen - 1] = '\0';
		if (local[0] == '\0')
			continue;

		if (strncmp(local, "tolen ", 6) == 0) {
			utf8len = atoi(local + 6);
		} else {
			r = mdn_converter_localtoutf8(converter, local, utf8, 
				sizeof(utf8));
			if (r != mdn_success) {
				fprintf(stderr,
					"mdn_converter_localtoutf8: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}

			r = mdn_delimitermap_map(mapper, utf8, utf8, utf8len);
			if (r != mdn_success) {
				fprintf(stderr, "mdn_delimitermap_map: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}

			r = mdn_converter_utf8tolocal(converter, utf8, local,
				sizeof(local));
			if (r != mdn_success) {
				fprintf(stderr,
					"mdn_converter_utf8tolocal: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}

			fprintf(stderr, "%s\n", local);
		}
	}

	mdn_delimitermap_destroy(mapper);
	return 0;
}

#endif /* TEST */
