#ifndef lint
static char *rcsid = "$Id: mapselector.c,v 1.1.2.1 2002/02/08 12:14:05 marka Exp $";
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

#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/result.h>
#include <mdn/mapselector.h>
#include <mdn/strhash.h>
#include <mdn/debug.h>

struct mdn_mapselector {
	mdn_strhash_t maphash;
	int reference_count;
};

/*
 * Maximum length of a top level domain name. (e.g. `com', `jp', ...)
 */
#define MAPSELECTOR_MAX_TLD_LENGTH	63

static void *memrchr(const void *s, int c, size_t n);
static void string_ascii_tolower(char *string);

mdn_result_t
mdn_mapselector_initialize(void) {
	TRACE(("mdn_mapselector_initialize()\n"));

	return mdn_mapper_initialize();
}

mdn_result_t
mdn_mapselector_create(mdn_mapselector_t *ctxp) {
	mdn_mapselector_t ctx = NULL;
	mdn_result_t r;

	assert(ctxp != NULL);
	TRACE(("mdn_mapselector_create()\n"));

	ctx = (mdn_mapselector_t)malloc(sizeof(struct mdn_mapselector));
	if (ctx == NULL) {
		WARNING(("mdn_mapselector_create: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	ctx->maphash = NULL;
	ctx->reference_count = 1;

	r = mdn_strhash_create(&(ctx->maphash));
	if (r != mdn_success)
		goto failure;

	*ctxp = ctx;

	return (mdn_success);

failure:
	if (ctx != NULL)
		free(ctx->maphash);
	free(ctx);
	return (r);
}

void
mdn_mapselector_destroy(mdn_mapselector_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_mapselector_destroy()\n"));
	TRACE(("mdn_mapselector_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_mapselector_destroy: the object is destroyed\n"));
		mdn_strhash_destroy(ctx->maphash,
			(mdn_strhash_freeproc_t)&mdn_mapper_destroy);
		free(ctx);
	}
}

void
mdn_mapselector_incrref(mdn_mapselector_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_mapselector_incrref()\n"));
	TRACE(("mdn_mapselector_incrref: update reference count (%d->%d)\n",
		ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
}

mdn_result_t
mdn_mapselector_add(mdn_mapselector_t ctx, const char *tld, const char *name) {
	mdn_result_t r;
	mdn_mapper_t mapper;
	char hash_key[MAPSELECTOR_MAX_TLD_LENGTH + 1];

	assert(ctx != NULL && tld != NULL);

	TRACE(("mdn_mapselector_add(tld=%s, name=%s)\n", tld, name));

	if (*tld != '.' || *(tld + 1) != '\0') {
		if (*tld == '.')
			tld++;
		if (strchr(tld, '.') != NULL)
			return (mdn_invalid_name);
	}
	if (strlen(tld) > MAPSELECTOR_MAX_TLD_LENGTH)
		return (mdn_invalid_name);
	strcpy(hash_key, tld);
	string_ascii_tolower(hash_key);

	if (mdn_strhash_get(ctx->maphash, hash_key, (void **)&mapper)
		!= mdn_success) {
		r = mdn_mapper_create(&mapper);
		if (r != mdn_success)
			return (r);

		r = mdn_strhash_put(ctx->maphash, hash_key, mapper);
		if (r != mdn_success)
			return (r);
	}

	return (mdn_mapper_add(mapper, name));
}

mdn_result_t
mdn_mapselector_addall(mdn_mapselector_t ctx, const char *tld,
		       const char **scheme_names, int nschemes) {
	mdn_result_t r;
	int i;

	assert(ctx != NULL && tld != NULL && scheme_names != NULL);

	TRACE(("mdn_mapselector_addall(tld=%s, nschemes=%d)\n", 
	      tld, nschemes));

	for (i = 0; i < nschemes; i++) {
		r = mdn_mapselector_add(ctx, tld, (const char *)*scheme_names);
		if (r != mdn_success)
			return (r);
		scheme_names++;
	}

	return (mdn_success);
}

mdn_mapper_t
mdn_mapselector_mapper(mdn_mapselector_t ctx, const char *tld) {
	mdn_result_t r;
	mdn_mapper_t mapper;
	char hash_key[MAPSELECTOR_MAX_TLD_LENGTH + 1];

	assert(ctx != NULL && tld != NULL);

	TRACE(("mdn_mapselector_mapper(tld=%s)\n", tld));

	if (*tld != '.' || *(tld + 1) != '\0') {
		if (*tld == '.')
			tld++;
		if (strchr(tld, '.') != NULL)
			return (NULL);
	}
	if (strlen(tld) > MAPSELECTOR_MAX_TLD_LENGTH)
		return (NULL);
	strcpy(hash_key, tld);
	string_ascii_tolower(hash_key);

	mapper = NULL;
	r = mdn_strhash_get(ctx->maphash, hash_key, (void **)&mapper);
	if (r != mdn_success)
		return (NULL);

	mdn_mapper_incrref(mapper);

	return (mapper);
}

mdn_result_t
mdn_mapselector_map(mdn_mapselector_t ctx, 
                    const char *from, char *to, size_t tolen) {
	mdn_result_t r;
	mdn_mapper_t mapper = NULL;
	char tld[MAPSELECTOR_MAX_TLD_LENGTH + 1];
	size_t fromlen;
	size_t tldlen;
	const char *last_dot;

	assert(ctx != NULL && from != NULL && to != NULL);

	TRACE(("mdn_mapselector_map(from=\"%s\")\n",
		mdn_debug_xstring(from, 20)));

	fromlen = strlen(from);

	/*
	 * Get TLD from `from'.
	 */
	if (from[0] == '\0') {
		/* 'from' is empty. */
		tld[0] = '\0';
	} else if (from[0] == '.' && from[1] == '\0') {
		/* 'from' is just a '.'. */
		tld[0] = '\0';
	} else if (from[fromlen - 1] == '.') {
		/*
		 * 'from' ends with dot.
		 */
		const char *tld_top;

		/* Find the second last dot. */
		last_dot = memrchr(from, '.', fromlen - 1);
		if (last_dot == NULL) {
			/* 'from' is a single label followed by a dot. */
			tld_top = from;
		} else {
			tld_top = last_dot + 1;
		}
		tldlen = strlen(tld_top) - 1;
		if (tldlen > MAPSELECTOR_MAX_TLD_LENGTH)
			return (mdn_invalid_name);
		memcpy(tld, tld_top, tldlen);
		tld[tldlen] = '\0';
	} else {
		/* Find the last dot. */
		last_dot = memrchr(from, '.', fromlen);
		if (last_dot == NULL) {
			/* 'from' contains no dots. */
			strcpy(tld, MDN_MAPSELECTOR_NO_TLD);
		} else {
			tldlen = strlen(last_dot + 1);
			if (tldlen > MAPSELECTOR_MAX_TLD_LENGTH)
				return (mdn_invalid_name);
			memcpy(tld, last_dot + 1, tldlen);
			tld[tldlen] = '\0';
		}
	}

	string_ascii_tolower(tld);

	/*
	 * Get the mapper for the TLD.
	 */
	if (tld[0] != '\0' &&
		mdn_strhash_get(ctx->maphash, tld, (void **)&mapper)
		!= mdn_success) {
		strcpy(tld, MDN_MAPSELECTOR_DEFAULT);
		mdn_strhash_get(ctx->maphash, tld, (void **)&mapper);
	}

	/*
	 * Map.
	 * If default mapper has not been registered, copy the string.
	 */
	if (mapper == NULL) {
		TRACE(("mdn_mapselector_map: no mapper\n"));
		if (fromlen + 1 > tolen)
			return (mdn_buffer_overflow);
		memcpy(to, from, fromlen + 1);
		r = mdn_success;
	} else {
		TRACE(("mdn_mapselector_map: tld=%s\n", tld));
		r = mdn_mapper_map(mapper, from, to, tolen);
	}

	return (r);
}


/*
 * The memrchr() function returns the last occurrence of c (converted to
 * an unsigned char) in the first n characters (each character is converted
 * to an unsigned char) of the object s, or returns NULL if c does not
 * occur.
 */
static void *
memrchr(const void *s, int c, size_t n) {
	const unsigned char *p = (const unsigned char *)s;
	void *save = NULL;

	if (n == 0)
		return (NULL);

	do {
		if (*p == c)
			save = (void *)p;
		p++;
	} while (--n != 0);

	return (save);
}


static void
string_ascii_tolower(char *string)
{
	unsigned char *p;

	for (p = (unsigned char *) string; *p != '\0'; p++) {
		if ('A' <= *p && *p <= 'Z')
			*p = *p - 'A' + 'a';
	}
}

#ifdef TEST
#include <stdio.h>

/*
 * Test program for this module.
 *
 * The test program repeatedly prompt you to input a command.  The
 * following command is currently recognized.
 *
 *    tolen N		set the length of output buffer. (1...1024)
 *    add TLD           add selectable map for TLD. (e.g. com, jp)
 *    DOMANNAME         try mapping DOMANNAME.
 *
 * Input EOF to exit.
 */
int
main(int ac, char **av) {
	mdn_mapselector_t ctx;
	char from[1024], to[1024];
	size_t fromlen, tolen = sizeof(to);
	mdn_result_t r;

	mdn_log_setlevel(mdn_log_level_trace);
	mdn_mapselector_initialize();
	r = mdn_mapselector_create(&ctx);
	if (r != mdn_success) {
		fprintf(stderr, "mdn_mapselector_create: %s\n",
			mdn_result_tostring(r));
		return 1;
	}
	while (fgets(from, sizeof(from), stdin) != NULL) {
		fromlen = strlen(from);
		if (from[fromlen - 1] == '\n')
			from[fromlen - 1] = '\0';
		if (from[0] == '\0')
			continue;

		if (strncmp(from, "tolen ", 6) == 0) {
			tolen = atoi(from + 6);
		} else if (strncmp(from, "add ", 4) == 0) {
			r = mdn_mapselector_add(ctx, from + 4, "dummy");
			if (r != mdn_success) {
				fprintf(stderr, "mdn_mapselector_add: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}
		} else {
			r = mdn_mapselector_map(ctx, from, to, tolen);
			if (r != mdn_success) {
				fprintf(stderr, "mdn_mapselector_map: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}
		}
	}

	mdn_mapselector_destroy(ctx);
	return 0;
}

#endif /* TEST */
