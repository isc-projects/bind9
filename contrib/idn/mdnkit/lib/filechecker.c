#ifndef lint
static char *rcsid = "$Id: filechecker.c,v 1.1.2.1 2002/02/08 12:13:56 marka Exp $";
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/log.h>
#include <mdn/logmacro.h>
#include <mdn/utf8.h>
#include <mdn/ucsset.h>
#include <mdn/filechecker.h>

#define SUPPORT_VERSIONING

struct mdn__filechecker {
	mdn_ucsset_t set;
};

static mdn_result_t	read_file(const char *file, FILE *fp,
				  mdn_ucsset_t set);
static int		get_range(char *s, unsigned long *ucs1,
				  unsigned long *ucs2);
static char		*get_ucs(char *p, unsigned long *vp);


mdn_result_t
mdn__filechecker_create(const char *file, mdn__filechecker_t *ctxp) {
	FILE *fp;
	mdn__filechecker_t ctx;
	mdn_result_t r;

	assert(file != NULL && ctxp != NULL);

	TRACE(("mdn__filechecker_create(file=\"%-.100s\")\n", file));

	if ((fp = fopen(file, "r")) == NULL) {
		WARNING(("mdn__filechecker_create: cannot open %-.100s\n",
			 file));
		return (mdn_nofile);
	}

	if ((ctx = malloc(sizeof(struct mdn__filechecker))) == NULL)
		return (mdn_nomemory);

	if ((r = mdn_ucsset_create(&ctx->set)) != mdn_success) {
		free(ctx);
		return (r);
	}

	r = read_file(file, fp, ctx->set);
	fclose(fp);

	if (r == mdn_success) {
		mdn_ucsset_fix(ctx->set);
		*ctxp = ctx;
	} else {
		mdn_ucsset_destroy(ctx->set);
		free(ctx);
	}
	return (r);
}

void
mdn__filechecker_destroy(mdn__filechecker_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn__filechecker_destroy()\n"));

	mdn_ucsset_destroy(ctx->set);
	free(ctx);
}

mdn_result_t
mdn__filechecker_lookup(mdn__filechecker_t ctx, const char *str,
			const char **found)
{
	mdn_result_t r = mdn_success;
	unsigned long v;
	size_t len = strlen(str);

	assert(ctx != NULL && str != NULL);

	while (len > 0) {
		int w;
		int exists;

		if ((w = mdn_utf8_getwc(str, len, &v)) == 0)
			return (mdn_invalid_encoding);

		r = mdn_ucsset_lookup(ctx->set, v, &exists);

		if (r != mdn_success) {
			return (r);
		} else if (exists) {
			/* Found. */
			*found = str;
			return (mdn_success);
		}

		str += w;
		len -= w;
	}
	*found = NULL;
	return (mdn_success);
}

static mdn_result_t
read_file(const char *file, FILE *fp, mdn_ucsset_t set) {
	char line[256];
	mdn_result_t r;
	int lineno = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p = line;
		unsigned long ucs1, ucs2;

		lineno++;
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '\0' || *p == '#')
			continue;

#ifdef SUPPORT_VERSIONING
		/* Skip version tag. */
		if (lineno == 1 && strncmp("version=", line, 8) == 0)
			continue;
#endif
		if (!get_range(p, &ucs1, &ucs2)) {
			WARNING(("syntax error in file \"%-.100s\" line %d: "
				 "%-.100s", file, lineno, line));
			return (mdn_invalid_syntax);
		}
		if ((r = mdn_ucsset_addrange(set, ucs1, ucs2)) != mdn_success)
			return (r);
	}
	return (mdn_success);
}

static int
get_range(char *s, unsigned long *ucs1, unsigned long *ucs2) {
	if ((s = get_ucs(s, ucs1)) == NULL)
		return (0);
	*ucs2 = *ucs1;

	switch (s[0]) {
	case '\0':
	case '\n':
	case '#':
	case ';':
		return (1);
	case '-':
		break;
	default:
		return (0);
	}

	if ((s = get_ucs(s + 1, ucs2)) == NULL)
		return (0);

	if (*ucs1 > *ucs2) {
		INFO(("mdn__filechecker_create: invalid range spec "
		      "U+%X-U+%X\n", *ucs1, *ucs2));
		return (0);
	}

	switch (s[0]) {
	case '\0':
	case '\n':
	case '#':
	case ';':
		return (1);
	default:
		return (0);
	}
}


static char *
get_ucs(char *p, unsigned long *vp) {
	char *end;

	/* Skip leading space */
	while (isspace((unsigned char)*p))
		p++;

	/* Skip optional 'U+' */
	if (strncmp(p, "U+", 2) == 0)
		p += 2;

	*vp = strtoul(p, &end, 16);
	if (end == p) {
		INFO(("mdn__filechecker_create: UCS code point expected\n"));
		return (NULL);
	}
	p = end;

	/* Skip trailing space */
	while (isspace((unsigned char)*p))
		p++;
	return p;
}

mdn_result_t
mdn__filechecker_createproc(const char *parameter, void **ctxp) {
	return mdn__filechecker_create(parameter, (mdn__filechecker_t *)ctxp);
}

void
mdn__filechecker_destroyproc(void *ctxp) {
	mdn__filechecker_destroy((mdn__filechecker_t)ctxp);
}

mdn_result_t
mdn__filechecker_lookupproc(void *ctx, const char *str, const char **found) {
	return mdn__filechecker_lookup((mdn__filechecker_t)ctx, str, found);
}


#ifdef TEST
int
main(int ac, char **av) {
	mdn__filechecker_t chk;
	mdn_result_t r;
	char line[1024];
	char *found;
	int lineno = 0;

	if (ac < 2) {
		fprintf(stderr, "Usage: %s file\n", av[0]);
		return 1;
	}
	r = mdn__filechecker_create(av[1], &chk);
	if (r != mdn_success) {
		fprintf(stderr, "mdn__filechecker_create: %s\n",
			mdn_result_tostring(r));
		return 1;
	}
	while (fgets(line, sizeof(line), stdin) != NULL) {
		int valid;
		size_t len = strlen(line);

		lineno++;
		/* since \n is likely to be prohibited, remove it beforehand */
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';

		r = mdn__filechecker_check(priv, line, &found);
		if (r != mdn_success) {
			fprintf(stderr, "error at line %d: %s\n",
				lineno, mdn_result_tostring(r));
			return 1;
		}
		if (found != NULL) {
			printf("line %d: invalid\n", lineno);
		}
	}
	return 0;
}
#endif /* TEST */
