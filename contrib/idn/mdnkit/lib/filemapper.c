#ifndef lint
static char *rcsid = "$Id: filemapper.c,v 1.1.2.1 2002/02/08 12:13:57 marka Exp $";
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
#include <mdn/debug.h>
#include <mdn/utf8.h>
#include <mdn/ucsmap.h>
#include <mdn/filemapper.h>

#define SUPPORT_VERSIONING

#define UCSBUF_LOCAL_SIZE	20

typedef struct ucsbuf {
	unsigned long *ucs;
	size_t size;
	size_t len;
	unsigned long local[UCSBUF_LOCAL_SIZE];
} ucsbuf_t;

struct mdn__filemapper {
	mdn_ucsmap_t map;
};

static void		ucsbuf_init(ucsbuf_t *b);
static mdn_result_t	ucsbuf_grow(ucsbuf_t *b);
static mdn_result_t	ucsbuf_append(ucsbuf_t *b, unsigned long v);
static void		ucsbuf_free(ucsbuf_t *b);
static mdn_result_t	read_file(const char *file, FILE *fp,
				  mdn_ucsmap_t map);
static mdn_result_t	get_map(char *p, ucsbuf_t *b);
static char 		*get_ucs(char *p, unsigned long *vp);


mdn_result_t
mdn__filemapper_create(const char *file, mdn__filemapper_t *ctxp) {
	FILE *fp;
	mdn__filemapper_t ctx;
	mdn_result_t r;

	assert(file != NULL && ctxp != NULL);

	TRACE(("mdn__filemapper_create(file=\"%-.100s\")\n", file));

	if ((fp = fopen(file, "r")) == NULL) {
		WARNING(("mdn__filemapper_create: cannot open %-.100s\n",
			 file));
		return (mdn_nofile);
	}
	if ((ctx = malloc(sizeof(struct mdn__filemapper))) == NULL)
		return (mdn_nomemory);

	if ((r = mdn_ucsmap_create(&ctx->map)) != mdn_success) {
		free(ctx);
		return (r);
	}

	r = read_file(file, fp, ctx->map);
	fclose(fp);

	if (r == mdn_success) {
		mdn_ucsmap_fix(ctx->map);
		*ctxp = ctx;
	} else {
		mdn_ucsmap_destroy(ctx->map);
		free(ctx);
	}
	return (r);
}

void
mdn__filemapper_destroy(mdn__filemapper_t ctx) {

	assert(ctx != NULL);

	TRACE(("mdn__filemapper_destroy()\n"));

	mdn_ucsmap_destroy(ctx->map);
	free(ctx);
}

mdn_result_t
mdn__filemapper_map(mdn__filemapper_t ctx, const char *from,
		    char *to, size_t tolen)
{
	mdn_result_t r = mdn_success;
	unsigned long v;
	ucsbuf_t ub;
	size_t fromlen = strlen(from);

	assert(ctx != NULL && from != NULL && to != NULL);

	TRACE(("mdn__filemapper_map(from=\"%s\")\n",
	       mdn_debug_xstring(from, 40)));

	/* Initialize temporary buffer. */
	ucsbuf_init(&ub);

	while (fromlen > 0) {
		int i;
		int w;

		/* Get one character. */
		if ((w = mdn_utf8_getwc(from, fromlen, &v)) == 0) {
			r = mdn_invalid_encoding;
			break;
		}
		from += w;
		fromlen -= w;

	again:
		/* Try mapping. */
		r = mdn_ucsmap_map(ctx->map, v, ub.ucs, ub.size, &ub.len);
		switch (r) {
		case mdn_buffer_overflow:
			/* Temporary buffer too small.  Enlarge and retry. */
			if ((r = ucsbuf_grow(&ub)) != mdn_success)
				break;
			goto again;
		case mdn_nomapping:
			/* There is no mapping. */
			r = mdn_success;
			/* fallthrough */
		case mdn_success:
			for (i = 0; i < ub.len; i++) {
				w = mdn_utf8_putwc(to, tolen, ub.ucs[i]);
				if (w == 0) {
					r = mdn_buffer_overflow;
					break;
				}
				to += w;
				tolen -= w;
			}
			break;
		default:
			goto ret;
		}
	}

 ret:
	ucsbuf_free(&ub);

	if (r == mdn_success) {
		/* Terminate with NUL. */
		if (tolen == 0)
			return (mdn_buffer_overflow);
		*to = '\0';
	}

	return (r);
}

static void
ucsbuf_init(ucsbuf_t *b) {
	b->ucs = b->local;
	b->size = UCSBUF_LOCAL_SIZE;
	b->len = 0;
}

static mdn_result_t
ucsbuf_grow(ucsbuf_t *b) {
	if (b->ucs == b->local)
		b->ucs = NULL;
	b->size *= 2;
	b->ucs = realloc(b->ucs, sizeof(unsigned long) * b->size);
	if (b->ucs == NULL)
		return (mdn_nomemory);
	return (mdn_success);
}

static mdn_result_t
ucsbuf_append(ucsbuf_t *b, unsigned long v) {
	mdn_result_t r;

	if (b->len + 1 > b->size) {
		r = ucsbuf_grow(b);
		if (r != mdn_success)
			return (r);
	}
	b->ucs[b->len++] = v;
	return (mdn_success);
}

static void
ucsbuf_free(ucsbuf_t *b) {
	if (b->ucs != b->local)
		free(b->ucs);
}

static mdn_result_t
read_file(const char *file, FILE *fp, mdn_ucsmap_t map) {
	char line[1024];
	ucsbuf_t ub;
	mdn_result_t r = mdn_success;
	int lineno = 0;

	ucsbuf_init(&ub);

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p = line;

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
	again:
		ub.len = 0;
		r = get_map(p, &ub);
		switch (r) {
		case mdn_success:
			r = mdn_ucsmap_add(map, ub.ucs[0],
					   &ub.ucs[1], ub.len - 1);
			break;
		case mdn_buffer_overflow:
			if ((r = ucsbuf_grow(&ub)) != mdn_success)
				break;
			goto again;
		case mdn_invalid_syntax:
			WARNING(("syntax error in file \"%-.100s\" line %d: "
				 "%-.100s", file, lineno, line));
			/* fall through */
		default:
			return (r);
		}
	}
	ucsbuf_free(&ub);
	return (r);
}

static mdn_result_t
get_map(char *p, ucsbuf_t *b) {
	unsigned long v;
	mdn_result_t r = mdn_success;

	for (;;) {
		if ((p = get_ucs(p, &v)) == NULL)
			return (mdn_invalid_syntax);
		if ((r = ucsbuf_append(b, v)) != mdn_success)
			return (r);
		if (b->len == 1) {
			if (*p != ';')
				return (mdn_invalid_syntax);
			p++;
			while (isspace((unsigned char)*p))
				p++;
		}

		if (*p == ';' || *p == '#' || *p == '\0')
			return (r);
	}
	return (r);
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
		INFO(("mdn__filemapper_create: UCS code point expected\n"));
		return (NULL);
	}
	p = end;

	/* Skip trailing space */
	while (isspace((unsigned char)*p))
		p++;
	return p;
}

mdn_result_t
mdn__filemapper_createproc(const char *parameter, void **ctxp) {
	return mdn__filemapper_create(parameter, (mdn__filemapper_t *)ctxp);
}

void
mdn__filemapper_destroyproc(void *ctxp) {
	mdn__filemapper_destroy((mdn__filemapper_t)ctxp);
}

mdn_result_t
mdn__filemapper_mapproc(void *ctx, const char *from, char *to, size_t tolen) {
	return mdn__filemapper_map((mdn__filemapper_t)ctx, from, to, tolen);
}


#ifdef TEST
int
main(int ac, char **av) {
	mdn__filemapper_t ctx;
	mdn_result_t r;
	char line[1024], mapped[1024];
	int lineno = 0;

	if (ac == 1) {
		while (fgets(line, sizeof(line), stdin) != NULL) {
			lineno++;
			fputs(line, stdout);
		}
	} else {
		r = mdn__filemapper_create(av[1], &ctx);
		if (r != mdn_success) {
			fprintf(stderr, "mdn__filemapper_create: %s\n",
				mdn_result_tostring(r));
			return 1;
		}
		while (fgets(line, sizeof(line), stdin) != NULL) {
			lineno++;
			r = mdn__filemapper_map(ctx, line, mapped,
						sizeof(mapped));
			if (r != mdn_success) {
				fprintf(stderr, "error at line %d: %s\n",
					lineno, mdn_result_tostring(r));
				return 1;
			}
			fputs(mapped, stdout);
		}
	}
	return 0;
}
#endif /* TEST */
