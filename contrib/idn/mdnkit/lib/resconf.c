#ifndef lint
static char *rcsid = "$Id: resconf.c,v 1.4 2000/09/20 02:47:32 ishisone Exp $";
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
 * a Japanese association, Fuundo Bldg., 1-2 Kanda Ogawamachi, Chiyoda-ku,
 * Tokyo, Japan.
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
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/translator.h>
#include <mdn/localencoding.h>
#include <mdn/resconf.h>
#include <mdn/debug.h>

#ifndef MDN_RESCONF_DIR
#define MDN_RESCONF_DIR		"/etc"
#endif
#define MDN_RESCONF_FILE	MDN_RESCONF_DIR "/mdnres.conf"

struct mdn_resconf {
	char *local_encoding;
	mdn_converter_t local_converter;
	mdn_converter_t alternate_converter;
	mdn_converter_t server_converter;
	mdn_normalizer_t normalizer;
	char *zld;
	int edns0;
};

static mdn_result_t	parse_conf(mdn_resconf_t ctx, FILE *fp);
static mdn_result_t	parse_normalize(mdn_resconf_t ctx, int argc,
					char **argv);
static mdn_result_t	parse_alias_file(mdn_resconf_t ctx, int argc,
					 char **argv);
static mdn_result_t	parse_server_encoding(mdn_resconf_t ctx, int argc,
					      char **argv);
static mdn_result_t	parse_server_zld(mdn_resconf_t ctx, int argc,
					 char **argv);
static mdn_result_t	parse_alternate_encoding(mdn_resconf_t ctx, int argc,
						char **argv);
static int		split_args(char *s, char **av, int nav);
static void		resetconf(mdn_resconf_t ctx);
static mdn_result_t	update_local_converter(mdn_resconf_t ctx);
static mdn_result_t	mystrdup(const char *from, char **top);

mdn_result_t
mdn_resconf_initialize(void) {
	mdn_result_t r;

	TRACE(("mdn_resconf_initialize()\n"));

	if ((r = mdn_converter_initialize()) != mdn_success)
		return (r);
	if ((r = mdn_normalizer_initialize()) != mdn_success)
		return (r);
	return (r);
}

mdn_result_t
mdn_resconf_create(mdn_resconf_t *ctxp) {
	mdn_resconf_t ctx = NULL;

	assert(ctxp != NULL);

	TRACE(("mdn_resconf_create()\n"));

	if ((ctx = malloc(sizeof(*ctx))) == NULL)
		return (mdn_nomemory);
	ctx->local_encoding = NULL;
	ctx->local_converter = NULL;
	ctx->server_converter = NULL;
	ctx->alternate_converter = NULL;
	ctx->normalizer = NULL;
	ctx->zld = NULL;
	ctx->edns0 = 0;
	*ctxp = ctx;
	return (mdn_success);
}

char *
mdn_resconf_defaultfile() {
	return MDN_RESCONF_FILE;
}

mdn_result_t
mdn_resconf_loadfile(mdn_resconf_t ctx, const char *file) {
	FILE *fp;
	mdn_result_t r;

	assert(ctx != NULL);

	TRACE(("mdn_resconf_loadfile(file=%s)\n",
	      file == NULL ? "<null>" : file));

	if ((r = mdn_converter_resetalias()) != mdn_success)
		return (r);

	resetconf(ctx);

	if (file == NULL)
		file = mdn_resconf_defaultfile();
	if ((fp = fopen(file, "r")) == NULL) {
		TRACE(("mdn_resconf_loadfile: cannot open %-.40s\n", file));
		return (mdn_nofile);
	}

	r = parse_conf(ctx, fp);
	fclose(fp);

	return (r);
}

void
mdn_resconf_destroy(mdn_resconf_t ctx) {
	TRACE(("mdn_resconf_destroy()\n"));
	resetconf(ctx);
	free(ctx);
}

mdn_converter_t
mdn_resconf_localconverter(mdn_resconf_t ctx) {
	TRACE(("mdn_resconf_localconverter()\n"));
	if (update_local_converter(ctx) != mdn_success)
		return (NULL);
	return (ctx->local_converter);
}

mdn_converter_t
mdn_resconf_serverconverter(mdn_resconf_t ctx) {
	TRACE(("mdn_resconf_serverconverter()\n"));
	return (ctx->server_converter);
}

mdn_converter_t
mdn_resconf_alternateconverter(mdn_resconf_t ctx) {
	TRACE(("mdn_resconf_alternateconverter()\n"));
	return (ctx->alternate_converter);
}

const char *
mdn_resconf_zld(mdn_resconf_t ctx) {
	TRACE(("mdn_resconf_zld()\n"));
	return (ctx->zld);
}

mdn_normalizer_t
mdn_resconf_normalizer(mdn_resconf_t ctx) {
	TRACE(("mdn_resconf_normalizer()\n"));
	return (ctx->normalizer);
}

static mdn_result_t
parse_conf(mdn_resconf_t ctx, FILE *fp) {
	char line[256];
	char *argv[20];
	int argc;
	mdn_result_t r;
	char *sencoding_line = NULL;
	char *fencoding_line = NULL;

	/*
	 * Parse config file.  parsing of 'server-encoding' and
	 * 'alternate-encoding' lines are postponed because
	 * 'alias-file' line must be processed before them.
	 */
	while (fgets(line, sizeof(line), fp) != NULL) {
		char buf[256];

		if (line[0] == '\n')
			continue;

		(void)strcpy(buf, line);
		argc = split_args(buf, argv, 20);
		if (argc == 0 || argv[0][0] == '#')
			continue;
		if (strcmp(argv[0], "normalize") == 0)
			r = parse_normalize(ctx, argc, argv);
		else if (strcmp(argv[0], "alias-file") == 0)
			r = parse_alias_file(ctx, argc, argv);
		else if (strcmp(argv[0], "server-zld") == 0)
			r = parse_server_zld(ctx, argc, argv);
		else if (strcmp(argv[0], "server-encoding") == 0)
			r = mystrdup(line, &sencoding_line);
		else if (strcmp(argv[0], "alternate-encoding") == 0)
			r = mystrdup(line, &fencoding_line);
		else {
			mdn_log_error("mdnres: unrecognized command "
				      "\"%-.30s\"\n", argv[0]);
			r = mdn_invalid_syntax;
		}
		if (r != mdn_success)
			return (r);
	}

	if (sencoding_line != NULL) {
		argc = split_args(sencoding_line, argv, 50);
		r = parse_server_encoding(ctx, argc, argv);
		free(sencoding_line);
		if (r != mdn_success)
			return (r);
	}
	if (fencoding_line != NULL) {
		argc = split_args(fencoding_line, argv, 50);
		r = parse_alternate_encoding(ctx, argc, argv);
		free(fencoding_line);
		if (r != mdn_success)
			return (r);
	}

	return (mdn_success);
}

static mdn_result_t
parse_normalize(mdn_resconf_t ctx, int argc, char **argv) {
	mdn_result_t r;
	int i;

	if (ctx->normalizer == NULL) {
		r = mdn_normalizer_create(&ctx->normalizer);
		if (r != mdn_success)
			return (r);
	}
	for (i = 1; i < argc; i++) {
		r = mdn_normalizer_add(ctx->normalizer, argv[i]);
		if (r != mdn_success) {
			if (r == mdn_invalid_name)
				mdn_log_error("mdnres: unknown "
					      "normalization scheme %-.30s\n",
					      argv[i]);
			return (r);
		}
	}
	return (mdn_success);
}

static mdn_result_t
parse_alias_file(mdn_resconf_t ctx, int argc, char **argv) {
	if (argc != 2) {
		mdn_log_error("mdnres: wrong # of args for %s\n", argv[0]);
		return (mdn_invalid_syntax);
	}
	return (mdn_converter_aliasfile(argv[1]));
}

static mdn_result_t
parse_server_encoding(mdn_resconf_t ctx, int argc, char **argv) {
	if (argc != 2) {
		mdn_log_error("mdnres: wrong # of args for %s\n", argv[0]);
		return (mdn_invalid_syntax);
	}
	return (mdn_converter_create(argv[1], &ctx->server_converter,
				     MDN_CONVERTER_DELAYEDOPEN));
}

static mdn_result_t
parse_server_zld(mdn_resconf_t ctx, int argc, char **argv) {
#ifdef MDN_SUPPORT_ZLD
	mdn_result_t r;

	if (argc != 2) {
		mdn_log_error("mdnres: wrong # of args for %s\n", argv[0]);
		return (mdn_invalid_syntax);
	}
	r = mdn_translator_canonicalzld(argv[1], &ctx->zld);
	if (r != mdn_success)
		return (r);

	return (mdn_success);
#else
	mdn_log_warning("mdnres: ZLD support is disabled -- ignored\n");
	return (mdn_success);
#endif /* MDN_SUPPORT_ZLD */
}

static mdn_result_t
parse_alternate_encoding(mdn_resconf_t ctx, int argc, char **argv) {
	mdn_result_t r;

	if (argc != 2) {
		mdn_log_error("mdnres: wrong # of args for %s\n", argv[0]);
		return (mdn_invalid_syntax);
	}
	r = mdn_converter_create(argv[1], &ctx->alternate_converter,
				 MDN_CONVERTER_DELAYEDOPEN);
	if (r == mdn_success &&
	    !mdn_converter_isasciicompatible(ctx->alternate_converter)) {
		mdn_log_error("mdnres: alternate encoding must be "
			      "ASCII-compatible\n");
		mdn_converter_destroy(ctx->alternate_converter);
		ctx->alternate_converter = NULL;
		return (mdn_invalid_name);
	}
	return (r);
}

static int
split_args(char *s, char **av, int nav) {
	int i;

	for (i = 0; i < nav; i++) {
		while (isspace((unsigned char)*s))
			s++;
		if (*s == '\0')
			break;
		if (*s == '"' || *s == '\'') {
			int qc = *s++;
			av[i] = s;
			while (*s != '\0' && *s != qc)
				s++;
		} else {
			av[i] = s;
			while (*s != '\0' && !isspace((unsigned char)*s))
				s++;
		}
		if (*s == '\0')
			return (i + 1);
		*s++ = '\0';
	}
	return (i);
}

static void
resetconf(mdn_resconf_t ctx) {
	if (ctx->local_encoding != NULL) {
		free(ctx->local_encoding);
		ctx->local_encoding = NULL;
	}
	if (ctx->local_converter != NULL) {
		mdn_converter_destroy(ctx->local_converter);
		ctx->local_converter = NULL;
	}
	if (ctx->server_converter != NULL) {
		mdn_converter_destroy(ctx->server_converter);
		ctx->server_converter = NULL;
	}
	if (ctx->alternate_converter != NULL) {
		mdn_converter_destroy(ctx->alternate_converter);
		ctx->alternate_converter = NULL;
	}
	if (ctx->normalizer != NULL) {
		mdn_normalizer_destroy(ctx->normalizer);
		ctx->normalizer = NULL;
	}
	if (ctx->zld != NULL) {
		free(ctx->zld);
		ctx->zld = NULL;
	}
	ctx->edns0 = 0;
}


static mdn_result_t
update_local_converter(mdn_resconf_t ctx) {
	mdn_result_t r;
	const char *local_encoding = mdn_localencoding_name();

	if (local_encoding == NULL) {
		mdn_log_error("cannot determine local codeset name\n");
		return (mdn_notfound);
	}

	if (ctx->local_encoding != NULL &&
	    strcmp(ctx->local_encoding, local_encoding) == 0 &&
	    ctx->local_converter != NULL) {
		return (mdn_success);
	}

	if (ctx->local_encoding != NULL) {
		free(ctx->local_encoding);
		ctx->local_encoding = NULL;
	}
	if (ctx->local_converter != NULL) {
		mdn_converter_destroy(ctx->local_converter);
		ctx->local_converter = NULL;
	}

	r = mystrdup(local_encoding, &ctx->local_encoding);
	if (r != mdn_success)
		return (r);
	r = mdn_converter_create(ctx->local_encoding,
				 &ctx->local_converter,
				 MDN_CONVERTER_RTCHECK);
	return (r);
}

static mdn_result_t
mystrdup(const char *from, char **top) {
	char *s = malloc(strlen(from) + 1);

	if (*top != NULL) {
		free(*top);
		*top = NULL;
	}

	if (s == NULL)
		return (mdn_nomemory);
	(void)strcpy(s, from);
	*top = s;
	return (mdn_success);
}
