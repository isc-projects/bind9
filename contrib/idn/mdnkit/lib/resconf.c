#ifndef lint
static char *rcsid = "$Id: resconf.c,v 1.1 2002/01/02 02:46:46 marka Exp $";
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
#include <mdn/checker.h>
#include <mdn/mapper.h>
#include <mdn/mapselector.h>
#include <mdn/delimitermap.h>
#include <mdn/localencoding.h>
#include <mdn/resconf.h>
#include <mdn/debug.h>

#ifndef MDN_RESCONF_DIR
#define MDN_RESCONF_DIR		"/etc"
#endif
#define MDN_RESCONF_FILE	MDN_RESCONF_DIR "/mdn.conf"

#define MAX_CONF_LINE_LENGTH	255
#define MAX_CONF_LINE_ARGS	63

struct mdn_resconf {
	char *local_encoding;
	mdn_converter_t local_converter;
	mdn_converter_t idn_converter;
	mdn_normalizer_t normalizer;
	mdn_checker_t prohibit_checker;
	mdn_checker_t unassigned_checker;
	mdn_mapper_t mapper;
	mdn_mapselector_t local_mapper;
	mdn_delimitermap_t delimiter_mapper;
	int reference_count;
};

static mdn_result_t	parse_conf(mdn_resconf_t ctx, FILE *fp);
static mdn_result_t	parse_delimiter_map(mdn_resconf_t ctx, char *args,
					    int lineno);
static mdn_result_t	parse_encoding_alias_file(mdn_resconf_t ctx,
						  char *args, int lineno);
static mdn_result_t	parse_idn_encoding(mdn_resconf_t ctx, char *args,
					   int lineno);
static mdn_result_t	parse_local_map(mdn_resconf_t ctx, char *args,
					int lineno);
static mdn_result_t	parse_nameprep(mdn_resconf_t ctx, char *args,
				       int lineno, char **nameprep);
static mdn_result_t	parse_map(mdn_resconf_t ctx, char *args, int lineno);
static mdn_result_t	parse_normalize(mdn_resconf_t ctx, char *args,
				        int lineno);
static mdn_result_t	parse_prohibit(mdn_resconf_t ctx, char *args,
				       int lineno);
static mdn_result_t	parse_unassigned(mdn_resconf_t ctx, char *args,
					 int lineno);
static int		split_args(char *s, char **av, int max_ac);
static void		resetconf(mdn_resconf_t ctx);
static mdn_result_t	update_local_converter(mdn_resconf_t ctx);
static mdn_result_t	mystrdup(const char *from, char **top);
static const char *	get_ucs(const char *p, unsigned long *vp);

mdn_result_t
mdn_resconf_initialize(void) {
	mdn_result_t r;

	TRACE(("mdn_resconf_initialize()\n"));

	/*
	 * Initialize sub modules.
	 */
	if ((r = mdn_converter_initialize()) != mdn_success)
		return (r);
	if ((r = mdn_normalizer_initialize()) != mdn_success)
		return (r);
	if ((r = mdn_checker_initialize()) != mdn_success)
		return (r);
	if ((r = mdn_mapselector_initialize()) != mdn_success)
		return (r);
	if ((r = mdn_mapper_initialize()) != mdn_success)
		return (r);

	return (mdn_success);
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
	ctx->idn_converter = NULL;
	ctx->normalizer = NULL;
	ctx->prohibit_checker = NULL;
	ctx->unassigned_checker = NULL;
	ctx->mapper = NULL;
	ctx->local_mapper = NULL;
	ctx->delimiter_mapper = NULL;
	ctx->reference_count = 1;

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
	assert(ctx != NULL);

	TRACE(("mdn_resconf_destroy()\n"));
	TRACE(("mdn_resconf_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_converter_destroy: the object is destroyed\n"));
		resetconf(ctx);
		free(ctx);
	}
}

void
mdn_resconf_incrref(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_incrref()\n"));
	TRACE(("mdn_resconf_incrref: update reference count (%d->%d)\n",
		ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
}

mdn_converter_t
mdn_resconf_getalternateconverter(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getalternateconverter()\n"));

	return (mdn_resconf_getidnconverter(ctx));
}

mdn_delimitermap_t
mdn_resconf_getdelimitermap(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getdelimitermap()\n"));

	if (ctx->delimiter_mapper != NULL)
		mdn_delimitermap_incrref(ctx->delimiter_mapper);
	return (ctx->delimiter_mapper);
}

mdn_converter_t
mdn_resconf_getidnconverter(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getidnconverter()\n"));

	if (ctx->idn_converter != NULL)
		mdn_converter_incrref(ctx->idn_converter);
	return (ctx->idn_converter);
}

mdn_converter_t
mdn_resconf_getlocalconverter(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getlocalconverter()\n"));

	if (update_local_converter(ctx) != mdn_success)
		return (NULL);
	mdn_converter_incrref(ctx->local_converter);
	return (ctx->local_converter);
}

mdn_mapselector_t
mdn_resconf_getlocalmapselector(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getlocalmapselector()\n"));

	if (ctx->local_mapper != NULL)
		mdn_mapselector_incrref(ctx->local_mapper);
	return (ctx->local_mapper);
}

mdn_mapper_t
mdn_resconf_getmapper(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getmapper()\n"));

	if (ctx->mapper != NULL)
		mdn_mapper_incrref(ctx->mapper);
	return (ctx->mapper);
}

mdn_normalizer_t
mdn_resconf_getnormalizer(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getnormalizer()\n"));

	if (ctx->normalizer != NULL)
		mdn_normalizer_incrref(ctx->normalizer);
	return (ctx->normalizer);
}

mdn_checker_t
mdn_resconf_getprohibitchecker(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getprohibitchecker()\n"));

	if (ctx->prohibit_checker != NULL)
		mdn_checker_incrref(ctx->prohibit_checker);
	return (ctx->prohibit_checker);
}

mdn_checker_t
mdn_resconf_getunassignedchecker(mdn_resconf_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_getunassignedchecker()\n"));

	if (ctx->unassigned_checker != NULL)
		mdn_checker_incrref(ctx->unassigned_checker);
	return (ctx->unassigned_checker);
}

void
mdn_resconf_setalternateconverter(mdn_resconf_t ctx,
				  mdn_converter_t alternate_converter) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setalternateconverter()\n"));
}

void
mdn_resconf_setdelimitermap(mdn_resconf_t ctx,
			    mdn_delimitermap_t delimiter_mapper) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setdelimitermap()\n"));

	if (ctx->delimiter_mapper != NULL)
		mdn_delimitermap_destroy(ctx->delimiter_mapper);
	ctx->delimiter_mapper = delimiter_mapper;
	if (delimiter_mapper != NULL)
		mdn_delimitermap_incrref(ctx->delimiter_mapper);
}

void
mdn_resconf_setidnconverter(mdn_resconf_t ctx, 
			    mdn_converter_t idn_converter) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setidnconverter()\n"));

	if (ctx->idn_converter != NULL)
		mdn_converter_destroy(ctx->idn_converter);
	ctx->idn_converter = idn_converter;
	if (idn_converter != NULL)
		mdn_converter_incrref(ctx->idn_converter);
}

void
mdn_resconf_setlocalconverter(mdn_resconf_t ctx,
				  mdn_converter_t local_converter) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setlocalconverter()\n"));

	if (ctx->local_converter != NULL)
		mdn_converter_destroy(ctx->local_converter);
	free(ctx->local_encoding);
	ctx->local_encoding = NULL;	/* See update_local_converter(). */
	ctx->local_converter = local_converter;
	if (local_converter != NULL)
		mdn_converter_incrref(local_converter);
}

void
mdn_resconf_setlocalmapselector(mdn_resconf_t ctx,
				mdn_mapselector_t local_mapper) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setlocalmapselector()\n"));

	if (ctx->local_mapper != NULL)
		mdn_mapselector_destroy(ctx->local_mapper);
	ctx->local_mapper = local_mapper;
	if (local_mapper != NULL)
		mdn_mapselector_incrref(ctx->local_mapper);
}

void
mdn_resconf_setmapper(mdn_resconf_t ctx, mdn_mapper_t mapper) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setmapper()\n"));

	if (ctx->mapper != NULL)
		mdn_mapper_destroy(ctx->mapper);
	ctx->mapper = mapper;
	if (mapper != NULL)
		mdn_mapper_incrref(ctx->mapper);
}

void
mdn_resconf_setnormalizer(mdn_resconf_t ctx, mdn_normalizer_t normalizer) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setnormalizer()\n"));

	if (ctx->normalizer != NULL)
		mdn_normalizer_destroy(ctx->normalizer);
	ctx->normalizer = normalizer;
	if (normalizer != NULL)
		mdn_normalizer_incrref(ctx->normalizer);
}

void
mdn_resconf_setprohibitchecker(mdn_resconf_t ctx,
			       mdn_checker_t prohibit_checker) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setprohibitchecker()\n"));

	if (ctx->prohibit_checker != NULL)
		mdn_checker_destroy(ctx->prohibit_checker);
	ctx->prohibit_checker = prohibit_checker;
	if (prohibit_checker != NULL)
		mdn_checker_incrref(ctx->prohibit_checker);
}

void
mdn_resconf_setunassignedchecker(mdn_resconf_t ctx,
				 mdn_checker_t unassigned_checker) {
	assert(ctx != NULL);

	TRACE(("mdn_resconf_setunassignedchecker()\n"));

	if (ctx->unassigned_checker != NULL)
		mdn_checker_destroy(ctx->unassigned_checker);
	ctx->unassigned_checker = unassigned_checker;
	if (unassigned_checker != NULL)
		mdn_checker_incrref(ctx->unassigned_checker);
}

mdn_result_t
mdn_resconf_setnameprepversion(mdn_resconf_t ctx, const char *version)
{
	char prohibit_scheme_name[MAX_CONF_LINE_LENGTH + 1];
	char unassigned_scheme_name[MAX_CONF_LINE_LENGTH + 1];
	mdn_mapper_t mapper = NULL;
	mdn_normalizer_t normalizer = NULL;
	mdn_checker_t prohibit_checker = NULL;
	mdn_checker_t unassigned_checker = NULL;
	mdn_result_t r;

	assert(ctx != NULL && version != NULL);

	TRACE(("mdn_resconf_setnameprepversion()\n"));

	/*
	 * Set canonical scheme names.
	 */
	if (strlen(version) + strlen(MDN_CHECKER_PROHIBIT_PREFIX)
	    > MAX_CONF_LINE_LENGTH) {
		r = mdn_invalid_name;
		goto failure;
	}
	sprintf(prohibit_scheme_name, "%s%s",
	        MDN_CHECKER_PROHIBIT_PREFIX, version);

	if (strlen(version) + strlen(MDN_CHECKER_UNASSIGNED_PREFIX)
	    > MAX_CONF_LINE_LENGTH) {
		r = mdn_invalid_name;
		goto failure;
	}
	sprintf(unassigned_scheme_name, "%s%s",
	        MDN_CHECKER_UNASSIGNED_PREFIX, version);

	/*
	 * Create objects.
	 */
	r = mdn_mapper_create(&mapper);
	if (r != mdn_success)
		goto failure;
	r = mdn_normalizer_create(&normalizer);
	if (r != mdn_success)
		goto failure;
	r = mdn_checker_create(&prohibit_checker);
	if (r != mdn_success)
		goto failure;
	r = mdn_checker_create(&unassigned_checker);
	if (r != mdn_success)
		goto failure;

	r = mdn_mapper_add(mapper, version);
	if (r != mdn_success)
		goto failure;
	r = mdn_normalizer_add(normalizer, version);
	if (r != mdn_success)
		goto failure;
	r = mdn_checker_add(prohibit_checker, prohibit_scheme_name);
	if (r != mdn_success)
		goto failure;
	r = mdn_checker_add(unassigned_checker, unassigned_scheme_name);
	if (r != mdn_success)
		goto failure;

	/*
	 * Set the objects.
	 */
	mdn_resconf_setmapper(ctx, mapper);
	mdn_resconf_setnormalizer(ctx, normalizer);
	mdn_resconf_setprohibitchecker(ctx, prohibit_checker);
	mdn_resconf_setunassignedchecker(ctx, unassigned_checker);

	/*
	 * Destroy the objects.
	 */
	mdn_mapper_destroy(mapper);
	mdn_normalizer_destroy(normalizer);
	mdn_checker_destroy(prohibit_checker);
	mdn_checker_destroy(unassigned_checker);

	return (mdn_success);

failure:
	if (mapper != NULL)
		mdn_mapper_destroy(mapper);
	if (normalizer != NULL)
		mdn_normalizer_destroy(normalizer);
	if (prohibit_checker != NULL)
		mdn_checker_destroy(prohibit_checker);
	if (unassigned_checker != NULL)
		mdn_checker_destroy(unassigned_checker);

	return (r);
}

mdn_result_t
mdn_resconf_setalternateconvertername(mdn_resconf_t ctx, const char *name,
				      int flags) {
	assert(ctx != NULL && name != NULL);

	TRACE(("mdn_resconf_setalternateconvertername(name=%s, flags=%d)\n",
	      name, flags));

	return (mdn_success);
}

mdn_result_t
mdn_resconf_setidnconvertername(mdn_resconf_t ctx, const char *name,
				int flags) {
	mdn_converter_t idn_converter;
	mdn_result_t r;

	assert(ctx != NULL && name != NULL);

	TRACE(("mdn_resconf_setidnconvertername(name=%s, flags=%d)\n",
	      name, flags));

	r = mdn_converter_create(name, &idn_converter, flags);
	if (r != mdn_success)
		return (r);

	if (ctx->idn_converter != NULL)
		mdn_converter_destroy(ctx->idn_converter);
	ctx->idn_converter = idn_converter;

	return (mdn_success);
}

mdn_result_t
mdn_resconf_setlocalconvertername(mdn_resconf_t ctx, const char *name,
				  int flags) {
	mdn_converter_t local_converter;
	char *local_encoding = NULL;
	mdn_result_t r;

	assert(ctx != NULL);

	TRACE(("mdn_resconf_setlocalconvertername(mame=%s, flags=%d)\n",
	      name == NULL ? "<null>" : name, flags));

	if (name == NULL) {
		local_converter = NULL;
	} else {
		r = mdn_converter_create(name, &local_converter, flags);
		if (r != mdn_success) {
			free(local_encoding);
			return (r);
		}
	}
	if (ctx->local_converter != NULL)
		mdn_converter_destroy(ctx->local_converter);
	free(ctx->local_encoding);
	ctx->local_converter = local_converter;
	ctx->local_encoding = NULL;	/* See update_local_converter(). */

	return (mdn_success);
}

mdn_result_t
mdn_resconf_addalldelimitermapucs(mdn_resconf_t ctx, unsigned long *v,
				  int nv) {
	mdn_result_t r;

	TRACE(("mdn_resconf_addalldelimitermapucs(nv=%d)\n", nv));

	if (ctx->delimiter_mapper == NULL) {
		r = mdn_delimitermap_create(&(ctx->delimiter_mapper));
		if (r != mdn_success)
			return (r);
	}

	r = mdn_delimitermap_addall(ctx->delimiter_mapper, v, nv);
	return (r);
}

mdn_result_t
mdn_resconf_addalllocalmapselectornames(mdn_resconf_t ctx, const char *tld,
					const char **names, int nnames) {
	mdn_result_t r;

	assert(ctx != NULL && names != NULL);

	TRACE(("mdn_resconf_addalllocalmapselectorname(tld=%s, nnames=%d)\n",
	      tld, nnames));

	if (ctx->local_mapper == NULL) {
		r = mdn_mapselector_create(&(ctx->local_mapper));
		if (r != mdn_success)
			return (r);
	}

	r = mdn_mapselector_addall(ctx->local_mapper, tld, names, nnames);
	return (r);
}

mdn_result_t
mdn_resconf_addallmappernames(mdn_resconf_t ctx, const char **names,
			      int nnames) {
	mdn_result_t r;

	assert(ctx != NULL && names != NULL);

	TRACE(("mdn_resconf_addallmappername()\n"));

	if (ctx->mapper == NULL) {
		r = mdn_mapper_create(&(ctx->mapper));
		if (r != mdn_success)
			return (r);
	}

	r = mdn_mapper_addall(ctx->mapper, names, nnames);
	return (r);
}

mdn_result_t
mdn_resconf_addallnormalizernames(mdn_resconf_t ctx, const char **names,
				  int nnames) {
	mdn_result_t r;

	assert(ctx != NULL && names != NULL);

	TRACE(("mdn_resconf_addallnormalizername(nnames=%d)\n", nnames));

	if (ctx->normalizer == NULL) {
		r = mdn_normalizer_create(&(ctx->normalizer));
		if (r != mdn_success)
			return (r);
	}

	r = mdn_normalizer_addall(ctx->normalizer, names, nnames);
	return (r);
}

mdn_result_t
mdn_resconf_addallprohibitcheckernames(mdn_resconf_t ctx, const char **names,
				       int nnames) {
	char long_name[MAX_CONF_LINE_LENGTH + 1];
	mdn_result_t r;
	int i;

	assert(ctx != NULL && names != NULL);

	TRACE(("mdn_resconf_addallprohibitcheckername(nnames=%d)\n", nnames));

	if (ctx->prohibit_checker == NULL) {
		r = mdn_checker_create(&(ctx->prohibit_checker));
		if (r != mdn_success)
			return (r);
	}

	for (i = 0; i < nnames; i++, names++) {
		if (strlen(*names) + strlen(MDN_CHECKER_PROHIBIT_PREFIX)
			> MAX_CONF_LINE_LENGTH) {
			return (mdn_invalid_name);
		}
		strcpy(long_name, MDN_CHECKER_PROHIBIT_PREFIX);
		strcat(long_name, *names);

		r = mdn_checker_add(ctx->prohibit_checker, long_name);
		if (r != mdn_success)
			return (r);
	}

	return (mdn_success);
}

mdn_result_t
mdn_resconf_addallunassignedcheckernames(mdn_resconf_t ctx, const char **names,
					 int nnames) {
	char long_name[MAX_CONF_LINE_LENGTH + 1];
	mdn_result_t r;
	int i;

	assert(ctx != NULL && names != NULL);

	TRACE(("mdn_resconf_addallunassignedcheckername(nnames=%d)\n",
	      nnames));

	if (ctx->unassigned_checker == NULL) {
		r = mdn_checker_create(&(ctx->unassigned_checker));
		if (r != mdn_success)
			return (r);
	}

	for (i = 0; i < nnames; i++, names++) {
		if (strlen(*names) + strlen(MDN_CHECKER_UNASSIGNED_PREFIX)
			> MAX_CONF_LINE_LENGTH) {
			return (mdn_invalid_name);
		}
		strcpy(long_name, MDN_CHECKER_UNASSIGNED_PREFIX);
		strcat(long_name, *names);

		r = mdn_checker_add(ctx->unassigned_checker, long_name);
		if (r != mdn_success)
			return (r);
	}

	return (mdn_success);
}

static mdn_result_t
parse_conf(mdn_resconf_t ctx, FILE *fp) {
	char line[MAX_CONF_LINE_LENGTH + 1];
	int lineno = 0;
	char *argv[3];
	int argc;
	mdn_result_t r;
	char *idn_encoding_args = NULL;
	int idn_encoding_lineno = 0;
	char *nameprep = NULL;

	/*
	 * Parse config file.  parsing of 'idn-encoding' line is
	 * postponed because 'alias-file' line must be processed
	 * before them.
	 */
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *newline;

		lineno++;
		newline = strpbrk(line, "\r\n");
		if (newline != NULL)
			*newline = '\0';
		else if (fgetc(fp) != EOF) {
			mdn_log_error("mdnres: too long line \"%-.30s\", "
				      "line %d", line, lineno);
			return (mdn_invalid_syntax);
		}

		argc = split_args(line, argv, 2);
		if (argc == -1) {
			mdn_log_error("mdnres: syntax error, line %d\n",
				lineno);
			return (mdn_invalid_syntax);
		} else if (argc == 0 || argv[0][0] == '#') {
			continue;
		}

		if (strcmp(argv[0], "alternate-encoding") == 0) {
			continue;
		} else if (strcmp(argv[0], "delimiter-map") == 0) {
			r = parse_delimiter_map(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "encoding-alias-file") == 0) {
			r = parse_encoding_alias_file(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "idn-encoding") == 0) {
			r = mystrdup(argv[1], &idn_encoding_args);
			if (r != mdn_success) {
				mdn_log_error("mdnres: %s, line %d\n",
					      mdn_result_tostring(r), lineno);
			}
			idn_encoding_lineno = lineno;

		} else if (strcmp(argv[0], "local-map") == 0) {
			r = parse_local_map(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "nameprep") == 0) {
			r = parse_nameprep(ctx, argv[1], lineno, &nameprep);

		} else if (strcmp(argv[0], "nameprep-map") == 0) {
			r = parse_map(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "nameprep-normalize") == 0) {
			r = parse_normalize(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "nameprep-prohibit") == 0) {
			r = parse_prohibit(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "nameprep-unassigned") == 0) {
			r = parse_unassigned(ctx, argv[1], lineno);

		} else if (strcmp(argv[0], "server-zld") == 0 || 
			strcmp(argv[0], "alias-file") == 0 ||
			strcmp(argv[0], "normalize") == 0 ||
			strcmp(argv[0], "server-encoding") == 0) {
			mdn_log_warning("mdnres: obsolete command "
					"\"%-.30s\", line %d (ignored)\n",
					argv[0], lineno);
			r = mdn_success;
		} else {
			mdn_log_error("mdnres: unrecognized command "
				      "\"%-.30s\", line %d\n",
				      argv[0], lineno);
			r = mdn_invalid_syntax;
		}
		if (r != mdn_success)
			return (r);
	}

	lineno++;

	if (nameprep != NULL) {
		if (ctx->mapper == NULL) {
			r = parse_map(ctx, nameprep, lineno);
			if (r != mdn_success)
				return (r);
		}
		if (ctx->normalizer == NULL) {
			r = parse_normalize(ctx, nameprep, lineno);
			if (r != mdn_success)
				return (r);
		}
		if (ctx->prohibit_checker == NULL) {
			r = parse_prohibit(ctx, nameprep, lineno);
			if (r != mdn_success)
				return (r);
		}
		if (ctx->unassigned_checker == NULL) {
			r = parse_unassigned(ctx, nameprep, lineno);
			if (r != mdn_success)
				return (r);
		}
	}

	if (idn_encoding_args != NULL) {
		r = parse_idn_encoding(ctx, idn_encoding_args,
				       idn_encoding_lineno);
		if (r != mdn_success)
			return (r);
	}

	return (mdn_success);
}

static mdn_result_t
parse_delimiter_map(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;
	unsigned long ucs;
	int i;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc > MAX_CONF_LINE_ARGS) {
		mdn_log_error("mdnres: wrong # of args for delimiter-map, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	if (ctx->delimiter_mapper == NULL) {
		r = mdn_delimitermap_create(&ctx->delimiter_mapper);
		if (r != mdn_success) {
			mdn_log_error("mdnres: cannot create delimiter "
				      "mapper, %s, line %d\n", 
				      mdn_result_tostring(r), lineno);
			return (r);
		}
	}

	for (i = 0; i < argc; i++) {
		if (get_ucs(argv[i], &ucs) == NULL) {
			mdn_log_error("mdnres: invalid delimiter "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (mdn_invalid_syntax);
		}
		r = mdn_delimitermap_add(ctx->delimiter_mapper, ucs);
		if (r == mdn_invalid_codepoint) {
			mdn_log_error("mdnres: invalid delimiter "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (r);
		} else if (r != mdn_success) {
			return (r);
		}
	}

	return (mdn_success);
}

static mdn_result_t
parse_encoding_alias_file(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc != 1) {
		mdn_log_error("mdnres: wrong # of args for "
			      "encoding-alias-file, line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	r = mdn_converter_aliasfile(argv[0]);
	if (r != mdn_success) {
		mdn_log_error("mdnres: cannot set aliasfile, %s, line %d\n",
			      mdn_result_tostring(r), lineno);
	}

	return (r);
}

static mdn_result_t
parse_idn_encoding(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc != 1) {
		mdn_log_error("mdnres: wrong # of args for idn-encoding, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	r = mdn_converter_create(argv[0], &ctx->idn_converter,
				 MDN_CONVERTER_DELAYEDOPEN);
	if (r != mdn_success) {
		mdn_log_error("mdnres: cannot create idn converter, %s, "
			      "line %d\n", mdn_result_tostring(r), lineno);
	}

	return (r);
}

static mdn_result_t
parse_local_map(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;
	int i;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc < 2 || argc > MAX_CONF_LINE_ARGS) {
		mdn_log_error("mdnres: wrong # of args for local-map, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	if (ctx->local_mapper == NULL) {
		r = mdn_mapselector_create(&ctx->local_mapper);
		if (r != mdn_success) {
			mdn_log_error("mdnres: cannot create local mapper, "
				      "%s, line %d\n",
				      mdn_result_tostring(r), lineno);
			return (r);
		}
	}

	for (i = 1; i < argc; i++) {
		r = mdn_mapselector_add(ctx->local_mapper, argv[0], argv[i]);
		if (r == mdn_invalid_name) {
			mdn_log_error("mdnres: map scheme unavailable "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (r);
		} else if (r != mdn_success) {
			return (r);
		}
	}

	return (mdn_success);
}

static mdn_result_t
parse_nameprep(mdn_resconf_t ctx, char *args, int lineno, char **nameprep) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc != 1) {
		mdn_log_error("mdnres: wrong # of args for nameprep, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	r = mystrdup(argv[0], nameprep);
	if (r != mdn_success) {
		mdn_log_error("mdnres: cannot set nameprep, %s, line %d\n",
			      mdn_result_tostring(r), lineno);
	}
	
	return (r);
}

static mdn_result_t
parse_map(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;
	int i;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc > MAX_CONF_LINE_ARGS) {
		mdn_log_error("mdnres: wrong # of args for map, line %d\n",
			      lineno);
		return (mdn_invalid_syntax);
	}

	if (ctx->mapper == NULL) {
		r = mdn_mapper_create(&ctx->mapper);
		if (r != mdn_success) {
			mdn_log_error("mdnres: cannot create mapper, %s, "
				      "line %d\n", mdn_result_tostring(r),
				      lineno);
			return (r);
		}
	}

	for (i = 0; i < argc; i++) {
		r = mdn_mapper_add(ctx->mapper, argv[i]);
		if (r == mdn_invalid_name) {
			mdn_log_error("mdnres: map scheme unavailable "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (r);
		} else if (r != mdn_success) {
			return (r);
		}
	}

	return (mdn_success);
}

static mdn_result_t
parse_normalize(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;
	int i;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc > MAX_CONF_LINE_ARGS) {
		mdn_log_error("mdnres: wrong # of args for normalize, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	if (ctx->normalizer == NULL) {
		r = mdn_normalizer_create(&ctx->normalizer);
		if (r != mdn_success) {
			mdn_log_error("mdnres: cannot create normalizer, %s, "
				      "line %d\n", mdn_result_tostring(r),
				      lineno);
			return (r);
		}
	}

	for (i = 0; i < argc; i++) {
		r = mdn_normalizer_add(ctx->normalizer, argv[i]);
		if (r == mdn_invalid_name) {
			mdn_log_error("mdnres: unknown normalization scheme "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (r);
		} else if (r != mdn_success) {
			return (r);
		}
	}

	return (mdn_success);
}

static mdn_result_t
parse_prohibit(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;
	char scheme_name[MAX_CONF_LINE_LENGTH + 1];
	int i;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc > MAX_CONF_LINE_ARGS) {
		mdn_log_error("mdnres: wrong # of args for prohibit, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	if (ctx->prohibit_checker == NULL) {
		r = mdn_checker_create(&ctx->prohibit_checker);
		if (r != mdn_success) {
			mdn_log_error("mdnres: cannot create prohibit "
				      "checker, %s, line %d\n",
				      mdn_result_tostring(r), lineno);
			return (r);
		}
	}

	for (i = 0; i < argc; i++) {
		sprintf(scheme_name, "%s%s", MDN_CHECKER_PROHIBIT_PREFIX,
			argv[i]);
		r = mdn_checker_add(ctx->prohibit_checker, scheme_name);
		if (r == mdn_invalid_name) {
			mdn_log_error("mdnres: prohibit scheme unavailable "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (r);
		} else if (r != mdn_success) {
			return (r);
		}
	}

	return (mdn_success);
}

static mdn_result_t
parse_unassigned(mdn_resconf_t ctx, char *args, int lineno) {
	mdn_result_t r;
	char *argv[MAX_CONF_LINE_ARGS + 1];
	int argc;
	char scheme_name[MAX_CONF_LINE_LENGTH + 1];
	int i;

	argc = split_args(args, argv, MAX_CONF_LINE_ARGS + 1);

	if (argc > MAX_CONF_LINE_ARGS) {
		mdn_log_error("mdnres: wrong # of args for unassigned, "
			      "line %d\n", lineno);
		return (mdn_invalid_syntax);
	}

	if (ctx->unassigned_checker == NULL) {
		r = mdn_checker_create(&ctx->unassigned_checker);
		if (r != mdn_success) {
			mdn_log_error("mdnres: cannot create unassigned "
				      "checker, %s, line %d\n",
				      mdn_result_tostring(r), lineno);
			return (r);
		}
	}

	for (i = 0; i < argc; i++) {
		sprintf(scheme_name, "%s%s", MDN_CHECKER_UNASSIGNED_PREFIX,
			argv[i]);
		r = mdn_checker_add(ctx->unassigned_checker, scheme_name);
		if (r == mdn_invalid_name) {
			mdn_log_error("mdnres: unassigned scheme unavailable "
				      "\"%-.30s\", line %d\n",
				      argv[i], lineno);
			return (r);
		} else if (r != mdn_success) {
			return (r);
		}
	}

	return (mdn_success);
}

static int
split_args(char *s, char **av, int max_ac) {
	int ac;
	int i;

	for (ac = 0; *s != '\0' && ac < max_ac; ac++) {
		if (ac > 0)
			*s++ = '\0';
		while (isspace((unsigned char)*s))
			s++;
		if (*s == '\0')
			break;
		if (*s == '"' || *s == '\'') {
			int qc = *s++;
			av[ac] = s;
			while (*s != qc) {
				if (*s == '\0')
					return (-1);
				s++;
			}
		} else {
			av[ac] = s;
			while (*s != '\0' && !isspace((unsigned char)*s))
				s++;
		}
	}

	for (i = ac; i < max_ac; i++)
		av[i] = NULL;

	return (ac);
}

static void
resetconf(mdn_resconf_t ctx) {
	free(ctx->local_encoding);
	ctx->local_encoding = NULL;

	mdn_resconf_setlocalconverter(ctx, NULL);
	mdn_resconf_setidnconverter(ctx, NULL);
	mdn_resconf_setdelimitermap(ctx, NULL);
	mdn_resconf_setlocalmapselector(ctx, NULL);
	mdn_resconf_setmapper(ctx, NULL);
	mdn_resconf_setnormalizer(ctx, NULL);
	mdn_resconf_setprohibitchecker(ctx, NULL);
	mdn_resconf_setunassignedchecker(ctx, NULL);
}

static mdn_result_t
update_local_converter(mdn_resconf_t ctx) {
	mdn_result_t r;
	const char *new_local_encoding;

	/*
	 * This condition comes true only when the converter is set by
	 * mdn_resconf_setlocalconverter().  In this case, we don't
	 * update the local converter.
	 */
	if (ctx->local_encoding == NULL && ctx->local_converter != NULL)
		return (mdn_success);

	/*
	 * Update the local converer if the local encoding is changed.
	 */
	new_local_encoding = mdn_localencoding_name();
	if (new_local_encoding == NULL) {
		mdn_log_error("cannot determine local codeset name\n");
		return (mdn_notfound);
	}

	if (ctx->local_encoding != NULL &&
	    ctx->local_converter != NULL &&
	    strcmp(ctx->local_encoding, new_local_encoding) == 0) {
		return (mdn_success);
	}

	free(ctx->local_encoding);
	ctx->local_encoding = NULL;
	if (ctx->local_converter != NULL) {
		mdn_converter_destroy(ctx->local_converter);
		ctx->local_converter = NULL;
	}

	r = mystrdup(new_local_encoding, &ctx->local_encoding);
	if (r != mdn_success)
		return (r);
	r = mdn_converter_create(ctx->local_encoding,
				 &ctx->local_converter,
				 MDN_CONVERTER_RTCHECK);
	return (r);
}

static mdn_result_t
mystrdup(const char *from, char **top) {
	char *s;

	if (*top != NULL) {
		free(*top);
		*top = NULL;
	}

	if (from == NULL)
		from = "";
	s = malloc(strlen(from) + 1);
	if (s == NULL)
		return (mdn_nomemory);
	(void)strcpy(s, from);
	*top = s;
	return (mdn_success);
}

static const char *
get_ucs(const char *p, unsigned long *vp) {
	char *end;

	/* Skip leading space */
	while (isspace((unsigned char)*p))
		p++;

	/* Skip optional 'U+' */
	if (strncmp(p, "U+", 2) == 0)
		p += 2;

	*vp = strtoul(p, &end, 16);
	if (end == p) {
		return (NULL);
	}
	p = end;

	/* Skip trailing space */
	while (isspace((unsigned char)*p))
		p++;
	return p;
}

#ifdef TEST

int
main(int argc, char *argv[])
{
	mdn_resconf_t resconf;
	mdn_result_t r;
	char *conf_file;

	if (argc == 1)
		conf_file = mdn_resconf_defaultfile();
	else
		conf_file = argv[1];

	r = mdn_resconf_initialize();
	if (r != mdn_success) {
		fprintf(stderr, "%s: %s\n", argv[0], mdn_result_tostring(r));
		exit(1);
	}

	r = mdn_resconf_create(&resconf);
	if (r != mdn_success) {
		fprintf(stderr, "%s: %s\n", argv[0], mdn_result_tostring(r));
		exit(1);
	}

	r = mdn_resconf_loadfile(resconf, conf_file);
	if (r != mdn_success) {
		fprintf(stderr, "%s: %s, %s\n", argv[0],
			mdn_result_tostring(r), conf_file);
		exit(1);
	}

	mdn_resconf_destroy(resconf);

	return 0;
}

#endif /* TEST */
