#ifndef lint
static char *rcsid = "$Id: checker.c,v 1.1.2.1 2002/02/08 12:13:48 marka Exp $";
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
#include <mdn/checker.h>
#include <mdn/strhash.h>
#include <mdn/debug.h>

/*
 * Type for checking scheme.
 */
typedef struct {
	char *prefix;
	char *parameter;
	mdn_checker_createproc_t create;
	mdn_checker_destroyproc_t destroy;
	mdn_checker_lookupproc_t lookup;
	void *context;
} check_scheme_t;

/*
 * Standard checking schemes.
 */
static const check_scheme_t nameprep_03_prohibit_scheme = {
	"prohibit#nameprep-03",
	"nameprep-03",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_prohibitproc,
	NULL,
};

static const check_scheme_t nameprep_03_unasigned_scheme = {
	"unassigned#nameprep-03",
	"nameprep-03",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_unassignedproc,
	NULL,
};

static const check_scheme_t nameprep_05_prohibit_scheme = {
	"prohibit#nameprep-05",
	"nameprep-05",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_prohibitproc,
	NULL,
};

static const check_scheme_t nameprep_05_unasigned_scheme = {
	"unassigned#nameprep-05",
	"nameprep-05",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_unassignedproc,
	NULL,
};

static const check_scheme_t nameprep_06_prohibit_scheme = {
	"prohibit#nameprep-06",
	"nameprep-06",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_prohibitproc,
	NULL,
};

static const check_scheme_t nameprep_06_unasigned_scheme = {
	"unassigned#nameprep-06",
	"nameprep-06",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_unassignedproc,
	NULL,
};

static const check_scheme_t filecheck_prohibit_scheme = {
	"prohibit#fileset",
	NULL,
	mdn__filechecker_createproc,
	mdn__filechecker_destroyproc,
	mdn__filechecker_lookupproc,
	NULL,
};

static const check_scheme_t filecheck_unassigned_scheme = {
	"unassigned#fileset",
	NULL,
	mdn__filechecker_createproc,
	mdn__filechecker_destroyproc,
	mdn__filechecker_lookupproc,
	NULL,
};

static const check_scheme_t *standard_check_schemes[] = {
	&nameprep_03_unasigned_scheme,
	&nameprep_03_prohibit_scheme,
	&nameprep_05_unasigned_scheme,
	&nameprep_05_prohibit_scheme,
	&nameprep_06_unasigned_scheme,
	&nameprep_06_prohibit_scheme,
	&filecheck_prohibit_scheme,
	&filecheck_unassigned_scheme,
	NULL,
};

/*
 * Hash table for checking schemes.
 */
static mdn_strhash_t scheme_hash = NULL;

/*
 * Mapper object type.
 */
struct mdn_checker {
	int nschemes;
	int scheme_size;
	check_scheme_t *schemes;
	int reference_count;
};

#define MAPPER_INITIAL_SCHEME_SIZE	1

mdn_result_t
mdn_checker_initialize(void) {
	mdn_result_t r;
	check_scheme_t **scheme;

	TRACE(("mdn_checker_initialize()\n"));

	if (scheme_hash != NULL)
		return (mdn_success);	/* already initialized */

	r = mdn_strhash_create(&scheme_hash);
	if (r != mdn_success) {
		WARNING(("mdn_checker_initialize: "
			"hash table creation failed\n"));
		goto failure;
	}

	for (scheme = (check_scheme_t **)standard_check_schemes;
		*scheme != NULL; scheme++) {
		r = mdn_strhash_put(scheme_hash, (*scheme)->prefix, *scheme);
		if (r != mdn_success) {
			WARNING(("mdn_checker_initialize: "
				"hash table creation failed\n"));
			goto failure;
		}
	}

	return (mdn_success);

failure:
	if (scheme_hash != NULL) {
		mdn_strhash_destroy(scheme_hash, NULL);
		scheme_hash = NULL;
	}
	return (r);
}

mdn_result_t
mdn_checker_create(mdn_checker_t *ctxp) {
	mdn_checker_t ctx = NULL;
	mdn_result_t r;

	assert(scheme_hash != NULL);
	assert(ctxp != NULL);

	TRACE(("mdn_checker_create()\n"));

	ctx = (mdn_checker_t) malloc(sizeof(struct mdn_checker));
	if (ctx == NULL) {
		WARNING(("mdn_checker_create: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	ctx->schemes = (check_scheme_t *) malloc(sizeof(check_scheme_t)
		 * MAPPER_INITIAL_SCHEME_SIZE);
	if (ctx->schemes == NULL) {
		WARNING(("mdn_checker_create: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	ctx->nschemes = 0;
	ctx->scheme_size = MAPPER_INITIAL_SCHEME_SIZE;
	ctx->reference_count = 1;
	*ctxp = ctx;

	return (mdn_success);

failure:
	if (ctx != NULL)
		free(ctx->schemes);
	free(ctx);
	return (r);
}

void
mdn_checker_destroy(mdn_checker_t ctx) {
	int i;

	assert(scheme_hash != NULL);
	assert(ctx != NULL);

	TRACE(("mdn_checker_destroy()\n"));
	TRACE(("mdn_checker_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_checker_destroy: the object is destroyed\n"));
		for (i = 0; i < ctx->nschemes; i++)
			ctx->schemes[i].destroy(ctx->schemes[i].context);
		free(ctx->schemes);
		free(ctx);
	}
}

void
mdn_checker_incrref(mdn_checker_t ctx) {
	assert(ctx != NULL && scheme_hash != NULL);

	TRACE(("mdn_checker_incrref()\n"));
	TRACE(("mdn_checker_incrref: update reference count (%d->%d)\n",
		ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
}

mdn_result_t
mdn_checker_add(mdn_checker_t ctx, const char *scheme_name) {
	mdn_result_t r;
	check_scheme_t *scheme;
	const char *scheme_prefix;
	const char *scheme_parameter;
	void *scheme_context = NULL;
	char static_buffer[128];	/* large enough */
	char *buffer = static_buffer;

	assert(scheme_hash != NULL);
	assert(ctx != NULL);

	TRACE(("mdn_checker_add(scheme_name=%s)\n",
		mdn_debug_xstring(scheme_name, 20)));

	/*
	 * Split `scheme_name' into `scheme_prefix' and `scheme_parameter'.
	 */
	scheme_parameter = strchr(scheme_name, ':');
	if (scheme_parameter == NULL) {
		scheme_prefix = scheme_name;
		scheme_parameter = NULL;
	} else {
		ptrdiff_t scheme_prefixlen;

		scheme_prefixlen = scheme_parameter - scheme_name;
		if (scheme_prefixlen + 1 > sizeof(static_buffer)) {
			buffer = (char *) malloc(scheme_prefixlen + 1);
			if (buffer == NULL) {
				r = mdn_nomemory;
				goto failure;
			}
		}
		memcpy(buffer, scheme_name, scheme_prefixlen);
		*(buffer + scheme_prefixlen) = '\0';
		scheme_prefix = buffer;
		scheme_parameter++;
	}

	/*
	 * Find a scheme.
	 */
	if (mdn_strhash_get(scheme_hash, scheme_prefix, (void **)&scheme)
		!= mdn_success) {
		WARNING(("mdn_checker_add: invalid scheme %s\n",
			 scheme_name));
		r = mdn_invalid_name;
		goto failure;
	}
	if (scheme_parameter == NULL && scheme->parameter != NULL)
		scheme_parameter = scheme->parameter;

	/*
	 * Add the scheme.
	 */
	assert(ctx->nschemes <= ctx->scheme_size);

	if (ctx->nschemes == ctx->scheme_size) {
		check_scheme_t *new_schemes;

		new_schemes = (check_scheme_t *) realloc(ctx->schemes,
			sizeof(check_scheme_t) * ctx->scheme_size * 2);
		if (new_schemes == NULL) {
			WARNING(("mdn_checker_add: malloc failed\n"));
			r = mdn_nomemory;
			goto failure;
		}
		ctx->schemes = new_schemes;
		ctx->scheme_size *= 2;
	}

	r = scheme->create(scheme_parameter, &scheme_context);
	if (r != mdn_success)
		goto failure;

	memcpy(ctx->schemes + ctx->nschemes, scheme, sizeof(check_scheme_t));
	ctx->schemes[ctx->nschemes].context = scheme_context;
	ctx->nschemes++;

	if (buffer != static_buffer)
		free(buffer);

	return (mdn_success);

failure:
	if (buffer != static_buffer)
		free(buffer);
	free(scheme_context);
	return (r);
}

mdn_result_t
mdn_checker_addall(mdn_checker_t ctx, const char **scheme_names,
		   int nschemes) {
	mdn_result_t r;
	int i;

	assert(scheme_hash != NULL);
	assert(ctx != NULL && scheme_names != NULL);

	TRACE(("mdn_checker_addall(nschemes=%d)\n", nschemes));

	for (i = 0; i < nschemes; i++) {
		r = mdn_checker_add(ctx, (const char *)*scheme_names);
		if (r != mdn_success)
			return (r);
		scheme_names++;
	}

	return (mdn_success);
}

mdn_result_t
mdn_checker_lookup(mdn_checker_t ctx, const char *utf8, const char **found) {
	mdn_result_t r;
	const char *p;
	int i;

	assert(scheme_hash != NULL);
	assert(ctx != NULL && utf8 != NULL && found != NULL);

	TRACE(("mdn_checker_lookup(utf8=\"%s\")\n",
		mdn_debug_xstring(utf8, 20)));

	/*
	 * Lookup.
	 */
	for (i = 0; i < ctx->nschemes; i++) {
		for (p = utf8; *p != '\0'; p = *found + 1) {
			r = (ctx->schemes[i].lookup)(ctx->schemes[i].context,
						     p, found);
			if (r != mdn_success)
				return (r);
			else if (*found == NULL)
				break;
			else if (**found != '.')
				return (mdn_success);
		}
	}

	*found = NULL;

	return (mdn_success);
}

mdn_result_t
mdn_checker_register(const char *prefix,		    
		    mdn_checker_createproc_t create,
		    mdn_checker_destroyproc_t destroy,
		    mdn_checker_lookupproc_t lookup) {
	mdn_result_t r;
	check_scheme_t *scheme = NULL;

	assert(scheme_hash != NULL);
	assert(prefix != NULL && create != NULL && destroy != NULL &&
		lookup != NULL);

	TRACE(("mdn_checker_register(prefix=%s)\n", prefix));

	scheme = (check_scheme_t *) malloc(sizeof(check_scheme_t));
	if (scheme == NULL) {
		WARNING(("mdn_checker_register: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	scheme->prefix = (char *) malloc(strlen(prefix) + 1);
	if (scheme->prefix == NULL) {
		WARNING(("mdn_checker_register: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	strcpy(scheme->prefix, prefix);
	scheme->parameter = NULL;
	scheme->create    = create;
	scheme->destroy   = destroy;
	scheme->lookup    = lookup;

	r = mdn_strhash_put(scheme_hash, prefix, scheme);
	if (r != mdn_success)
		WARNING(("mdn_checker_register: registration failed\n"));

	return (r);

failure:
	if (scheme != NULL)
		free(scheme->prefix);
	free(scheme);
	return (r);
}

#ifdef TEST
#include <stdio.h>

/*
 * Test program for this module.
 *
 * The test program repeatedly prompt you to input a command.  The
 * following command is currently recognized.
 *
 *    add TLD           add selectable check for TLD. (e.g. com, jp)
 *    DOMANNAME         try checking DOMANNAME.
 *
 * Input EOF to exit.
 */
int
main(int ac, char **av) {
	mdn_checker_t ctx;
	char from[1024];
	char *found;
	size_t fromlen;
	mdn_result_t r;

	mdn_log_setlevel(mdn_log_level_trace);
	mdn_checker_initialize();
	r = mdn_checker_create(&ctx);
	if (r != mdn_success) {
		fprintf(stderr, "mdn_checker_create: %s\n",
			mdn_result_tostring(r));
		return 1;
	}
	while (fgets(from, sizeof(from), stdin) != NULL) {
		fromlen = strlen(from);
		if (from[fromlen - 1] == '\n')
			from[fromlen - 1] = '\0';
		if (from[0] == '\0')
			continue;

		if (strncmp(from, "add ", 4) == 0) {
			r = mdn_checker_add(ctx, from + 4);
			if (r != mdn_success) {
				fprintf(stderr, "mdn_checker_add: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}
		} else {
			r = mdn_checker_lookup(ctx, from, &found);
			if (r != mdn_success) {
				fprintf(stderr, "mdn_checker_check: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}
			if (found != NULL)
				fprintf(stderr, "->%s\n", found);
		}
	}

	mdn_checker_destroy(ctx);
	return 0;
}

#endif /* TEST */
