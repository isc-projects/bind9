#ifndef lint
static char *rcsid = "$Id: mapper.c,v 1.1.2.1 2002/02/08 12:14:04 marka Exp $";
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
#include <mdn/mapper.h>
#include <mdn/strhash.h>
#include <mdn/debug.h>

/*
 * Type for mapping scheme.
 */
typedef struct {
	char *prefix;
	char *parameter;
	mdn_mapper_createproc_t create;
	mdn_mapper_destroyproc_t destroy;
	mdn_mapper_mapproc_t map;
	void *context;
} map_scheme_t;

/*
 * Standard mapping schemes.
 */
static const map_scheme_t nameprep_03_scheme = {
	"nameprep-03",
	"nameprep-03",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_mapproc,
	NULL,
};

static const map_scheme_t nameprep_05_scheme = {
	"nameprep-05",
	"nameprep-05",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_mapproc,
	NULL,
};

static const map_scheme_t nameprep_06_scheme = {
	"nameprep-06",
	"nameprep-06",
	mdn__nameprep_createproc,
	mdn__nameprep_destroyproc,
	mdn__nameprep_mapproc,
	NULL,
};

static const map_scheme_t filemap_scheme = {
	"filemap",
	NULL,
	mdn__filemapper_createproc,
	mdn__filemapper_destroyproc,
	mdn__filemapper_mapproc,
	NULL,
};

static const map_scheme_t *standard_map_schemes[] = {
	&nameprep_03_scheme,
	&nameprep_05_scheme,
	&nameprep_06_scheme,
	&filemap_scheme,
	NULL,
};

/*
 * Hash table for mapping schemes.
 */
static mdn_strhash_t scheme_hash = NULL;

/*
 * Mapper object type.
 */
struct mdn_mapper {
	int nschemes;
	int scheme_size;
	map_scheme_t *schemes;
	int reference_count;
};

#define MAPPER_INITIAL_SCHEME_SIZE	1

mdn_result_t
mdn_mapper_initialize(void) {
	mdn_result_t r;
	map_scheme_t **scheme;

	TRACE(("mdn_mapper_initialize()\n"));

	if (scheme_hash != NULL)
		return (mdn_success);	/* already initialized */

	r = mdn_strhash_create(&scheme_hash);
	if (r != mdn_success) {
		WARNING(("mdn_mapper_initialize: "
			"hash table creation failed\n"));
		goto failure;
	}

	for (scheme = (map_scheme_t **)standard_map_schemes;
		*scheme != NULL; scheme++) {
		r = mdn_strhash_put(scheme_hash, (*scheme)->prefix, *scheme);
		if (r != mdn_success) {
			WARNING(("mdn_mapper_initialize: "
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
mdn_mapper_create(mdn_mapper_t *ctxp) {
	mdn_mapper_t ctx = NULL;
	mdn_result_t r;

	assert(scheme_hash != NULL);
	assert(ctxp != NULL);

	TRACE(("mdn_mapper_create()\n"));

	ctx = (mdn_mapper_t) malloc(sizeof(struct mdn_mapper));
	if (ctx == NULL) {
		WARNING(("mdn_mapper_create: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	ctx->schemes = (map_scheme_t *) malloc(sizeof(map_scheme_t)
		 * MAPPER_INITIAL_SCHEME_SIZE);
	if (ctx->schemes == NULL) {
		WARNING(("mdn_mapper_create: malloc failed\n"));
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
mdn_mapper_destroy(mdn_mapper_t ctx) {
	int i;

	assert(scheme_hash != NULL);
	assert(ctx != NULL);

	TRACE(("mdn_mapper_destroy()\n"));
	TRACE(("mdn_mapper_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_mapper_destroy: the object is destroyed\n"));
		for (i = 0; i < ctx->nschemes; i++)
			ctx->schemes[i].destroy(ctx->schemes[i].context);
		free(ctx->schemes);
		free(ctx);
	}
}

void
mdn_mapper_incrref(mdn_mapper_t ctx) {
	assert(ctx != NULL && scheme_hash != NULL);

	TRACE(("mdn_mapper_incrref()\n"));
	TRACE(("mdn_mapper_incrref: update reference count (%d->%d)\n",
		ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
}

mdn_result_t
mdn_mapper_add(mdn_mapper_t ctx, const char *scheme_name) {
	mdn_result_t r;
	map_scheme_t *scheme;
	const char *scheme_prefix;
	const char *scheme_parameter;
	void *scheme_context = NULL;
	char static_buffer[128];	/* large enough */
	char *buffer = static_buffer;

	assert(scheme_hash != NULL);
	assert(ctx != NULL);

	TRACE(("mdn_mapper_add(scheme_name=%s)\n",
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
		WARNING(("mdn_mapper_add: invalid scheme %s\n",
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
		map_scheme_t *new_schemes;

		new_schemes = (map_scheme_t *) realloc(ctx->schemes,
			sizeof(map_scheme_t) * ctx->scheme_size * 2);
		if (new_schemes == NULL) {
			WARNING(("mdn_mapper_add: malloc failed\n"));
			r = mdn_nomemory;
			goto failure;
		}
		ctx->schemes = new_schemes;
		ctx->scheme_size *= 2;
	}

	r = scheme->create(scheme_parameter, &scheme_context);
	if (r != mdn_success)
		goto failure;

	memcpy(ctx->schemes + ctx->nschemes, scheme, sizeof(map_scheme_t));
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
mdn_mapper_addall(mdn_mapper_t ctx, const char **scheme_names, int nschemes) {
	mdn_result_t r;
	int i;

	assert(scheme_hash != NULL);
	assert(ctx != NULL && scheme_names != NULL);

	TRACE(("mdn_mapper_addall(nschemes=%d)\n", nschemes));

	for (i = 0; i < nschemes; i++) {
		r = mdn_mapper_add(ctx, (const char *)*scheme_names);
		if (r != mdn_success)
			return (r);
		scheme_names++;
	}

	return (mdn_success);
}

mdn_result_t
mdn_mapper_map(mdn_mapper_t ctx, const char *from, char *to, size_t tolen) {
	mdn_result_t r;
	size_t fromlen;
	char *src, *dst;
	char static_buffers[2][1024];	/* large enough */
	char *dynamic_buffers[2];
	size_t dynamic_buflen[2];
	size_t dstlen;
	int idx;
	int i;

	assert(scheme_hash != NULL);
	assert(ctx != NULL && from != NULL && to != NULL);

	TRACE(("mdn_mapper_map(from=\"%s\")\n", mdn_debug_xstring(from, 20)));

	/*
	 * Initialize the buffers to use the local
	 * storage (stack memory).
	 */
	dynamic_buffers[0] = NULL;
	dynamic_buffers[1] = NULL;
	dynamic_buflen[0] = 0;
	dynamic_buflen[1] = 0;

	fromlen = strlen(from);

	/*
	 * If no mapping scheme has been registered, copy the string.
	 */
	if (ctx->nschemes == 0) {
		if (fromlen + 1 > tolen)
			return (mdn_buffer_overflow);
		memcpy(to, from, fromlen + 1);
		return (mdn_success);
	}

	/*
	 * Map.
	 */
	src = (void *)from;
	dstlen = fromlen + 1;

	i = 0;
	while (i < ctx->nschemes) {
		/*
		 * Choose destination area to restore the result of a mapping.
		 */
		if (i + 1 == ctx->nschemes) {
			dst = to;
			dstlen = tolen;

		} else if (dstlen <= sizeof(static_buffers[0])) {
			if (src == static_buffers[0])
				idx = 1;
			else
				idx = 0;

			dst = static_buffers[idx];
			dstlen = sizeof(static_buffers[0]);

		} else {
			if (src == dynamic_buffers[0])
				idx = 1;
			else
				idx = 0;

			if (dynamic_buflen[idx] == 0) {
				dynamic_buffers[idx] = (char *) malloc(dstlen);
				if (dynamic_buffers[idx] == NULL) {
					r = mdn_nomemory;
					goto failure;
				}
				dynamic_buflen[idx] = dstlen;

			} else if (dynamic_buflen[idx] < dstlen) {
				char *newbuf;

				newbuf = realloc(dynamic_buffers[idx], dstlen);
				if (newbuf == NULL) {
					r = mdn_nomemory;
					goto failure;
				}
				dynamic_buffers[idx] = newbuf;
				dynamic_buflen[idx] = dstlen;
			}

			dst = dynamic_buffers[idx];
			dstlen = dynamic_buflen[idx];
		}

		/*
		 * Perform i-th map scheme.
		 * If buffer size is not enough, we double it and try again.
		 */
		r = (ctx->schemes[i].map)(ctx->schemes[i].context, src, dst,
					  dstlen);
		if (r == mdn_buffer_overflow && dst != to) {
			dstlen *= 2;
			continue;
		}
		if (r != mdn_success)
			goto failure;

		src = dst;
		i++;
	}

	free(dynamic_buffers[0]);
	free(dynamic_buffers[1]);
	return (mdn_success);

failure:
	free(dynamic_buffers[0]);
	free(dynamic_buffers[1]);
	return (r);
}

mdn_result_t
mdn_mapper_register(const char *prefix,		    
		    mdn_mapper_createproc_t create,
		    mdn_mapper_destroyproc_t destroy,
		    mdn_mapper_mapproc_t map) {
	mdn_result_t r;
	map_scheme_t *scheme = NULL;

	assert(scheme_hash != NULL);
	assert(prefix != NULL && create != NULL && destroy != NULL &&
		map != NULL);

	TRACE(("mdn_mapper_register(prefix=%s)\n", prefix));

	scheme = (map_scheme_t *) malloc(sizeof(map_scheme_t));
	if (scheme == NULL) {
		WARNING(("mdn_mapper_register: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	scheme->prefix = (char *) malloc(strlen(prefix) + 1);
	if (scheme->prefix == NULL) {
		WARNING(("mdn_mapper_register: malloc failed\n"));
		r = mdn_nomemory;
		goto failure;
	}

	strcpy(scheme->prefix, prefix);
	scheme->parameter = NULL;
	scheme->create    = create;
	scheme->destroy   = destroy;
	scheme->map       = map;

	r = mdn_strhash_put(scheme_hash, prefix, scheme);
	if (r != mdn_success)
		WARNING(("mdn_mapper_register: registration failed\n"));

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
 *    tolen N		set the length of output buffer. (1...1024)
 *    add TLD           add selectable map for TLD. (e.g. com, jp)
 *    DOMANNAME         try mapping DOMANNAME.
 *
 * Input EOF to exit.
 */
int
main(int ac, char **av) {
	mdn_mapper_t ctx;
	char from[1024], to[1024];
	size_t fromlen, tolen = sizeof(to);
	mdn_result_t r;

	mdn_log_setlevel(mdn_log_level_trace);
	mdn_mapper_initialize();
	r = mdn_mapper_create(&ctx);
	if (r != mdn_success) {
		fprintf(stderr, "mdn_mapper_create: %s\n",
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
			r = mdn_mapper_add(ctx, from + 4);
			if (r != mdn_success) {
				fprintf(stderr, "mdn_mapper_add: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}
		} else {
			r = mdn_mapper_map(ctx, from, to, tolen);
			if (r != mdn_success) {
				fprintf(stderr, "mdn_mapper_map: %s\n",
					mdn_result_tostring(r));
				conitinue;
			}
			fprintf(stderr, "%s\n", to);
		}
	}

	mdn_mapper_destroy(ctx);
	return 0;
}

#endif /* TEST */
