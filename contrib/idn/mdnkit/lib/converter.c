#ifndef lint
static char *rcsid = "$Id: converter.c,v 1.1 2002/01/02 02:46:40 marka Exp $";
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <iconv.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/strhash.h>
#include <mdn/debug.h>
#include <mdn/utf8.h>
#include <mdn/amcacez.h>
#include <mdn/race.h>
#include <mdn/dude.h>
#ifdef MDN_EXTRA_ACE
#include <mdn/utf5.h>
#include <mdn/utf6.h>
#include <mdn/brace.h>
#include <mdn/lace.h>
#include <mdn/altdude.h>
#include <mdn/amcacem.h>
#include <mdn/amcaceo.h>
#include <mdn/amcacer.h>
#include <mdn/amcacev.h>
#include <mdn/amcacew.h>
#include <mdn/mace.h>
#endif /* MDN_EXTRA_ACE */

#ifndef MDN_UTF8_ENCODING_NAME
#define MDN_UTF8_ENCODING_NAME "UTF-8"		/* by IANA */
#endif
#ifndef MDN_UTF6_ENCODING_NAME
#define MDN_UTF6_ENCODING_NAME "UTF-6"
#endif
#ifndef MDN_UTF5_ENCODING_NAME
#define MDN_UTF5_ENCODING_NAME "UTF-5"
#endif
#ifndef MDN_RACE_ENCODING_NAME
#define MDN_RACE_ENCODING_NAME "RACE"
#endif
#ifndef MDN_BRACE_ENCODING_NAME
#define MDN_BRACE_ENCODING_NAME "BRACE"
#endif
#ifndef MDN_LACE_ENCODING_NAME
#define MDN_LACE_ENCODING_NAME "LACE"
#endif
#ifndef MDN_DUDE_ENCODING_NAME
#define MDN_DUDE_ENCODING_NAME "DUDE"
#endif
#ifndef MDN_ALTDUDE_ENCODING_NAME
#define MDN_ALTDUDE_ENCODING_NAME "AltDUDE"
#endif
#ifndef MDN_AMCACEM_ENCODING_NAME
#define MDN_AMCACEM_ENCODING_NAME "AMC-ACE-M"
#endif
#ifndef MDN_AMCACEO_ENCODING_NAME
#define MDN_AMCACEO_ENCODING_NAME "AMC-ACE-O"
#endif
#ifndef MDN_AMCACER_ENCODING_NAME
#define MDN_AMCACER_ENCODING_NAME "AMC-ACE-R"
#endif
#ifndef MDN_AMCACEV_ENCODING_NAME
#define MDN_AMCACEV_ENCODING_NAME "AMC-ACE-V"
#endif
#ifndef MDN_AMCACEW_ENCODING_NAME
#define MDN_AMCACEW_ENCODING_NAME "AMC-ACE-W"
#endif
#ifndef MDN_AMCACEZ_ENCODING_NAME
#define MDN_AMCACEZ_ENCODING_NAME "AMC-ACE-Z"
#endif
#ifndef MDN_MACE_ENCODING_NAME
#define MDN_MACE_ENCODING_NAME "MACE"
#endif

#define MAX_RECURSE	20

typedef struct {
	mdn_converter_openproc_t open;
	mdn_converter_closeproc_t close;
	mdn_converter_convertproc_t convert;
	int encoding_type;
} converter_ops_t;

struct mdn_converter {
	char *local_encoding_name;
	converter_ops_t *ops;
	int flags;
	int opened[2];
	int reference_count;
	void *private_data;
};

static mdn_strhash_t encoding_name_hash;
static mdn_strhash_t encoding_alias_hash;

static mdn_result_t	converter_open(mdn_converter_t ctx,
				       mdn_converter_dir_t dir);
static mdn_result_t	converter_close(mdn_converter_t ctx,
					mdn_converter_dir_t dir);
static mdn_result_t	register_standard_encoding(void);
static const char	*get_realname(const char *name);
static void		free_alias_value(void *value);
static mdn_result_t	roundtrip_check(mdn_converter_t ctx,
					mdn_converter_dir_t dir,
					const char *from, const char *to);

static mdn_result_t	converter_none_open(mdn_converter_t ctx,
					    mdn_converter_dir_t dir,
					    void **privdata);
static mdn_result_t	converter_none_close(mdn_converter_t ctx,
					     void *privdata,
					     mdn_converter_dir_t dir);
static mdn_result_t	converter_none_convert(mdn_converter_t ctx,
					       void *privdata,
					       mdn_converter_dir_t dir,
					       const char *from,
					       char *to, size_t tolen);
static mdn_result_t	converter_iconv_open(mdn_converter_t ctx,
					     mdn_converter_dir_t dir,
					     void **privdata);
static mdn_result_t	converter_iconv_close(mdn_converter_t ctx,
					      void *privdata,
					      mdn_converter_dir_t dir);
static mdn_result_t	converter_iconv_convert(mdn_converter_t ctx,
					        void *privdata,
						mdn_converter_dir_t dir,
						const char *from,
						char *to, size_t tolen);
#ifdef MDN_EXTRA_ACE
static mdn_result_t	converter_utf5_open(mdn_converter_t ctx,
					    mdn_converter_dir_t dir,
					    void **privdata);
static mdn_result_t	converter_utf5_close(mdn_converter_t ctx,
					     void *privdata,
					     mdn_converter_dir_t dir);
static mdn_result_t	converter_utf5_convert(mdn_converter_t ctx,
					       void *privdata,
					       mdn_converter_dir_t dir,
					       const char *from,
					       char *to, size_t tolen);
#endif

#ifdef DEBUG
static mdn_result_t	converter_uescape_open(mdn_converter_t ctx,
					       mdn_converter_dir_t dir,
					       void **privdata);
static mdn_result_t	converter_uescape_close(mdn_converter_t ctx,
					        void *privdata,
					        mdn_converter_dir_t dir);
static mdn_result_t	converter_uescape_convert(mdn_converter_t ctx,
						  void *privdata,
						  mdn_converter_dir_t dir,
						  const char *from,
						  char *to, size_t tolen);
#endif

static converter_ops_t none_converter_ops = {
	converter_none_open,
	converter_none_close,
	converter_none_convert,
	MDN_NONACE,
};

static converter_ops_t iconv_converter_ops = {
	converter_iconv_open,
	converter_iconv_close,
	converter_iconv_convert,
	MDN_NONACE,
};

/*
 * Initialize.
 */

mdn_result_t
mdn_converter_initialize(void) {
	mdn_result_t r = mdn_success;
	mdn_strhash_t hash;

	if (encoding_alias_hash == NULL) {
		if ((r = mdn_strhash_create(&hash)) != mdn_success)
			return (r);
		encoding_alias_hash = hash;
	}
	if (encoding_name_hash == NULL) {
		if ((r = mdn_strhash_create(&hash)) != mdn_success)
			return (r);
		encoding_name_hash = hash;
		r = register_standard_encoding();
	}
	return (r);
}

mdn_result_t
mdn_converter_create(const char *name, mdn_converter_t *ctxp, int flags) {
	const char *realname;
	mdn_converter_t ctx;
	mdn_result_t r;
	void *v;

	assert(name != NULL && ctxp != NULL);

	TRACE(("mdn_converter_create(%s)\n", name));

	realname = get_realname(name);
#ifdef DEBUG
	if (strcmp(name, realname) != 0) {
		TRACE(("mdn_converter_create: realname=%s\n", realname));
	}
#endif

	*ctxp = NULL;

	/* Allocate memory for a converter context and the name. */
	ctx = malloc(sizeof(struct mdn_converter) + strlen(realname) + 1);
	if (ctx == NULL) {
		WARNING(("mdn_converter_create: malloc failed\n"));
		return (mdn_nomemory);
	}
	(void)memset(ctx, 0, sizeof(*ctx));
	ctx->local_encoding_name = (char *)(ctx + 1);
	(void)strcpy(ctx->local_encoding_name, realname);
	ctx->flags = flags;
	ctx->reference_count = 1;
	ctx->private_data = NULL;

	assert(encoding_name_hash != NULL);

	if (strcmp(realname, MDN_UTF8_ENCODING_NAME) == 0) {
		/* No conversion needed */
		ctx->ops = &none_converter_ops;
	} else if ((r = mdn_strhash_get(encoding_name_hash, realname, &v))
		   == mdn_success) {
		/* Special converter found */
		ctx->ops = (converter_ops_t *)v;
	} else {
		/* General case */
		ctx->ops = &iconv_converter_ops;
	}

	if ((flags & MDN_CONVERTER_DELAYEDOPEN) == 0) {
		mdn_result_t r;

		if ((r = converter_open(ctx,
					mdn_converter_l2u)) != mdn_success) {
			WARNING(("mdn_converter_create: open failed "
			     "(local->utf8)\n"));
			return (r);
		}
		if ((r = converter_open(ctx,
					mdn_converter_u2l)) != mdn_success) {
			WARNING(("mdn_converter_create: open failed "
			     "(utf8->local)\n"));
			return (r);
		}
	}

	*ctxp = ctx;
	return (mdn_success);
}

static mdn_result_t
converter_open(mdn_converter_t ctx, mdn_converter_dir_t dir) {
	mdn_result_t st = mdn_success;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	if (!ctx->opened[dir]) {
		st = (*ctx->ops->open)(ctx, dir, &(ctx->private_data));
		if (st == mdn_success)
			ctx->opened[dir] = 1;
	}
	return (st);
}

void
mdn_converter_destroy(mdn_converter_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_converter_destroy()\n"));
	TRACE(("mdn_converter_destroy: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count - 1));

	ctx->reference_count--;
	if (ctx->reference_count <= 0) {
		TRACE(("mdn_converter_destroy: the object is destroyed\n"));
		(void)converter_close(ctx, mdn_converter_l2u);
		(void)converter_close(ctx, mdn_converter_u2l);
		free(ctx);
	}
}

void
mdn_converter_incrref(mdn_converter_t ctx) {
	assert(ctx != NULL);

	TRACE(("mdn_converter_incrref()\n"));
	TRACE(("mdn_converter_incrref: update reference count (%d->%d)\n",
	    ctx->reference_count, ctx->reference_count + 1));

	ctx->reference_count++;
}

static mdn_result_t
converter_close(mdn_converter_t ctx, mdn_converter_dir_t dir) {
	mdn_result_t st = mdn_success;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	if (ctx->opened[dir]) {
		st = (*ctx->ops->close)(ctx, ctx->private_data, dir);
		if (st == mdn_success)
			ctx->opened[dir] = 0;
	}
	return (st);
}

char *
mdn_converter_localencoding(mdn_converter_t ctx) {
	assert(ctx != NULL);
	TRACE(("mdn_converter_localencoding()\n"));
	return (ctx->local_encoding_name);
}
	
int
mdn_converter_encodingtype(mdn_converter_t ctx) {
	assert(ctx != NULL);
	TRACE(("mdn_converter_encodingtype()\n"));
	return (ctx->ops->encoding_type);
}

int
mdn_converter_isasciicompatible(mdn_converter_t ctx) {
	assert(ctx != NULL);
	TRACE(("mdn_converter_isasciicompatible()\n"));
	return (ctx->ops->encoding_type != MDN_NONACE);
}

mdn_result_t
mdn_converter_convert(mdn_converter_t ctx, mdn_converter_dir_t dir,
		      const char *from, char *to, size_t tolen)
{
	mdn_result_t r;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	TRACE(("mdn_converter_convert(dir=%s,from=\"%s\")\n",
	       dir == mdn_converter_l2u ? "l2u" : "u2l",
	       from == NULL ? "(null)" : mdn_debug_xstring(from, 20)));

	if (!ctx->opened[dir]) {
		mdn_result_t st = converter_open(ctx, dir);
		if (st != mdn_success)
			return (st);
	}

	if (from == NULL) {
		/* for compatibility */
		INFO(("mdn_converter_convert: "
		      "obsolete feature (reset) invoked\n"));
		return (mdn_success);
	}

	r = (*ctx->ops->convert)(ctx, ctx->private_data, dir, from, to, tolen);
	if (r == mdn_success && dir == mdn_converter_u2l &&
	    (ctx->flags & MDN_CONVERTER_RTCHECK) != 0) {
		return (roundtrip_check(ctx, dir, from, to));
	}

	return (r);
}

/*
 * Encoding registration.
 */

mdn_result_t
mdn_converter_register(const char *name,
		       mdn_converter_openproc_t open,
		       mdn_converter_closeproc_t close,
		       mdn_converter_convertproc_t convert,
		       int encoding_type) {
	converter_ops_t *ops;
	mdn_result_t r;

	assert(name != NULL && open != NULL && close != NULL &&
	       convert != NULL);

	TRACE(("mdn_converter_register(name=%s)\n", name));

	if ((ops = malloc(sizeof(*ops))) == NULL) {
		WARNING(("mdn_converter_register: malloc failed\n"));
		return (mdn_nomemory);
	}
	ops->open = open;
	ops->close = close;
	ops->convert = convert;
	ops->encoding_type = encoding_type;

	r = mdn_strhash_put(encoding_name_hash, name, ops);
	if (r != mdn_success)
		free(ops);

	return (r);
}

static mdn_result_t
register_standard_encoding(void) {
	mdn_result_t r;

	r = mdn_converter_register(MDN_AMCACEZ_ENCODING_NAME,
				   mdn__amcacez_open,
				   mdn__amcacez_close,
				   mdn__amcacez_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_RACE_ENCODING_NAME,
				   mdn__race_open,
				   mdn__race_close,
				   mdn__race_convert,
				   MDN_ACE_LOOSECASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_DUDE_ENCODING_NAME,
				   mdn__dude_open,
				   mdn__dude_close,
				   mdn__dude_convert,
				   MDN_ACE_LOOSECASE);
	if (r != mdn_success)
		return (r);

#ifdef MDN_EXTRA_ACE
	r = mdn_converter_register(MDN_UTF5_ENCODING_NAME,
				   converter_utf5_open,
				   converter_utf5_close,
				   converter_utf5_convert,
				   MDN_ACE_LOOSECASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_BRACE_ENCODING_NAME,
				   mdn__brace_open,
				   mdn__brace_close,
				   mdn__brace_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_LACE_ENCODING_NAME,
				   mdn__lace_open,
				   mdn__lace_close,
				   mdn__lace_convert,
				   MDN_ACE_LOOSECASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_UTF6_ENCODING_NAME,
				   mdn__utf6_open,
				   mdn__utf6_close,
				   mdn__utf6_convert,
				   MDN_ACE_LOOSECASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_ALTDUDE_ENCODING_NAME,
				   mdn__altdude_open,
				   mdn__altdude_close,
				   mdn__altdude_convert,
				   MDN_ACE_LOOSECASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_AMCACEM_ENCODING_NAME,
				   mdn__amcacem_open,
				   mdn__amcacem_close,
				   mdn__amcacem_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_AMCACEO_ENCODING_NAME,
				   mdn__amcaceo_open,
				   mdn__amcaceo_close,
				   mdn__amcaceo_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_AMCACER_ENCODING_NAME,
				   mdn__amcacer_open,
				   mdn__amcacer_close,
				   mdn__amcacer_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_AMCACEV_ENCODING_NAME,
				   mdn__amcacev_open,
				   mdn__amcacev_close,
				   mdn__amcacev_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_AMCACEW_ENCODING_NAME,
				   mdn__amcacew_open,
				   mdn__amcacew_close,
				   mdn__amcacew_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);

	r = mdn_converter_register(MDN_MACE_ENCODING_NAME,
				   mdn__mace_open,
				   mdn__mace_close,
				   mdn__mace_convert,
				   MDN_ACE_STRICTCASE);
	if (r != mdn_success)
		return (r);
#endif /* MDN_EXTRA_ACE */

#ifdef DEBUG
	/* This is convenient for debug.  Not useful for other purposes. */
	r = mdn_converter_register("U-escape",
				   converter_uescape_open,
				   converter_uescape_close,
				   converter_uescape_convert,
				   MDN_NONACE);
	if (r != mdn_success)
		return (r);
#endif /* DEBUG */

	return (r);
}

/*
 * Encoding alias support.
 */

mdn_result_t
mdn_converter_addalias(const char *alias_name, const char *real_name) {
	char *rn_copy;

	assert(alias_name != NULL && real_name != NULL);

	TRACE(("mdn_converter_addalias(alias_name=%s,real_name=%s)\n",
	       alias_name, real_name));

	if (strcmp(alias_name, real_name) == 0)
		return (mdn_success);

	if (encoding_alias_hash == NULL) {
		WARNING(("mdn_converter_addalias: the module is not \n"
			 "initialized"));
		return (mdn_failure);
	}

	if ((rn_copy = malloc(strlen(real_name) + 1)) == NULL) {
		WARNING(("mdn_converter_addalias: malloc failed\n"));
		return (mdn_nomemory);
	}
	(void)strcpy(rn_copy, real_name);
	(void)mdn_strhash_put(encoding_alias_hash, alias_name, rn_copy);

	return (mdn_success);
}

mdn_result_t
mdn_converter_aliasfile(const char *path) {
	FILE *fp;
	int line_no;
	mdn_result_t st = mdn_success;
	char line[200], alias[200], real[200];

	assert(path != NULL);

	TRACE(("mdn_converter_aliasfile(path=%s)\n", path));

	if ((fp = fopen(path, "r")) == NULL) {
		return (mdn_nofile);
	}
	for (line_no = 1; fgets(line, sizeof(line), fp) != NULL; line_no++) {
		unsigned char *p = (unsigned char *)line;

		while (isascii(*p) && isspace(*p))
			p++;
		if (*p == '#' || *p == '\n')
			continue;
		if (sscanf((char *)p, "%s %s", alias, real) == 2) {
			st = mdn_converter_addalias(alias, real);
			if (st != mdn_success)
				break;
		} else {
			WARNING(("mdn_converter_aliasfile: file %s has "
				 "invalid contents at line %d\n",
				 path, line_no));
			st = mdn_invalid_syntax;
			break;
		}
	}
	fclose(fp);
	return st;
}

mdn_result_t
mdn_converter_resetalias(void) {
	mdn_strhash_t hash;
	mdn_result_t r;

	TRACE(("mdn_converter_resetalias()\n"));

	hash = encoding_alias_hash;
	encoding_alias_hash = NULL;
	mdn_strhash_destroy(hash, free_alias_value);
	hash = NULL;
	r = mdn_strhash_create(&hash);
	encoding_alias_hash = hash;
	return (r);
}

static const char *
get_realname(const char *name) {
	if (encoding_alias_hash != NULL) {
		char *realname;
		int recurse = 0;

		while (recurse < MAX_RECURSE) {
			mdn_result_t r;

			r = mdn_strhash_get(encoding_alias_hash,
					    name, (void **)&realname);
			if (r != mdn_success)
				break;

			name = realname;
			recurse++;
		}
		if (recurse >= MAX_RECURSE) {
			WARNING(("mdn_converter: encoding alias table has "
				 "cyclic reference\n"));
		}
	}
	return (name);
}
				       
static void
free_alias_value(void *value) {
	free(value);
}

/*
 * Round trip check.
 */

static mdn_result_t
roundtrip_check(mdn_converter_t ctx, mdn_converter_dir_t dir,
		const char *from, const char *to)
{
	/*
	 * One problem with iconv() convertion is that
	 * iconv() doesn't signal an error if the input
	 * string contains characters which are valid but
	 * do not have mapping to the output codeset.
	 * (the behavior of iconv() for that case is defined as
	 * `implementation dependent')
	 * One way to check this case is to perform round-trip
	 * conversion and see if it is same as the original string.
	 */
	mdn_result_t r;
	char *back_converted;
	char buf[256];
	size_t len;

	TRACE(("mdn_converter_convert: round-trip checking ("
	       " from=\"%s\")\n", mdn_debug_xstring(from, 20)));

	/* Allocate enough buffer. */
	len = strlen(from) + 1;
	if (len <= sizeof(buf)) {
		back_converted = buf;
		len = sizeof(buf);
	} else {
		back_converted = malloc(len);
		if (back_converted == NULL)
			return (mdn_nomemory);
	}

	/*
	 * Perform backward conversion.
	 */
	if (dir == mdn_converter_l2u)
		dir = mdn_converter_u2l;
	else
		dir = mdn_converter_l2u;
	r = mdn_converter_convert(ctx, dir, to, back_converted, len);

	switch (r) {
	case mdn_success:
		if (strcmp(back_converted, from) != 0)
			r = mdn_nomapping;
		break;
	case mdn_invalid_encoding:
	case mdn_buffer_overflow:
		r = mdn_nomapping;
		break;
	default:
		break;
	}

	if (back_converted != buf)
		free(back_converted);

	if (r != mdn_success) {
		TRACE(("round-trip check failed: %s\n",
		       mdn_result_tostring(r)));
	}

	return (r);
}

/*
 * Identity conversion (or, no conversion at all).
 */

/* ARGSUSED */
static mdn_result_t
converter_none_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		    void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
static mdn_result_t
converter_none_close(mdn_converter_t ctx, void *privdata,
		     mdn_converter_dir_t dir) {
	return (mdn_success);
}

static mdn_result_t
converter_none_convert(mdn_converter_t ctx, void *privdata,
		       mdn_converter_dir_t dir, const char *from, char *to,
		       size_t tolen) {
	size_t fromlen;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	/*
	 * Just copying is not enough.  We should at least check
	 * the validity of 'from'.
	 */
	if (!mdn_utf8_isvalidstring(from))
		return (mdn_invalid_encoding);

	fromlen = strlen(from) + 1;		/* including NUL */
	if (fromlen > tolen)
		return (mdn_buffer_overflow);

	(void)memcpy(to, from, fromlen);	/* including NUL */
	return (mdn_success);
}


/*
 * Conversion using iconv() interface.
 */

static mdn_result_t
converter_iconv_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		     void **privdata) {
	iconv_t ictx;

	if (*privdata == NULL) {
		ictx = (iconv_t)(-1);
		*privdata = malloc(sizeof(iconv_t) * 2);
		if (*privdata == NULL)
			return (mdn_nomemory);
		*((iconv_t *)*privdata) = (iconv_t)(-1);
		*((iconv_t *)*privdata + 1) = (iconv_t)(-1);
	}

	if (dir == mdn_converter_l2u) {
		ictx = iconv_open(MDN_UTF8_ENCODING_NAME,
				  ctx->local_encoding_name);
	} else {
		ictx = iconv_open(ctx->local_encoding_name,
				  MDN_UTF8_ENCODING_NAME);
	}
	if (ictx == (iconv_t)(-1)) {
		free(*privdata);
		switch (errno) {
		case ENOMEM:
			return (mdn_nomemory);
		case EINVAL:
			return (mdn_invalid_name);
		default:
			WARNING(("iconv_open failed with errno %d\n", errno));
			return (mdn_failure);
		}
	}

	memcpy((iconv_t *)*privdata + dir, &ictx, sizeof(iconv_t));

	return (mdn_success);
}

static mdn_result_t
converter_iconv_close(mdn_converter_t ctx, void *privdata,
		      mdn_converter_dir_t dir) {
	iconv_t *ictxp;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	ictxp = (iconv_t *)privdata;
	if (ictxp[dir] != (iconv_t)(-1))
		(void)iconv_close(ictxp[dir]);
	ictxp[dir] = (iconv_t)(-1);
	if (ictxp[mdn_converter_l2u] == (iconv_t)(-1) &&
	    ictxp[mdn_converter_u2l] == (iconv_t)(-1)) {
		free(privdata);
	}

	return (mdn_success);
}

static mdn_result_t
converter_iconv_convert(mdn_converter_t ctx, void *privdata,
			mdn_converter_dir_t dir, const char *from, char *to,
			size_t tolen) {
	iconv_t ictx;
	char *toorg = to;
	size_t sz;
	size_t fromsz;
	size_t tosz;
	char *p;

	assert(ctx != NULL &&
	       (dir == mdn_converter_l2u || dir == mdn_converter_u2l));

	if (tolen <= 0)
		return (mdn_buffer_overflow);	/* need space for NUL */

	/*
	 * For utf-8 -> local conversion, check the validity of
	 * the input string.
	 */
	if (dir == mdn_converter_u2l && !mdn_utf8_isvalidstring(from)) {
		WARNING(("mdn_converter_convert: "
			 "input is not a valid UTF-8 string\n"));
		return (mdn_invalid_encoding);
	}

	/*
	 * Reset internal state.
	 */
	ictx = ((iconv_t *)privdata)[dir];
#if 0
	(void)iconv(ictx, (const char **)NULL, (size_t *)NULL, 
		    (char **)NULL, (size_t *)NULL);
#else
	/*
	 * Above code should work according to the spec, but causes
	 * segmentation fault with Solaris 2.6.
	 * So.. a work-around.
	 */
	fromsz = tosz = 0;
	p = NULL;
	(void)iconv(ictx, (const char **)NULL, &fromsz, &p, &tosz);
#endif

	fromsz = strlen(from);
	tosz = tolen - 1;	/* reserve space for terminating NUL */
	sz = iconv(ictx, &from, &fromsz, &to, &tosz);

	if (sz == (size_t)(-1) || fromsz > 0) {
		switch (errno) {
		case EILSEQ:
		case EINVAL:
			if (dir == mdn_converter_u2l) {
				/*
				 * We already checked the validity of the
				 * input string.  So we assume a mapping
				 * error.
				 */
				return (mdn_nomapping);
			} else {
				/*
				 * We assume all the characters in the local
				 * codeset are included in UCS.  This means
				 * mapping error is not possible, so the
				 * input string must have some problem.
				 */
				return (mdn_invalid_encoding);
			}
		case E2BIG:
			return (mdn_buffer_overflow);
		default:
			WARNING(("iconv failed with errno %d\n", errno));
			return (mdn_failure);
		}
	}

	if (dir == mdn_converter_l2u) {
		/*
		 * For local -> utf-8 conversion, check the validity of the
		 * output string.
		 */
		*to = '\0';
		if (!mdn_utf8_isvalidstring(toorg)) {
			WARNING(("mdn_converter_convert: "
				 "output is not a valid UTF-8 string\n"));
			return (mdn_invalid_encoding);
		}
	} else {
		/*
		 * For utf-8 -> local conversion, append a sequence of
		 * state reset.
		 */
		fromsz = 0;
		sz = iconv(ictx, (const char **)NULL, &fromsz, &to, &tosz);
		if (sz == (size_t)(-1)) {
			switch (errno) {
			case EILSEQ:
			case EINVAL:
				return (mdn_invalid_encoding);
			case E2BIG:
				return (mdn_buffer_overflow);
			default:
				WARNING(("iconv failed with errno %d\n",
					 errno));
				return (mdn_failure);
			}
		}
		*to = '\0';
	}

	return (mdn_success);
}

/*
 * Conversion to/from UTF-5.
 */

#ifdef MDN_EXTRA_ACE

/* ARGSUSED */
static mdn_result_t
converter_utf5_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		    void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
static mdn_result_t
converter_utf5_close(mdn_converter_t ctx, void *privdata, 
		     mdn_converter_dir_t dir) {
	return (mdn_success);
}

static mdn_result_t
converter_utf5_convert(mdn_converter_t ctx, void *privdata, 
		       mdn_converter_dir_t dir, const char *from, char *to,
		       size_t tolen) {
	size_t fromlen = strlen(from);

	if (dir == mdn_converter_l2u) {
		unsigned long v;
		int flen, tlen;

		while (fromlen > 0) {
			flen = mdn_utf5_getwc(from, fromlen, &v);
			if (flen == 0) {
				WARNING(("mdn_converter_convert: "
					 "invalid character\n"));
				return (mdn_invalid_encoding);
			}
			from += flen;
			fromlen -= flen;

			tlen = mdn_utf8_putwc(to, tolen, v);
			if (tlen == 0)
				goto overflow;
			to += tlen;
			tolen -= tlen;
		}
	} else {	/* mdn_converter_u2l */
		unsigned long v;
		int flen, tlen;

		while (fromlen > 0) {
			flen = mdn_utf8_getwc(from, fromlen, &v);
			if (flen == 0) {
				WARNING(("mdn_converter_convert: "
					 "invalid character\n"));
				return (mdn_invalid_encoding);
			}
			from += flen;
			fromlen -= flen;

			tlen = mdn_utf5_putwc(to, tolen, v);
			if (tlen == 0)
				goto overflow;
			to += tlen;
			tolen -= tlen;
		}
	}
	if (tolen <= 0)
		goto overflow;

	*to = '\0';
	return (mdn_success);

overflow:
	WARNING(("mdn_converter_convert: buffer overflow\n"));
	return (mdn_buffer_overflow);
}

#endif

#ifdef DEBUG
/*
 * Conversion to/from unicode escape string.
 * Arbitrary UCS-4 character can be specified by a special sequence
 *	\u{XXXXXX}
 * where XXXXX denotes any hexadecimal string up to FFFFFFFF.
 * This is designed for debugging.
 */

static int	uescape_getwc(const char *from, size_t fromlen,
			    unsigned long *vp);
static int	uescape_putwc(char *to, size_t tolen, unsigned long v);

/* ARGSUSED */
static mdn_result_t
converter_uescape_open(mdn_converter_t ctx, mdn_converter_dir_t dir,
		       void **privdata) {
	return (mdn_success);
}

/* ARGSUSED */
static mdn_result_t
converter_uescape_close(mdn_converter_t ctx, void *privdata,
			mdn_converter_dir_t dir) {
	return (mdn_success);
}

static mdn_result_t
converter_uescape_convert(mdn_converter_t ctx, void *privdata,
			  mdn_converter_dir_t dir, const char *from, char *to,
			  size_t tolen)
{
	size_t fromlen = strlen(from);

	if (dir == mdn_converter_l2u) {
		unsigned long v;
		int flen, tlen;

		while (fromlen > 0) {
			flen = uescape_getwc(from, fromlen, &v);
			if (flen == 0) {
				WARNING(("mdn_converter_convert: "
					 "invalid character\n"));
				return (mdn_invalid_encoding);
			}
			from += flen;
			fromlen -= flen;

			tlen = mdn_utf8_putwc(to, tolen, v);
			if (tlen == 0)
				goto overflow;
			to += tlen;
			tolen -= tlen;
		}
	} else {	/* mdn_converter_u2l */
		unsigned long v;
		int flen, tlen;

		while (fromlen > 0) {
			flen = mdn_utf8_getwc(from, fromlen, &v);
			if (flen == 0) {
				WARNING(("mdn_converter_convert: "
					 "invalid character\n"));
				return (mdn_invalid_encoding);
			}
			from += flen;
			fromlen -= flen;

			tlen = uescape_putwc(to, tolen, v);
			if (tlen == 0)
				goto overflow;
			to += tlen;
			tolen -= tlen;
		}
	}
	if (tolen <= 0)
		goto overflow;

	*to = '\0';
	return (mdn_success);

overflow:
	WARNING(("mdn_converter_convert: buffer overflow\n"));
	return (mdn_buffer_overflow);
}

static int
uescape_getwc(const char *from, size_t fromlen, unsigned long *vp) {
	char *end;
	if (fromlen >= 4 && strncmp(from, "\\u{", 3) == 0 &&
	    (end = memchr(from, '}', fromlen)) != NULL &&
	    end - from <= 3 + 8) {	/* '\u{' + 'xxxxxxxx' */
		int len = end - from - 3;
		char tmp[9];

		(void)memcpy(tmp, from + 3, len);
		tmp[len] = '\0';
		*vp = strtoul(tmp, NULL, 16);
		return (end + 1 - from);
	} else if (fromlen > 0) {
		*vp = (unsigned char)from[0];
		return (1);
	} else {
		return (0);
	}
}

static int
uescape_putwc(char *to, size_t tolen, unsigned long v) {
	if (v <= 0x7f) {
		if (tolen < 1)
			return (0);
		*to = v;
		return (1);
	} else if (v <= 0xffffffff) {
		char tmp[20];
		int len;

		(void)sprintf(tmp, "\\u{%lx}", v);
		len = strlen(tmp);
		if (tolen < len)
			return (0);
		(void)memcpy(to, tmp, len);
		return (len);
	} else {
		return (0);
	}
}
#endif
