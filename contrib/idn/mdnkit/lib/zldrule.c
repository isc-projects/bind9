#ifndef lint
static char *rcsid = "$Id: zldrule.c,v 1.10 2000/09/20 02:47:33 ishisone Exp $";
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
#include <stdlib.h>
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/converter.h>
#include <mdn/translator.h>
#include <mdn/zldrule.h>
#include <mdn/debug.h>

typedef struct zld_rule {
	struct zld_rule *next;
	char *zld;
	int zld_depth;
	int nencodings;
	mdn_converter_t ctx[1];		/* actually, a variable sized array */
} zld_rule_t;

struct mdn_zldrule {
	zld_rule_t *rules;
};

static int	delayedopen = MDN_CONVERTER_RTCHECK;	/* XXX */

static void		insert_rule(mdn_zldrule_t ctx, zld_rule_t *rule);
static int		domain_depth(const char *domain);


mdn_result_t
mdn_zldrule_create(mdn_zldrule_t *ctxp) {
	mdn_zldrule_t ctx;

	assert(ctxp != NULL);

	TRACE(("mdn_zldrule_create()\n"));

	*ctxp = NULL;

	if ((ctx = malloc(sizeof(*ctx))) == NULL) {
		WARNING(("mdn_zldrule_create: malloc failed\n"));
		return (mdn_nomemory);
	}

	ctx->rules = NULL;

	*ctxp = ctx;
	return (mdn_success);
}

void
mdn_zldrule_destroy(mdn_zldrule_t ctx) {
	zld_rule_t *rule;

	assert(ctx != NULL);

	TRACE(("mdn_zldrule_destroy()\n"));

	rule = ctx->rules;
	while (rule != NULL) {
		zld_rule_t *next = rule->next;
		int i;

		free(rule->zld);
		for (i = 0; i < rule->nencodings; i++)
			mdn_converter_destroy(rule->ctx[i]);
		free(rule);
		rule = next;
	}

	free(ctx);
}

mdn_result_t
mdn_zldrule_add(mdn_zldrule_t ctx, const char *zld,
		const char **encodings, int nencodings)
{
	mdn_result_t r;
	zld_rule_t *rule;
	size_t sz;
	int i;

	assert(ctx != NULL && zld != NULL && encodings != NULL &&
	       nencodings > 0);

	TRACE(("mdn_zldrule_add(zld=%s)\n", zld));

	sz = sizeof(*rule) + sizeof(mdn_converter_t) * nencodings;
	if ((rule = malloc(sz)) == NULL) {
		WARNING(("mdn_zldrule_add: malloc failed\n"));
		return (mdn_nomemory);
	}
	rule->next = NULL;
	rule->zld = NULL;
	rule->zld_depth = 0;
	rule->nencodings = 0;

	r = mdn_translator_canonicalzld(zld, &rule->zld);
	if (r != mdn_success)
		goto error;

	rule->zld_depth = domain_depth(rule->zld);

	for (i = 0; i < nencodings; i++) {
		r = mdn_converter_create(encodings[i], &rule->ctx[i],
					 delayedopen);
		if (r != mdn_success)
			goto error;
	}

	insert_rule(ctx, rule);

	return (mdn_success);

error:
	free(rule);
	return (r);
}

mdn_result_t
mdn_zldrule_select(mdn_zldrule_t ctx, const char *domain,
		   char **zldp, mdn_converter_t *convctxp)
{
	char dummy[1024];
	zld_rule_t *rule;
	int i;
	mdn_result_t r;

	assert(ctx != NULL && domain != NULL &&
	       zldp != NULL && convctxp != NULL);

	TRACE(("mdn_zldrule_select(domain=\"%s\")\n",
	      mdn_debug_xstring(domain, 30)));

	for (rule = ctx->rules; rule != NULL; rule = rule->next) {
		if (mdn_translator_matchzld(domain, rule->zld))
			goto found;
	}
	return (mdn_notfound);

found:
	*zldp = rule->zld;
	if (rule->nencodings > 1) {
		for (i = 0; i < rule->nencodings; i++) {
			mdn_converter_t convctx = rule->ctx[i];
			r = mdn_converter_convert(convctx, mdn_converter_l2u,
						  domain, dummy,
						  sizeof(dummy));
			if (r != mdn_success)
				continue;
			*convctxp = rule->ctx[i];
			return (mdn_success);
		}
		return (mdn_invalid_encoding);
	} else {
		*convctxp = rule->ctx[0];
	}

	return (mdn_success);
}

static void
insert_rule(mdn_zldrule_t ctx, zld_rule_t *rule) {
	zld_rule_t *prev, *cur;

	for (prev = NULL, cur = ctx->rules;
	     cur != NULL;
	     prev = cur, cur = cur->next) {
		if (cur->zld_depth <= rule->zld_depth) {
			rule->next = cur;
			if (prev == NULL)
				ctx->rules = rule;
			else
				prev->next = rule;
			return;
		}
	}
	rule ->next = NULL;
	if (prev == NULL)
		ctx->rules = rule;
	else
		prev->next = rule;
}

static int
domain_depth(const char *s) {
	int n = 0;

	if (s == NULL)
		return (0);

	while ((s = strchr(s, '.')) != NULL) {
		n++;
		s++;
	}
	return (n);
}
