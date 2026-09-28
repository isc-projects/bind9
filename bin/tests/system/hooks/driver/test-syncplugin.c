/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/tokens.h>

#include <ns/hooks.h>

typedef struct {
	isc_mem_t *mctx;
	uint8_t rcode;

	/*
	 * Plugin will bails out without altering the response if qname first
	 * label matches `firstlbl`.
	 */
	char *firstlbl;
} syncplugin_t;

static ns_hookresult_t
syncplugin__hook(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *)arg;
	syncplugin_t *inst = cbdata;

	UNUSED(resp);

	if (inst->firstlbl != NULL) {
		const dns_name_t *qname = dns_name(qctx->client->query.qname);
		dns_label_t label;
		size_t len = strlen(inst->firstlbl);

		dns_name_getlabel(qname, 0, &label);

		/*
		 * +1 because the first label byte is the length of the label
		 * itself
		 */
		if (*label.base == len &&
		    strncmp(inst->firstlbl, (char *)label.base + 1, len) == 0)
		{
			return NS_HOOK_CONTINUE;
		}
	}

	qctx->client->message->rcode = inst->rcode;
	*resp = ns_query_done(qctx);
	return NS_HOOK_RETURN;
}

typedef struct {
	cfg_tokens_t tokens;
	const char *rcode;
	const char *source;
	const char *firstlbl;
} syncplugin_params_t;

static isc_result_t
syncplugin__parse_params(const char *const *parameters, const char *cfgfile,
			 unsigned long cfgline, syncplugin_params_t *params) {
	cfg_tokens_t *tok = &params->tokens;

	*params = (syncplugin_params_t){ 0 };

	cfg_tokens_init(tok, parameters, cfgfile, cfgline);
	while (cfg_tokens_peek(tok) != NULL) {
		const char *name = NULL;
		const char **valuep = NULL;

		RETERR(cfg_tokens_getstring(tok, &name));
		if (strcmp(name, "rcode") == 0) {
			valuep = &params->rcode;
		} else if (strcmp(name, "source") == 0) {
			valuep = &params->source;
		} else if (strcmp(name, "firstlbl") == 0) {
			valuep = &params->firstlbl;
		} else {
			cfg_tokens_log(tok, ISC_LOG_ERROR,
				       "unknown option '%s'", name);
			return ISC_R_FAILURE;
		}
		RETERR(cfg_tokens_getstring(tok, valuep));
		RETERR(cfg_tokens_expect(tok, CFG_TOKEN_END));
	}

	if (params->rcode == NULL || params->source == NULL) {
		return ISC_R_NOTFOUND;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
syncplugin__parse_rcode(const char *rcodestr, uint8_t *rcode) {
	isc_result_t result = ISC_R_SUCCESS;

	if (strcmp("servfail", rcodestr) == 0) {
		*rcode = dns_rcode_servfail;
	} else if (strcmp("notimp", rcodestr) == 0) {
		*rcode = dns_rcode_notimp;
	} else if (strcmp("noerror", rcodestr) == 0) {
		*rcode = dns_rcode_noerror;
	} else if (strcmp("notauth", rcodestr) == 0) {
		*rcode = dns_rcode_notauth;
	} else if (strcmp("notzone", rcodestr) == 0) {
		*rcode = dns_rcode_notzone;
	} else {
		result = ISC_R_FAILURE;
	}

	return result;
}

isc_result_t
plugin_register(const char *const *parameters, const void *cfg,
		const char *cfgfile, unsigned long cfgline, isc_mem_t *mctx,
		void *aclctx, ns_hooktable_t *hooktable,
		const ns_pluginctx_t *ctx, void **instp) {
	isc_result_t result;
	syncplugin_params_t params;
	ns_hook_t hook;
	syncplugin_t *inst = NULL;
	const char *sourcestr = NULL;
	dns_name_t example2com = DNS_NAME_INITEMPTY;
	dns_name_t example3com = DNS_NAME_INITEMPTY;
	dns_name_t example4com = DNS_NAME_INITEMPTY;

	UNUSED(cfg);
	UNUSED(aclctx);
	UNUSED(ctx);

	inst = isc_mem_get(mctx, sizeof(*inst));
	*inst = (syncplugin_t){ .mctx = mctx };
	*instp = inst;

	CHECK(syncplugin__parse_params(parameters, cfgfile, cfgline, &params));

	CHECK(syncplugin__parse_rcode(params.rcode, &inst->rcode));

	if (params.firstlbl != NULL) {
		size_t len = strlen(params.firstlbl) + 1;

		inst->firstlbl = isc_mem_allocate(mctx, len);
		strncpy(inst->firstlbl, params.firstlbl, len);
	}

	sourcestr = params.source;

	if (strcmp(sourcestr, "zone") == 0) {
		if (ctx->source != NS_HOOKSOURCE_ZONE) {
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		if (ctx->origin == NULL) {
			result = ISC_R_FAILURE;
			goto cleanup;
		}

		CHECK(dns_name_fromstring(&example2com, "example2.com.", NULL,
					  0, isc_g_mctx));
		CHECK(dns_name_fromstring(&example3com, "example3.com.", NULL,
					  0, isc_g_mctx));
		CHECK(dns_name_fromstring(&example4com, "example4.com.", NULL,
					  0, isc_g_mctx));

		if (!dns_name_equal(ctx->origin, &example2com) &&
		    !dns_name_equal(ctx->origin, &example3com) &&
		    !dns_name_equal(ctx->origin, &example4com))
		{
			result = ISC_R_FAILURE;
			goto cleanup;
		}

	} else if (strcmp(sourcestr, "view") == 0) {
		if (ctx->source != NS_HOOKSOURCE_VIEW) {
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		if (ctx->origin != NULL) {
			result = ISC_R_FAILURE;
			goto cleanup;
		}
	} else {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	hook = (ns_hook_t){ .action = syncplugin__hook, .action_data = inst };
	ns_hook_add(hooktable, mctx, NS_QUERY_NXDOMAIN_BEGIN, &hook);

cleanup:
	cfg_tokens_clear(&params.tokens);
	if (dns_name_dynamic(&example2com)) {
		dns_name_free(&example2com, isc_g_mctx);
	}

	if (dns_name_dynamic(&example3com)) {
		dns_name_free(&example3com, isc_g_mctx);
	}

	if (dns_name_dynamic(&example4com)) {
		dns_name_free(&example4com, isc_g_mctx);
	}

	return result;
}

isc_result_t
plugin_check(const char *const *parameters, const void *cfg,
	     const char *cfgfile, unsigned long cfgline, isc_mem_t *mctx,
	     void *aclctx, const ns_pluginctx_t *ctx) {
	UNUSED(parameters);
	UNUSED(cfg);
	UNUSED(cfgfile);
	UNUSED(cfgline);
	UNUSED(mctx);
	UNUSED(aclctx);
	UNUSED(ctx);

	return ISC_R_SUCCESS;
}

void
plugin_destroy(void **instp) {
	syncplugin_t *inst = *instp;
	isc_mem_t *mctx = inst->mctx;

	if (inst->firstlbl != NULL) {
		isc_mem_free(mctx, inst->firstlbl);
	}

	isc_mem_put(mctx, inst, sizeof(*inst));
	*instp = NULL;
}

int
plugin_version(void) {
	return NS_PLUGIN_VERSION;
}
