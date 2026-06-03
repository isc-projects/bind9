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

#include <dns/byaddr.h>
#include <dns/rdatalist.h>
#include <dns/view.h>

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <ns/hooks.h>

#define DEFAULT_TTL 300

typedef enum { UNDEFINED, FORWARD, REVERSE } synthrecord_mode_t;

typedef struct synthrecord synthrecord_t;
struct synthrecord {
	isc_mem_t *mctx;
	dns_acl_t *allowedsynth;
	isc_region_t prefix;
	dns_name_t origin;
	uint32_t ttl;
	synthrecord_mode_t mode;
};

static bool
synthrecord_allowedsynth(synthrecord_t *inst, isc_netaddr_t *net) {
	return dns_acl_allowed(net, NULL, inst->allowedsynth, NULL);
}

static void
synthrecord_chrreplace(isc_buffer_t *b, char from, char to) {
	while (isc_buffer_consumedlength(b) < isc_buffer_usedlength(b)) {
		char *c = isc_buffer_current(b);

		if (*c == from) {
			*c = to;
		}
		isc_buffer_forward(b, 1);
	}

	isc_buffer_first(b);
}

static isc_result_t
synthrecord_reverseanswer(synthrecord_t *inst, isc_netaddr_t *na,
			  dns_name_t *synthname) {
	isc_buffer_t b;
	char bdata[DNS_NAME_FORMATSIZE];
	isc_buffer_t addrb;
	char addrbdata[DNS_NAME_FORMATSIZE];
	isc_region_t addrr;

	REQUIRE(DNS_NAME_VALID(synthname));
	REQUIRE(na->family == AF_INET || na->family == AF_INET6);

	isc_buffer_init(&b, bdata, sizeof(bdata));
	RETERR(isc_buffer_copyregion(&b, &inst->prefix));

	isc_buffer_init(&addrb, addrbdata, sizeof(addrbdata));
	RETERR(isc_netaddr_totext(na, &addrb));

	/*
	 * IDN compatibility, as an IPv6 beginning or ending with `::` will be
	 * converted into `--` and RFC5890 section 2.3.1 states that an IDN
	 * label can't start or end with an hyphen.
	 */
	if (na->family == AF_INET6) {
		uint8_t c = 0;

		/*
		 * Address starts with `::`, so append a `0` right after the
		 * prefix.
		 */
		isc_buffer_peekuint8(&addrb, &c);
		if (c == ':') {
			if (isc_buffer_availablelength(&b) == 0) {
				return ISC_R_NOSPACE;
			}
			isc_buffer_putuint8(&b, '0');
		}

		/*
		 * Address ends with `::`, so add a `0` at the end of the
		 * address.
		 */
		isc_buffer_forward(&addrb, isc_buffer_usedlength(&addrb) - 1);
		isc_buffer_peekuint8(&addrb, &c);
		if (c == ':') {
			if (isc_buffer_availablelength(&b) == 0) {
				return ISC_R_NOSPACE;
			}
			isc_buffer_putuint8(&addrb, '0');
		}
	}

	isc_buffer_usedregion(&addrb, &addrr);
	RETERR(isc_buffer_copyregion(&b, &addrr));

	/*
	 * Do not attempt to replace anything in the prefix
	 */
	isc_buffer_forward(&b, inst->prefix.length);
	synthrecord_chrreplace(&b, na->family == AF_INET ? '.' : ':', '-');

	return dns_name_fromtext(synthname, &b, &inst->origin, 0);
}

static isc_result_t
synthrecord_respond(synthrecord_t *inst, query_ctx_t *qctx, void *rdata,
		    dns_rdatatype_t rtype) {
	isc_result_t result;
	isc_mem_t *mctx = qctx->client->inner.view->mctx;
	dns_message_t *msg = qctx->client->message;
	dns_name_t aname = DNS_NAME_INITEMPTY;
	dns_rdataset_t *synthset = NULL;
	dns_rdatalist_t *synthlist = NULL;
	dns_rdata_t *synthdata = NULL;
	isc_buffer_t synthdatab;
	char synthdatabdata[DNS_NAME_MAXWIRE];

	/*
	 * Build the rdata from synthesized name
	 */
	dns_message_gettemprdata(msg, &synthdata);
	isc_buffer_init(&synthdatab, synthdatabdata, sizeof(synthdatabdata));
	CHECK(dns_rdata_fromstruct(synthdata, dns_rdataclass_in, rtype, rdata,
				   &synthdatab));

	/*
	 * Reference synthdata from the rdatalist
	 */
	dns_message_gettemprdatalist(msg, &synthlist);
	synthlist->ttl = inst->ttl;
	synthlist->rdclass = dns_rdataclass_in;
	synthlist->type = rtype;
	ISC_LIST_APPEND(synthlist->rdata, synthdata, link);

	/*
	 * Fill the rdataset with the rdatalist
	 */
	dns_message_gettemprdataset(msg, &synthset);
	dns_rdatalist_tordataset(synthlist, synthset);

	/*
	 * Then create the name in the ANSWER section and attach the
	 * rdataset to it.
	 */
	dns_name_dup(qctx->client->query.qname, mctx, &aname);
	dns_message_addname(msg, &aname, DNS_SECTION_ANSWER);
	dns_rdataset_setownercase(synthset, &aname);
	ISC_LIST_APPEND(aname.list, synthset, link);

	/*
	 * Send the message with the ANSWER section containing the
	 * synthesized PTR rdata.
	 */
	result = ns_query_done(qctx);

	/*
	 * Message is gone now, let's free message response datastructures
	 */
	dns_message_removename(msg, &aname, DNS_SECTION_ANSWER);
	ISC_LIST_UNLINK(aname.list, synthset, link);
	dns_name_free(&aname, mctx);

	dns_rdataset_disassociate(synthset);
	dns_message_puttemprdataset(msg, &synthset);

	ISC_LIST_UNLINK(synthlist->rdata, synthdata, link);
	dns_message_puttemprdatalist(msg, &synthlist);

cleanup:
	dns_message_puttemprdata(msg, &synthdata);

	return result;
}

static bool
synthrecord_parseforward(synthrecord_t *inst, const dns_name_t *name,
			 isc_netaddr_t *addr) {
	dns_name_t label;
	char bdata[DNS_NAME_FORMATSIZE];
	isc_buffer_t b;
	size_t labelcount = dns_name_countlabels(name);
	dns_name_t subname;

	/*
	 * A forward name last label is `prefix-<encoded ip>`.<origin>
	 */
	if (labelcount <= 2) {
		return false;
	}

	dns_name_init(&subname);
	dns_name_getlabelsequence(name, 1, labelcount - 1, &subname);
	if (!dns_name_equal(&subname, &inst->origin)) {
		return false;
	}

	/*
	 * First, extract the first label which contains the prefix (which
	 * should match) and the encoded address.
	 */
	dns_name_init(&label);
	dns_name_getlabelsequence(name, 0, 1, &label);
	dns_name_downcase(&label, &label);

	isc_buffer_init(&b, bdata, sizeof(bdata));
	dns_name_totext(&label, DNS_NAME_OMITFINALDOT, &b);

	/*
	 * Buffer is `DNS_NAME_FORMATSIZE` which is the maximum length of
	 * `dns_name_totext()` can put in there, plus one byte which we're
	 * setting here. So we know there is at least one remaining byte in the
	 * buffer.
	 */
	isc_buffer_putuint8(&b, 0);
	if (strncmp((const char *)inst->prefix.base, isc_buffer_base(&b),
		    inst->prefix.length) != 0)
	{
		return false;
	}

	/*
	 * Let's parse the address, starting right after the prefix. First try
	 * as if it's an IPv6 address, and IPv4 in case of failure.
	 */
	synthrecord_chrreplace(&b, '-', ':');
	isc_buffer_forward(&b, inst->prefix.length);
	addr->family = AF_INET6;
	if (inet_pton(addr->family, isc_buffer_current(&b), &addr->type.in6) ==
	    1)
	{
		return true;
	}

	synthrecord_chrreplace(&b, ':', '.');
	isc_buffer_forward(&b, inst->prefix.length);
	addr->family = AF_INET;
	if (inet_pton(addr->family, isc_buffer_current(&b), &addr->type.in) ==
	    1)
	{
		return true;
	}

	return false;
}

static ns_hookresult_t
synthrecord_forward(synthrecord_t *inst, query_ctx_t *qctx,
		    isc_result_t *resp) {
	isc_netaddr_t addr;
	const dns_name_t *qname = qctx->client->query.qname;

	*resp = ISC_R_UNSET;

	if (!synthrecord_parseforward(inst, qname, &addr)) {
		return NS_HOOK_CONTINUE;
	}

	if (!synthrecord_allowedsynth(inst, &addr)) {
		return NS_HOOK_CONTINUE;
	}

	if (qctx->qtype != dns_rdatatype_a &&
	    qctx->qtype != dns_rdatatype_aaaa &&
	    qctx->qtype != dns_rdatatype_any)
	{
		/*
		 * The name is a candidate for a synthetic record, but the type
		 * is not A/AAAA. So, from protocol perspective, a record with
		 * this name "exists", even if there is no answer here.
		 */
		qctx->client->message->rcode = dns_rcode_noerror;
		*resp = ns_query_done(qctx);
		return NS_HOOK_RETURN;
	}

	if ((qctx->qtype == dns_rdatatype_a ||
	     qctx->qtype == dns_rdatatype_any) &&
	    addr.family == AF_INET)
	{
		dns_rdata_in_a_t ardata = { .in_addr = addr.type.in };
		DNS_RDATACOMMON_INIT(&ardata, dns_rdatatype_a,
				     dns_rdataclass_in);
		*resp = synthrecord_respond(inst, qctx, &ardata,
					    dns_rdatatype_a);
	} else if ((qctx->qtype == dns_rdatatype_aaaa ||
		    qctx->qtype == dns_rdatatype_any) &&
		   addr.family == AF_INET6)
	{
		dns_rdata_in_aaaa_t aaaardata = { .in6_addr = addr.type.in6 };
		DNS_RDATACOMMON_INIT(&aaaardata, dns_rdatatype_aaaa,
				     dns_rdataclass_in);
		*resp = synthrecord_respond(inst, qctx, &aaaardata,
					    dns_rdatatype_aaaa);
	} else {
		/*
		 * qtype is A but the address format matches AAAA, or
		 * qtype AAAA but format A. Either way, there is nothing
		 * to answer here.
		 */
		qctx->client->message->rcode = dns_rcode_noerror;
		*resp = ns_query_done(qctx);
	}

	return NS_HOOK_RETURN;
}

static ns_hookresult_t
synthrecord_reverse(synthrecord_t *inst, query_ctx_t *qctx,
		    isc_result_t *resp) {
	isc_result_t result;
	dns_name_t aname = DNS_NAME_INITEMPTY;
	char anamebdata[DNS_NAME_FORMATSIZE];
	isc_buffer_t anameb;
	isc_netaddr_t qaddr;
	const dns_name_t *qname = qctx->client->query.qname;
	dns_rdata_ptr_t synthptrdata;

	*resp = ISC_R_UNSET;

	result = dns_byaddr_parseptrname(qname, &qaddr);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_DEBUG(10),
			      "synthrecord ptr parsing error %s",
			      isc_result_totext(result));
		return NS_HOOK_CONTINUE;
	}

	if (!synthrecord_allowedsynth(inst, &qaddr)) {
		return NS_HOOK_CONTINUE;
	}

	if (qctx->qtype != dns_rdatatype_ptr &&
	    qctx->qtype != dns_rdatatype_any)
	{
		/*
		 * The name is a candidate for a synthetic record, but the
		 * type is not PTR. So, from protocol perspective, a record
		 * with this name "exists", even if there is no answer
		 * here.
		 */
		qctx->client->message->rcode = dns_rcode_noerror;
		*resp = ns_query_done(qctx);
		return NS_HOOK_RETURN;
	}

	isc_buffer_init(&anameb, anamebdata, sizeof(anamebdata));
	dns_name_setbuffer(&aname, &anameb);
	result = synthrecord_reverseanswer(inst, &qaddr, &aname);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(
			NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			ISC_LOG_DEBUG(1),
			"synthrecord cannot create reverse answer name: %s",
			isc_result_totext(result));
		return NS_HOOK_CONTINUE;
	}

	synthptrdata = (dns_rdata_ptr_t){
		.mctx = qctx->client->inner.view->mctx, .ptr = aname
	};
	DNS_RDATACOMMON_INIT(&synthptrdata, dns_rdatatype_ptr,
			     dns_rdataclass_in);
	result = synthrecord_respond(inst, qctx, &synthptrdata,
				     dns_rdatatype_ptr);
	*resp = result;

	return NS_HOOK_RETURN;
}

static ns_hookresult_t
synthrecord_entry(void *arg, void *cbdata, isc_result_t *resp) {
	synthrecord_t *inst = cbdata;
	query_ctx_t *qctx = arg;

	REQUIRE(qctx != NULL && qctx->zone != NULL);
	REQUIRE(inst != NULL);

	switch (inst->mode) {
	case FORWARD:
		return synthrecord_forward(inst, qctx, resp);
	case REVERSE:
		return synthrecord_reverse(inst, qctx, resp);
	default:
		REQUIRE(false);
	}
}

static cfg_clausedef_t synthrecord_cfgclauses[] = {
	{ "prefix", &cfg_type_astring, 0, NULL },
	{ "origin", &cfg_type_astring, 0, NULL },
	{ "allow-synth", &cfg_type_bracketed_aml, 0, NULL },
	{ "ttl", &cfg_type_uint32, 0, NULL }
};

static cfg_clausedef_t *synthrecord_cfgparamsclausesets[] = {
	synthrecord_cfgclauses, NULL
};

static cfg_type_t synthrecord_cfgparams = {
	"synthrecord-params", cfg_parse_mapbody, cfg_print_mapbody,
	cfg_doc_mapbody,      &cfg_rep_map,	 synthrecord_cfgparamsclausesets
};

static isc_result_t
synthrecord_initprefix(synthrecord_t *inst, const cfg_obj_t *synthrecordcfg) {
	isc_result_t result;
	const char *base = NULL;
	const cfg_obj_t *obj = NULL;

	result = cfg_map_get(synthrecordcfg, "prefix", &obj);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR, "synthrecord: prefix not found");
		return result;
	}

	base = obj->value.string;
	if (strstr(base, ".") != NULL) {
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "synthrecord: prefix '%s' must be a single label",
			      base);
		return ISC_R_UNEXPECTEDTOKEN;
	}

	inst->prefix = (isc_region_t){ .base = (unsigned char *)isc_mem_strdup(
					       inst->mctx, base),
				       .length = strlen(base) };

	/*
	 * Avoid dynamically lower-casing the prefix when parsing the
	 * address in the forward flow.
	 */
	isc_ascii_lowercopy((uint8_t *)inst->prefix.base,
			    (uint8_t *)inst->prefix.base, inst->prefix.length);

	return result;
}

static isc_result_t
synthrecord_initorigin(synthrecord_t *inst, const cfg_obj_t *synthrecordcfg,
		       const dns_name_t *zname) {
	isc_result_t result;
	const cfg_obj_t *obj = NULL;
	const char *originstr = NULL;

	result = cfg_map_get(synthrecordcfg, "origin", &obj);
	if (inst->mode == REVERSE && result != ISC_R_SUCCESS) {
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_ERROR,
			      "'origin' must be set when configuring "
			      "'synthrecord' for a reverse zone");
		return result;
	}

	dns_name_init(&inst->origin);
	if (result == ISC_R_SUCCESS) {
		originstr = cfg_obj_asstring(obj);
		RETERR(dns_name_fromstring(&inst->origin, originstr, NULL, 0,
					   inst->mctx));

		if (!dns_name_isabsolute(&inst->origin)) {
			isc_log_write(NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
				      "synthrecord: origin '%s' not absolute",
				      originstr);
			return ISC_R_FAILURE;
		}
	} else {
		dns_name_dup(zname, inst->mctx, &inst->origin);
	}

	return ISC_R_SUCCESS;
}

static void
synthrecord_setconfigmode(synthrecord_t *inst, const dns_name_t *zname) {
	if (dns_name_issubdomain(zname, dns_ip6arpa) ||
	    dns_name_issubdomain(zname, dns_inaddrarpa))
	{
		inst->mode = REVERSE;
	} else {
		inst->mode = FORWARD;
	}
}

static isc_result_t
synthrecord_parseallowsynth(synthrecord_t *inst, const cfg_obj_t *cfg,
			    cfg_aclconfctx_t *aclctx,
			    const cfg_obj_t *synthrecordcfg) {
	isc_result_t result;
	const cfg_obj_t *obj = NULL;

	INSIST(inst->allowedsynth == NULL);
	result = cfg_map_get(synthrecordcfg, "allow-synth", &obj);

	if (result == ISC_R_NOTFOUND) {
		return dns_acl_any(inst->mctx, &inst->allowedsynth);
	}

	if (result != ISC_R_SUCCESS) {
		return result;
	}

	RETERR(cfg_acl_fromconfig(obj, cfg, aclctx, inst->mctx, 0,
				  &inst->allowedsynth));

	for (unsigned int i = 0; i < inst->allowedsynth->length; i++) {
		switch (inst->allowedsynth->elements[i].type) {
		case dns_aclelementtype_nestedacl:
		case dns_aclelementtype_localhost:
		case dns_aclelementtype_localnets:
			continue;
		default:
			/* This rejects keyname and geoip elements */
			isc_log_write(NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_HOOKS, ISC_LOG_ERROR,
				      "synthrecord: allow-synth must be an "
				      "address-match list");
			return ISC_R_UNEXPECTED;
		}
	}
	return result;
}

static isc_result_t
synthrecord_parsettl(synthrecord_t *inst, const cfg_obj_t *synthrecordcfg) {
	isc_result_t result;
	const cfg_obj_t *obj = NULL;

	result = cfg_map_get(synthrecordcfg, "ttl", &obj);

	if (result == ISC_R_NOTFOUND) {
		inst->ttl = DEFAULT_TTL;
		result = ISC_R_SUCCESS;
	} else if (result == ISC_R_SUCCESS) {
		inst->ttl = cfg_obj_asuint32(obj);
	}

	return result;
}

static isc_result_t
synthrecord_parseconfig(synthrecord_t *inst, const char *parameters,
			const cfg_obj_t *cfg, const char *cfgfile,
			unsigned long cfgline, cfg_aclconfctx_t *aclctx,
			const dns_name_t *zname) {
	isc_result_t result;
	cfg_obj_t *synthrecordcfg = NULL;
	isc_buffer_t b;

	isc_buffer_constinit(&b, parameters, strlen(parameters));
	isc_buffer_add(&b, strlen(parameters));

	CHECK(cfg_parse_buffer(&b, cfgfile, cfgline, &synthrecord_cfgparams, 0,
			       &synthrecordcfg));

	synthrecord_setconfigmode(inst, zname);
	CHECK(synthrecord_initorigin(inst, synthrecordcfg, zname));
	CHECK(synthrecord_initprefix(inst, synthrecordcfg));
	CHECK(synthrecord_parseallowsynth(inst, cfg, aclctx, synthrecordcfg));
	CHECK(synthrecord_parsettl(inst, synthrecordcfg));

cleanup:
	if (synthrecordcfg != NULL) {
		cfg_obj_detach(&synthrecordcfg);
	}

	return result;
}

isc_result_t
plugin_register(const char *parameters, const void *cfg, const char *cfgfile,
		unsigned long cfgline, isc_mem_t *mctx, void *aclctx,
		ns_hooktable_t *hooktable, const ns_pluginctx_t *ctx,
		void **instp) {
	synthrecord_t *inst = NULL;
	ns_hook_t hook;
	isc_result_t result;

	REQUIRE(cfg);
	REQUIRE(mctx);
	REQUIRE(aclctx);
	REQUIRE(hooktable);
	REQUIRE(instp && *instp == NULL);

	isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "registering 'synthrecord' module from %s:%lu", cfgfile,
		      cfgline);

	inst = isc_mem_get(mctx, sizeof(*inst));
	*inst = (synthrecord_t){ .prefix = {} };
	*instp = inst;

	isc_mem_attach(mctx, &inst->mctx);
	result = ISC_R_SUCCESS;
	result = synthrecord_parseconfig(inst, parameters, cfg, cfgfile,
					 cfgline, aclctx, ctx->origin);

	hook = (ns_hook_t){ .action = synthrecord_entry, .action_data = inst };
	ns_hook_add(hooktable, mctx, NS_QUERY_NXDOMAIN_BEGIN, &hook);

	/*
	 * The qname with a different type might be defined in the zone. If
	 * there is a delegation, NS_QUERY_NODATA_BEGIN is never called.
	 */
	ns_hook_add(hooktable, mctx, NS_QUERY_NODATA_BEGIN, &hook);

	return result;
}

isc_result_t
plugin_check(const char *parameters, const void *cfg, const char *cfgfile,
	     unsigned long cfgline, isc_mem_t *mctx, void *aclctx,
	     const ns_pluginctx_t *ctx) {
	isc_result_t result;
	synthrecord_t *inst = NULL;

	REQUIRE(ctx != NULL);
	if (ctx->source != NS_HOOKSOURCE_ZONE || ctx->origin == NULL) {
		isc_log_write(NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_HOOKS,
			      ISC_LOG_INFO,
			      "'synthrecord' must be configured "
			      "as a zone plugin");
		return ISC_R_FAILURE;
	}

	inst = isc_mem_get(mctx, sizeof(*inst));
	*inst = (synthrecord_t){};

	isc_mem_attach(mctx, &inst->mctx);
	result = synthrecord_parseconfig(inst, parameters, cfg, cfgfile,
					 cfgline, aclctx, ctx->origin);
	plugin_destroy((void **)&inst);

	return result;
}

void
plugin_destroy(void **instp) {
	REQUIRE(instp && *instp);

	synthrecord_t *inst = *instp;
	isc_mem_t *mctx = inst->mctx;

	if (inst->allowedsynth != NULL) {
		dns_acl_detach(&inst->allowedsynth);
	}

	if (inst->prefix.base != NULL) {
		isc_mem_free(mctx, inst->prefix.base);
	}

	if (DNS_NAME_VALID(&inst->origin)) {
		dns_name_free(&inst->origin, inst->mctx);
	}

	isc_mem_putanddetach(&inst->mctx, inst, sizeof(*inst));
	*instp = NULL;
}

int
plugin_version(void) {
	return NS_PLUGIN_VERSION;
}
