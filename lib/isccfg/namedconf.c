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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <isc/lex.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/ttl.h>

#include <isccfg/cfg.h>
#include <isccfg/clause.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#define TOKEN_STRING(pctx) (pctx->token.value.as_textregion.base)

/*% Clean up a configuration object if non-NULL. */
#define CLEANUP_OBJ(obj)                        \
	{                                       \
		if ((obj) != NULL) {            \
			cfg_obj_detach(&(obj)); \
		}                               \
	}

/*%
 * Forward declarations of static functions.
 */

static isc_result_t
parse_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

static isc_result_t
parse_optional_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret);

static isc_result_t
parse_updatepolicy(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);
static void
print_updatepolicy(cfg_printer_t *pctx, const cfg_obj_t *obj);

static void
doc_updatepolicy(cfg_printer_t *pctx, const cfg_type_t *type);

static void
print_keyvalue(cfg_printer_t *pctx, const cfg_obj_t *obj);

static void
doc_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type);

static void
doc_optional_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type);

static isc_result_t
cfg_parse_kv_tuple(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

static void
cfg_print_kv_tuple(cfg_printer_t *pctx, const cfg_obj_t *obj);

static void
cfg_doc_kv_tuple(cfg_printer_t *pctx, const cfg_type_t *type);

static cfg_type_t cfg_type_acl;
static cfg_type_t cfg_type_bracketed_namesockaddrkeylist;
static cfg_type_t cfg_type_bracketed_netaddrlist;
static cfg_type_t cfg_type_bracketed_sockaddrnameportlist;
static cfg_type_t cfg_type_bracketed_sockaddrtlslist;
static cfg_type_t cfg_type_bracketed_http_endpoint_list;
static cfg_type_t cfg_type_checkdstype;
static cfg_type_t cfg_type_controls;
static cfg_type_t cfg_type_controls_sockaddr;
static cfg_type_t cfg_type_destinationlist;
static cfg_type_t cfg_type_dlz;
static cfg_type_t cfg_type_dnssecpolicy;
static cfg_type_t cfg_type_dnstap;
static cfg_type_t cfg_type_dnstapoutput;
static cfg_type_t cfg_type_dyndb;
static cfg_type_t cfg_type_http_description;
static cfg_type_t cfg_type_ixfrdifftype;
static cfg_type_t cfg_type_ixfrratio;
static cfg_type_t cfg_type_key;
static cfg_type_t cfg_type_keystore;
static cfg_type_t cfg_type_logfile;
static cfg_type_t cfg_type_logging;
static cfg_type_t cfg_type_logseverity;
static cfg_type_t cfg_type_logsuffix;
static cfg_type_t cfg_type_logversions;
static cfg_type_t cfg_type_remoteselement;
static cfg_type_t cfg_type_maxcachesize;
static cfg_type_t cfg_type_maxduration;
static cfg_type_t cfg_type_minimal;
static cfg_type_t cfg_type_nameportiplist;
static cfg_type_t cfg_type_notifycfg;
static cfg_type_t cfg_type_notifytype;
static cfg_type_t cfg_type_optional_allow;
static cfg_type_t cfg_type_optional_class;
static cfg_type_t cfg_type_optional_facility;
static cfg_type_t cfg_type_optional_keyref;
static cfg_type_t cfg_type_optional_port;
static cfg_type_t cfg_type_optional_sourceaddr4;
static cfg_type_t cfg_type_optional_sourceaddr6;
static cfg_type_t cfg_type_optional_uint32;
static cfg_type_t cfg_type_optional_tls;
static cfg_type_t cfg_type_options;
static cfg_type_t cfg_type_plugin;
static cfg_type_t cfg_type_portiplist;
static cfg_type_t cfg_type_printtime;
static cfg_type_t cfg_type_qminmethod;
static cfg_type_t cfg_type_querysource4;
static cfg_type_t cfg_type_querysource6;
static cfg_type_t cfg_type_server_querysource4;
static cfg_type_t cfg_type_server_querysource6;
static cfg_type_t cfg_type_querysource;
static cfg_type_t cfg_type_server;
static cfg_type_t cfg_type_server_key_kludge;
static cfg_type_t cfg_type_size;
static cfg_type_t cfg_type_sizenodefault;
static cfg_type_t cfg_type_sizeval;
static cfg_type_t cfg_type_sockaddr4wild;
static cfg_type_t cfg_type_sockaddr6wild;
static cfg_type_t cfg_type_statschannels;
static cfg_type_t cfg_type_template;
static cfg_type_t cfg_type_templateopts;
static cfg_type_t cfg_type_tlsconf;
static cfg_type_t cfg_type_view;
static cfg_type_t cfg_type_viewopts;
static cfg_type_t cfg_type_zone;

/*% listen-on */

static cfg_tuplefielddef_t listenon_tuple_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	/*
	 * Let's follow the protocols encapsulation order (lower->upper), at
	 * least roughly.
	 */
	{ "proxy", &cfg_type_astring, CFG_CLAUSEFLAG_EXPERIMENTAL },
	{ "tls", &cfg_type_astring, 0 },
#if HAVE_LIBNGHTTP2
	{ "http", &cfg_type_astring, CFG_CLAUSEFLAG_OPTIONAL },
#else
	{ "http", &cfg_type_astring, CFG_CLAUSEFLAG_NOTCONFIGURED },
#endif
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_listen_tuple = {
	"listenon tuple", cfg_parse_kv_tuple, cfg_print_kv_tuple,
	cfg_doc_kv_tuple, &cfg_rep_tuple,     listenon_tuple_fields
};

static cfg_tuplefielddef_t listenon_fields[] = {
	{ "tuple", &cfg_type_listen_tuple, 0 },
	{ "acl", &cfg_type_bracketed_aml, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_listenon = { "listenon",	 cfg_parse_tuple,
					cfg_print_tuple, cfg_doc_tuple,
					&cfg_rep_tuple,	 listenon_fields };

/*% acl */

/*
 * Encrypted transfer related definitions
 */

static cfg_tuplefielddef_t cfg_transport_acl_tuple_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "transport", &cfg_type_astring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_transport_acl_tuple = {
	"transport-acl tuple", cfg_parse_kv_tuple,
	cfg_print_kv_tuple,    cfg_doc_kv_tuple,
	&cfg_rep_tuple,	       cfg_transport_acl_tuple_fields
};

static cfg_tuplefielddef_t cfg_transport_acl_fields[] = {
	{ "port-transport", &cfg_transport_acl_tuple, 0 },
	{ "aml", &cfg_type_bracketed_aml, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_transport_acl = {
	"transport-acl", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	 &cfg_rep_tuple,  cfg_transport_acl_fields
};

/*
 * NOTE: To enable syntax which allows specifying port and protocol,
 * replace 'cfg_type_bracketed_aml' with
 * 'cfg_type_transport_acl'.
 *
 * Example: acl port 853 protocol tls { ... };
 */
static cfg_tuplefielddef_t acl_fields[] = { { "name", &cfg_type_astring, 0 },
					    { "value", &cfg_type_bracketed_aml,
					      0 },
					    { NULL, NULL, 0 } };

static cfg_type_t cfg_type_acl = { "acl",	    cfg_parse_tuple,
				   cfg_print_tuple, cfg_doc_tuple,
				   &cfg_rep_tuple,  acl_fields };

/*% remote servers, used for primaries and parental agents */
static cfg_tuplefielddef_t remotes_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "port", &cfg_type_optional_port, 0 },
	{ "source", &cfg_type_optional_sourceaddr4, 0 },
	{ "source-v6", &cfg_type_optional_sourceaddr6, 0 },
	{ "addresses", &cfg_type_bracketed_namesockaddrkeylist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_serverlist = { "server-list",   cfg_parse_tuple,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  remotes_fields };

/*%
 * "sockaddrkeylist", a list of socket addresses with optional keys
 * and an optional default port, as used in the remote-servers option.
 * E.g.,
 *   "port 1234 { myservers; 10.0.0.1 key foo; 1::2 port 69; }"
 */

static cfg_tuplefielddef_t namesockaddrkey_fields[] = {
	{ "remoteselement", &cfg_type_remoteselement, 0 },
	{ "key", &cfg_type_optional_keyref, 0 },
	{ "tls", &cfg_type_optional_tls, 0 },
	{ NULL, NULL, 0 },
};

static cfg_type_t cfg_type_namesockaddrkey = {
	"namesockaddrkey", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	   &cfg_rep_tuple,  namesockaddrkey_fields
};

static cfg_type_t cfg_type_bracketed_namesockaddrkeylist = {
	"bracketed_namesockaddrkeylist",
	cfg_parse_bracketed_list,
	cfg_print_bracketed_list,
	cfg_doc_bracketed_list,
	&cfg_rep_list,
	&cfg_type_namesockaddrkey
};

static cfg_tuplefielddef_t namesockaddrkeylist_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "source", &cfg_type_optional_sourceaddr4, 0 },
	{ "source-v6", &cfg_type_optional_sourceaddr6, 0 },
	{ "addresses", &cfg_type_bracketed_namesockaddrkeylist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_namesockaddrkeylist = {
	"sockaddrkeylist", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	   &cfg_rep_tuple,  namesockaddrkeylist_fields
};

/*%
 * A list of socket addresses with an optional default port, as used
 * in the 'forwarders' option.  E.g., "{ 10.0.0.1; 1::2 port 69; }"
 */
static cfg_tuplefielddef_t portiplist_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "tls", &cfg_type_optional_tls, 0 },
	{ "addresses", &cfg_type_bracketed_sockaddrtlslist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_portiplist = { "portiplist",	   cfg_parse_tuple,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  portiplist_fields };

/*%
 * A list of RR types, used in grant statements.
 * Note that the old parser allows quotes around the RR type names.
 */
static cfg_type_t cfg_type_rrtypelist = {
	"rrtypelist",	  cfg_parse_spacelist, cfg_print_spacelist,
	cfg_doc_terminal, &cfg_rep_list,       &cfg_type_astring
};

static const char *mode_enums[] = { "deny", "grant", NULL };
static cfg_type_t cfg_type_mode = {
	"mode",	      cfg_parse_enum,  cfg_print_ustring,
	cfg_doc_enum, &cfg_rep_string, &mode_enums
};

static isc_result_t
parse_matchtype(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "zonesub") == 0)
	{
		pctx->flags |= CFG_PCTX_SKIP;
	}
	return cfg_parse_enum(pctx, type, ret);

cleanup:
	return result;
}

static isc_result_t
parse_matchname(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;

	if ((pctx->flags & CFG_PCTX_SKIP) != 0) {
		pctx->flags &= ~CFG_PCTX_SKIP;
		CHECK(cfg_parse_void(pctx, NULL, &obj));
	} else {
		result = cfg_parse_astring(pctx, type, &obj);
	}

	*ret = obj;
cleanup:
	return result;
}

static void
doc_matchname(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_print_cstr(pctx, "[ ");
	cfg_doc_obj(pctx, type->of);
	cfg_print_cstr(pctx, " ]");
}

static const char *matchtype_enums[] = { "6to4-self",
					 "external",
					 "krb5-self",
					 "krb5-selfsub",
					 "krb5-subdomain",
					 "krb5-subdomain-self-rhs",
					 "ms-self",
					 "ms-selfsub",
					 "ms-subdomain",
					 "ms-subdomain-self-rhs",
					 "name",
					 "self",
					 "selfsub",
					 "selfwild",
					 "subdomain",
					 "tcp-self",
					 "wildcard",
					 "zonesub",
					 NULL };

static cfg_type_t cfg_type_matchtype = { "matchtype",	    parse_matchtype,
					 cfg_print_ustring, cfg_doc_enum,
					 &cfg_rep_string,   &matchtype_enums };

static cfg_type_t cfg_type_matchname = {
	"optional_matchname", parse_matchname, cfg_print_ustring,
	doc_matchname,	      &cfg_rep_tuple,  &cfg_type_ustring
};

/*%
 * A grant statement, used in the update policy.
 */
static cfg_tuplefielddef_t grant_fields[] = {
	{ "mode", &cfg_type_mode, 0 },
	{ "identity", &cfg_type_astring, 0 }, /* domain name */
	{ "matchtype", &cfg_type_matchtype, 0 },
	{ "name", &cfg_type_matchname, 0 }, /* domain name */
	{ "types", &cfg_type_rrtypelist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_grant = { "grant",	      cfg_parse_tuple,
				     cfg_print_tuple, cfg_doc_tuple,
				     &cfg_rep_tuple,  grant_fields };

static cfg_type_t cfg_type_updatepolicy = {
	"update_policy",  parse_updatepolicy, print_updatepolicy,
	doc_updatepolicy, &cfg_rep_list,      &cfg_type_grant
};

static isc_result_t
parse_updatepolicy(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	isc_result_t result;
	CHECK(cfg_gettoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_special &&
	    pctx->token.value.as_char == '{')
	{
		cfg_ungettoken(pctx);
		return cfg_parse_bracketed_list(pctx, type, ret);
	}

	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "local") == 0)
	{
		cfg_string_create(pctx, "local", &cfg_type_ustring, ret);
		return ISC_R_SUCCESS;
	}

	cfg_ungettoken(pctx);
	return ISC_R_UNEXPECTEDTOKEN;

cleanup:
	return result;
}

static void
print_updatepolicy(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	if (cfg_obj_isstring(obj)) {
		cfg_print_ustring(pctx, obj);
	} else {
		cfg_print_bracketed_list(pctx, obj);
	}
}

static void
doc_updatepolicy(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_print_cstr(pctx, "( local | { ");
	cfg_doc_obj(pctx, type->of);
	cfg_print_cstr(pctx, "; ... } )");
}

/*%
 * A view statement.
 */
static cfg_tuplefielddef_t view_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "class", &cfg_type_optional_class, 0 },
	{ "options", &cfg_type_viewopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_view = { "view",	     cfg_parse_tuple,
				    cfg_print_tuple, cfg_doc_tuple,
				    &cfg_rep_tuple,  view_fields };

/*%
 * A zone statement.
 */
static cfg_tuplefielddef_t zone_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "class", &cfg_type_optional_class, 0 },
	{ "options", &cfg_type_zoneopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_zone = { "zone",	     cfg_parse_tuple,
				    cfg_print_tuple, cfg_doc_tuple,
				    &cfg_rep_tuple,  zone_fields };

/*%
 * A zone statement.
 */
static cfg_tuplefielddef_t template_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "options", &cfg_type_templateopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_template = { "template",	 cfg_parse_tuple,
					cfg_print_tuple, cfg_doc_tuple,
					&cfg_rep_tuple,	 template_fields };

/*%
 * A dnssec-policy statement.
 */
static cfg_tuplefielddef_t dnssecpolicy_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "options", &cfg_type_dnssecpolicyopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_dnssecpolicy = {
	"dnssec-policy", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	 &cfg_rep_tuple,  dnssecpolicy_fields
};

/*%
 * A "category" clause in the "logging" statement.
 */
static cfg_tuplefielddef_t category_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "destinations", &cfg_type_destinationlist, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_category = { "category",	 cfg_parse_tuple,
					cfg_print_tuple, cfg_doc_tuple,
					&cfg_rep_tuple,	 category_fields };

static isc_result_t
parse_maxduration(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_duration, ret);
}

static void
doc_maxduration(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_duration);
}

/*%
 * A duration or "unlimited", but not "default".
 */
static const char *maxduration_enums[] = { "unlimited", NULL };
static cfg_type_t cfg_type_maxduration = {
	"maxduration_no_default", parse_maxduration, cfg_print_ustring,
	doc_maxduration,	  &cfg_rep_duration, maxduration_enums
};

/*%
 * Optional enums.
 *
 */
static isc_result_t
parse_optional_enum(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_void, ret);
}

static void
doc_optional_enum(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ ");
	cfg_doc_enum(pctx, type);
	cfg_print_cstr(pctx, " ]");
}

/*%
 * A key initialization specifier, as used in the "trust-anchors" statement.
 */
static const char *anchortype_enums[] = { "static-key", "initial-key",
					  "static-ds", "initial-ds", NULL };
static cfg_type_t cfg_type_anchortype = { "anchortype",	     cfg_parse_enum,
					  cfg_print_ustring, cfg_doc_enum,
					  &cfg_rep_string,   anchortype_enums };
static cfg_tuplefielddef_t managedkey_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "anchortype", &cfg_type_anchortype, 0 },
	{ "rdata1", &cfg_type_uint32, 0 },
	{ "rdata2", &cfg_type_uint32, 0 },
	{ "rdata3", &cfg_type_uint32, 0 },
	{ "data", &cfg_type_qstring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_managedkey = { "managedkey",	   cfg_parse_tuple,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  managedkey_fields };

/*%
 * DNSSEC key roles.
 */
static const char *dnsseckeyrole_enums[] = { "csk", "ksk", "zsk", NULL };
static cfg_type_t cfg_type_dnsseckeyrole = {
	"dnssec-key-role", cfg_parse_enum,  cfg_print_ustring,
	cfg_doc_enum,	   &cfg_rep_string, &dnsseckeyrole_enums
};

/*%
 * DNSSEC key storage types.
 */
static keyword_type_t keystore_kw = { "key-store", &cfg_type_astring };
static cfg_type_t cfg_type_keystorage = { "keystorage",	   parse_keyvalue,
					  print_keyvalue,  doc_keyvalue,
					  &cfg_rep_string, &keystore_kw };

static isc_result_t
parse_keystore(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;

	UNUSED(type);

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "key-directory") == 0)
	{
		CHECK(cfg_parse_obj(pctx, &cfg_type_ustring, &obj));
	} else if (pctx->token.type == isc_tokentype_string &&
		   strcasecmp(TOKEN_STRING(pctx), "key-store") == 0)
	{
		CHECK(cfg_parse_obj(pctx, &cfg_type_keystorage, &obj));
	} else {
		CHECK(cfg_parse_void(pctx, NULL, &obj));
	}

	*ret = obj;
cleanup:
	return result;
}

static void
doc_keystore(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);

	cfg_print_cstr(pctx, "[ key-directory | key-store <string> ]");
}

static void
print_keystore(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	REQUIRE(pctx != NULL);
	REQUIRE(obj != NULL);
	REQUIRE(obj->type->rep == &cfg_rep_string);

	if (strcasecmp(cfg_obj_asstring(obj), "key-directory") != 0) {
		cfg_print_cstr(pctx, "key-store ");
	}
	cfg_print_ustring(pctx, obj);
}

static cfg_type_t cfg_type_optional_keystore = {
	"optionalkeystorage", parse_keystore,  print_keystore,
	doc_keystore,	      &cfg_rep_string, &keystore_kw
};

/*%
 * A dnssec key, as used in the "keys" statement in a "dnssec-policy".
 */
static keyword_type_t algorithm_kw = { "algorithm", &cfg_type_ustring };
static cfg_type_t cfg_type_algorithm = { "algorithm",	  parse_keyvalue,
					 print_keyvalue,  doc_keyvalue,
					 &cfg_rep_string, &algorithm_kw };

static keyword_type_t lifetime_kw = { "lifetime",
				      &cfg_type_duration_or_unlimited };
static cfg_type_t cfg_type_lifetime = { "lifetime",	   parse_keyvalue,
					print_keyvalue,	   doc_keyvalue,
					&cfg_rep_duration, &lifetime_kw };
/*
 * Keytag range.
 */
static void
print_tagrange(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	REQUIRE(pctx != NULL);
	REQUIRE(obj != NULL);
	REQUIRE(obj->type->rep == &cfg_rep_tuple);

	if (cfg_obj_istuple(obj)) {
		cfg_print_cstr(pctx, "tag-range ");
		cfg_print_tuple(pctx, obj);
	}
}

static cfg_tuplefielddef_t tagrange_fields[] = {
	{ "tag-min", &cfg_type_uint32, 0 },
	{ "tag-max", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_tagrange = { "tagrange",	cfg_parse_tuple,
					print_tagrange, cfg_doc_tuple,
					&cfg_rep_tuple, tagrange_fields };

static keyword_type_t tagrange_kw = { "tag-range", &cfg_type_tagrange };
static void
doc_optionaltagrange(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);

	cfg_print_cstr(pctx, "[ tag-range <integer> <integer> ]");
}

static isc_result_t
parse_optionaltagrange(cfg_parser_t *pctx, const cfg_type_t *type,
		       cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;

	UNUSED(type);

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "tag-range") == 0)
	{
		CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
		CHECK(cfg_parse_obj(pctx, &cfg_type_tagrange, &obj));
	} else {
		CHECK(cfg_parse_void(pctx, NULL, &obj));
	}

	*ret = obj;
cleanup:
	return result;
}

static cfg_type_t cfg_type_optional_tagrange = {
	"optionaltagrange",   parse_optionaltagrange, NULL,
	doc_optionaltagrange, &cfg_rep_tuple,	      &tagrange_kw
};

/*
 * Key flags.
 */
static const char *keyflag_enums[] = { "sep", "adt", NULL };

static cfg_type_t cfg_type_keyflag = { "keyflag",	  cfg_parse_enum,
				       cfg_print_ustring, cfg_doc_enum,
				       &cfg_rep_string,	  keyflag_enums };

static cfg_type_t cfg_type_keyflaglist = {
	"keyflaglist",	   cfg_parse_spacelist, cfg_print_spacelist,
	cfg_doc_enum_list, &cfg_rep_list,	&cfg_type_keyflag
};

static keyword_type_t keyflags_kw = { "flags", &cfg_type_keyflaglist };

static cfg_type_t cfg_type_optional_keyflags = {
	"optional_keyflags",   parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_list,		&keyflags_kw
};

/*
 * KASP key.
 */
static cfg_tuplefielddef_t kaspkey_fields[] = {
	{ "role", &cfg_type_dnsseckeyrole, 0 },
	{ "keystorage", &cfg_type_optional_keystore, 0 },
	{ "lifetime", &cfg_type_lifetime, 0 },
	{ "algorithm", &cfg_type_algorithm, 0 },
	{ "tag-range", &cfg_type_optional_tagrange, 0 },
	{ "length", &cfg_type_optional_uint32, 0 },
	{ "flags", &cfg_type_optional_keyflags, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_kaspkey = { "kaspkey",	cfg_parse_tuple,
				       cfg_print_tuple, cfg_doc_tuple,
				       &cfg_rep_tuple,	kaspkey_fields };

/*%
 * NSEC3 parameters.
 */
static keyword_type_t nsec3iter_kw = { "iterations", &cfg_type_uint32 };
static cfg_type_t cfg_type_nsec3iter = {
	"iterations",	       parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_uint32,		&nsec3iter_kw
};

static keyword_type_t nsec3optout_kw = { "optout", &cfg_type_boolean };
static cfg_type_t cfg_type_nsec3optout = {
	"optout",	  parse_optional_keyvalue,
	print_keyvalue,	  doc_optional_keyvalue,
	&cfg_rep_boolean, &nsec3optout_kw
};

static keyword_type_t nsec3salt_kw = { "salt-length", &cfg_type_uint32 };
static cfg_type_t cfg_type_nsec3salt = {
	"salt-length",	       parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_uint32,		&nsec3salt_kw
};

static cfg_tuplefielddef_t nsec3param_fields[] = {
	{ "iterations", &cfg_type_nsec3iter, 0 },
	{ "optout", &cfg_type_nsec3optout, 0 },
	{ "salt-length", &cfg_type_nsec3salt, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_nsec3 = { "nsec3param",    cfg_parse_tuple,
				     cfg_print_tuple, cfg_doc_tuple,
				     &cfg_rep_tuple,  nsec3param_fields };

/*%
 * Wild class, type, name.
 */
static keyword_type_t wild_class_kw = { "class", &cfg_type_ustring };

static cfg_type_t cfg_type_optional_wild_class = {
	"optional_wild_class", parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_string,		&wild_class_kw
};

static keyword_type_t wild_type_kw = { "type", &cfg_type_ustring };

static cfg_type_t cfg_type_optional_wild_type = {
	"optional_wild_type",  parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_string,		&wild_type_kw
};

static keyword_type_t wild_name_kw = { "name", &cfg_type_qstring };

static cfg_type_t cfg_type_optional_wild_name = {
	"optional_wild_name",  parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_string,		&wild_name_kw
};

/*%
 * An rrset ordering element.
 */
static cfg_tuplefielddef_t rrsetorderingelement_fields[] = {
	{ "class", &cfg_type_optional_wild_class, 0 },
	{ "type", &cfg_type_optional_wild_type, 0 },
	{ "name", &cfg_type_optional_wild_name, 0 },
	{ "order", &cfg_type_ustring, 0 }, /* must be literal "order" */
	{ "ordering", &cfg_type_ustring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rrsetorderingelement = {
	"rrsetorderingelement", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,		&cfg_rep_tuple,	 rrsetorderingelement_fields
};

/*%
 * A global or view "check-names" option.  Note that the zone
 * "check-names" option has a different syntax.
 */

static const char *checktype_enums[] = { "primary", "master",	"secondary",
					 "slave",   "response", NULL };
static cfg_type_t cfg_type_checktype = { "checktype",	    cfg_parse_enum,
					 cfg_print_ustring, cfg_doc_enum,
					 &cfg_rep_string,   &checktype_enums };

static const char *checkmode_enums[] = { "fail", "warn", "ignore", NULL };
static cfg_type_t cfg_type_checkmode = { "checkmode",	    cfg_parse_enum,
					 cfg_print_ustring, cfg_doc_enum,
					 &cfg_rep_string,   &checkmode_enums };

static const char *warn_enums[] = { "warn", "ignore", NULL };
static cfg_type_t cfg_type_warn = {
	"warn",	      cfg_parse_enum,  cfg_print_ustring,
	cfg_doc_enum, &cfg_rep_string, &warn_enums
};

static cfg_tuplefielddef_t checknames_fields[] = {
	{ "type", &cfg_type_checktype, 0 },
	{ "mode", &cfg_type_checkmode, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_checknames = { "checknames",	   cfg_parse_tuple,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  checknames_fields };

static cfg_type_t cfg_type_bracketed_netaddrlist = { "bracketed_netaddrlist",
						     cfg_parse_bracketed_list,
						     cfg_print_bracketed_list,
						     cfg_doc_bracketed_list,
						     &cfg_rep_list,
						     &cfg_type_netaddr };

static cfg_type_t cfg_type_bracketed_sockaddrtlslist = {
	"bracketed_sockaddrtlslist",
	cfg_parse_bracketed_list,
	cfg_print_bracketed_list,
	cfg_doc_bracketed_list,
	&cfg_rep_list,
	&cfg_type_sockaddrtls
};

static const char *dnssecupdatemode_enums[] = { "maintain", "no-resign", NULL };
static cfg_type_t cfg_type_dnssecupdatemode = {
	"dnssecupdatemode", cfg_parse_enum,  cfg_print_ustring,
	cfg_doc_enum,	    &cfg_rep_string, &dnssecupdatemode_enums
};

static const char *updatemethods_enums[] = { "date", "increment", "unixtime",
					     NULL };
static cfg_type_t cfg_type_updatemethod = {
	"updatemethod", cfg_parse_enum,	 cfg_print_ustring,
	cfg_doc_enum,	&cfg_rep_string, &updatemethods_enums
};

/*
 * zone-statistics: full, terse, or none.
 *
 * for backward compatibility, we also support boolean values.
 * yes represents "full", no represents "terse". in the future we
 * may change no to mean "none".
 */
static const char *zonestat_enums[] = { "full", "terse", "none", NULL };
static isc_result_t
parse_zonestat(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_zonestat(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_zonestat = { "zonestat",	   parse_zonestat,
					cfg_print_ustring, doc_zonestat,
					&cfg_rep_string,   zonestat_enums };

static cfg_type_t cfg_type_rrsetorder = { "rrsetorder",
					  cfg_parse_bracketed_list,
					  cfg_print_bracketed_list,
					  cfg_doc_bracketed_list,
					  &cfg_rep_list,
					  &cfg_type_rrsetorderingelement };

static keyword_type_t port_kw = { "port", &cfg_type_uint32 };

static cfg_type_t cfg_type_optional_port = {
	"optional_port",       parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_uint32,		&port_kw
};

/*% A list of keys, as in the "key" clause of the controls statement. */
static cfg_type_t cfg_type_keylist = { "keylist",
				       cfg_parse_bracketed_list,
				       cfg_print_bracketed_list,
				       cfg_doc_bracketed_list,
				       &cfg_rep_list,
				       &cfg_type_astring };

/*%
 * A list of managed trust anchors.  Each entry contains a name, a keyword
 * ("static-key", initial-key", "static-ds" or "initial-ds"), and the
 * fields associated with either a DNSKEY or a DS record.
 */
static cfg_type_t cfg_type_dnsseckeys = { "dnsseckeys",
					  cfg_parse_bracketed_list,
					  cfg_print_bracketed_list,
					  cfg_doc_bracketed_list,
					  &cfg_rep_list,
					  &cfg_type_managedkey };

cfg_type_t cfg_type_builtin_dnsseckeys = {
	"builtin-dnsseckeys", cfg_parse_bracketed_list, NULL, NULL,
	&cfg_rep_list,	      &cfg_type_managedkey
};

/*%
 * A list of key entries, used in a DNSSEC Key and Signing Policy.
 */
static cfg_type_t cfg_type_kaspkeys = { "kaspkeys",
					cfg_parse_bracketed_list,
					cfg_print_bracketed_list,
					cfg_doc_bracketed_list,
					&cfg_rep_list,
					&cfg_type_kaspkey };

static const char *forwardtype_enums[] = { "first", "only", NULL };
static cfg_type_t cfg_type_forwardtype = {
	"forwardtype", cfg_parse_enum,	cfg_print_ustring,
	cfg_doc_enum,  &cfg_rep_string, &forwardtype_enums
};

static const char *zonetype_enums[] = { "primary", "master",   "secondary",
					"slave",   "mirror",   "forward",
					"hint",	   "redirect", "static-stub",
					"stub",	   NULL };
static cfg_type_t cfg_type_zonetype = { "zonetype",	   cfg_parse_enum,
					cfg_print_ustring, cfg_doc_enum,
					&cfg_rep_string,   &zonetype_enums };

static const char *loglevel_enums[] = { "critical", "error", "warning",
					"notice",   "info",  "dynamic",
					NULL };
static cfg_type_t cfg_type_loglevel = { "loglevel",	   cfg_parse_enum,
					cfg_print_ustring, cfg_doc_enum,
					&cfg_rep_string,   &loglevel_enums };

static const char *transferformat_enums[] = { "many-answers", "one-answer",
					      NULL };
static cfg_type_t cfg_type_transferformat = {
	"transferformat", cfg_parse_enum,  cfg_print_ustring,
	cfg_doc_enum,	  &cfg_rep_string, &transferformat_enums
};

/*%
 * The special keyword "none", as used in the pid-file option.
 */

static void
print_none(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	UNUSED(obj);
	cfg_print_cstr(pctx, "none");
}

static cfg_type_t cfg_type_none = { "none", NULL,	   print_none,
				    NULL,   &cfg_rep_void, NULL };

/*%
 * A quoted string or the special keyword "none".  Used in the pid-file option.
 */
static isc_result_t
parse_qstringornone(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret) {
	isc_result_t result;

	CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "none") == 0)
	{
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_none, ret);
		return ISC_R_SUCCESS;
	}
	cfg_ungettoken(pctx);
	return cfg_parse_qstring(pctx, type, ret);
cleanup:
	return result;
}

static void
doc_qstringornone(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( <quoted_string> | none )");
}

static cfg_type_t cfg_type_qstringornone = { "qstringornone",
					     parse_qstringornone,
					     NULL,
					     doc_qstringornone,
					     NULL,
					     NULL };

/*%
 * A boolean ("yes" or "no"), or the special keyword "auto".
 * Used in the dnssec-validation option.
 */
static void
print_auto(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	UNUSED(obj);
	cfg_print_cstr(pctx, "auto");
}

static cfg_type_t cfg_type_auto = { "auto", NULL,	   print_auto,
				    NULL,   &cfg_rep_void, NULL };

static isc_result_t
parse_boolorauto(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;

	CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "auto") == 0)
	{
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_auto, ret);
		return ISC_R_SUCCESS;
	}
	cfg_ungettoken(pctx);
	return cfg_parse_boolean(pctx, type, ret);
cleanup:
	return result;
}

static void
print_boolorauto(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	if (obj->type->rep == &cfg_rep_void) {
		cfg_print_cstr(pctx, "auto");
	} else if (obj->value.boolean) {
		cfg_print_cstr(pctx, "yes");
	} else {
		cfg_print_cstr(pctx, "no");
	}
}

static void
doc_boolorauto(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( yes | no | auto )");
}

static cfg_type_t cfg_type_boolorauto = {
	"boolorauto", parse_boolorauto, print_boolorauto, doc_boolorauto, NULL,
	NULL
};

/*%
 * keyword hostname
 */
static void
print_hostname(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	UNUSED(obj);
	cfg_print_cstr(pctx, "hostname");
}

static cfg_type_t cfg_type_hostname = { "hostname",	  NULL,
					print_hostname,	  NULL,
					&cfg_rep_boolean, NULL };

/*%
 * "server-id" argument.
 */

static isc_result_t
parse_serverid(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	CHECK(cfg_gettoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "none") == 0)
	{
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_none, ret);
		return ISC_R_SUCCESS;
	}
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "hostname") == 0)
	{
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_hostname, ret);
		(*ret)->value.boolean = true;
		return ISC_R_SUCCESS;
	}
	cfg_ungettoken(pctx);
	return cfg_parse_qstring(pctx, type, ret);
cleanup:
	return result;
}

static void
doc_serverid(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( <quoted_string> | none | hostname )");
}

static cfg_type_t cfg_type_serverid = { "serverid",   parse_serverid, NULL,
					doc_serverid, NULL,	      NULL };

static const char *cookiealg_enums[] = { "siphash24", NULL };
static cfg_type_t cfg_type_cookiealg = { "cookiealg",	    cfg_parse_enum,
					 cfg_print_ustring, cfg_doc_enum,
					 &cfg_rep_string,   &cookiealg_enums };

/*%
 * fetch-quota-params
 */

static cfg_tuplefielddef_t fetchquota_fields[] = {
	{ "frequency", &cfg_type_uint32, 0 },
	{ "low", &cfg_type_fixedpoint, 0 },
	{ "high", &cfg_type_fixedpoint, 0 },
	{ "discount", &cfg_type_fixedpoint, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_fetchquota = { "fetchquota",	   cfg_parse_tuple,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  fetchquota_fields };

/*%
 * fetches-per-server or fetches-per-zone
 */

static const char *response_enums[] = { "drop", "fail", NULL };

static cfg_type_t cfg_type_responsetype = {
	"responsetype",	   parse_optional_enum, cfg_print_ustring,
	doc_optional_enum, &cfg_rep_string,	response_enums
};

static cfg_tuplefielddef_t fetchesper_fields[] = {
	{ "fetches", &cfg_type_uint32, 0 },
	{ "response", &cfg_type_responsetype, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_fetchesper = { "fetchesper",	   cfg_parse_tuple,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  fetchesper_fields };

static void
map_merge(const cfg_obj_t *config ISC_ATTR_UNUSED, cfg_obj_t *effectivemap,
	  const cfg_obj_t *defaultmap) {
	const void *clauses = NULL;
	const cfg_clausedef_t *clause = NULL;
	unsigned int i = 0;

	for (clause = cfg_map_firstclause(effectivemap->type, &clauses, &i);
	     clause != NULL;
	     clause = cfg_map_nextclause(effectivemap->type, &clauses, &i))
	{
		isc_result_t defaultres;
		isc_result_t effectiveres;
		cfg_obj_t *effectiveobj = NULL;
		const cfg_obj_t *defaultobj = NULL;

		defaultres = cfg_map_get(defaultmap, clause->name, &defaultobj);
		INSIST(defaultres == ISC_R_NOTFOUND ||
		       defaultres == ISC_R_SUCCESS);

		effectiveres = cfg_map_get(effectivemap, clause->name,
					   (const cfg_obj_t **)&effectiveobj);
		INSIST(effectiveres == ISC_R_NOTFOUND ||
		       effectiveres == ISC_R_SUCCESS);

		/*
		 * If the clause has a specific case, let's delegate to its
		 * merge callback
		 */
		if (effectiveobj != NULL && defaultobj != NULL &&
		    clause->merge != NULL)
		{
			clause->merge(effectivemap, effectiveobj, defaultobj);
			continue;
		}

		/*
		 * If the clause is defined in the default but not in the user
		 * config, let's clone it inside the user config
		 */
		if (effectiveres == ISC_R_NOTFOUND &&
		    defaultres == ISC_R_SUCCESS)
		{
			INSIST(cfg_map_addclone(effectivemap, defaultobj,
						clause) == ISC_R_SUCCESS);
			continue;
		}

		/*
		 * Otherwise, the clause is defined in user, so the default (if
		 * it exists) is ignored
		 */
	}
}

/*
 * "dnssec-policy" has CFG_CLAUSEFLAG_MULTI, but unlike most such
 * clauses, the entries in the user configuration are appended to the
 * default configuration instead of overriding the list.
 */
static void
policy_merge(const cfg_obj_t *config ISC_ATTR_UNUSED, cfg_obj_t *eff,
	     const cfg_obj_t *def) {
	cfg_list_addclone(eff, def, true);
}

static void
cloneto(cfg_obj_t *options, const cfg_obj_t *obj, enum cfg_clause clausename) {
	isc_result_t result;
	const cfg_clausedef_t *clause = cfg_map_findclause(options->type,
							   clausename);

	result = cfg_map_addclone(options, obj, clause);
	INSIST(result == ISC_R_SUCCESS);
}

static void
setdefaultacl(cfg_obj_t *options, const cfg_obj_t *defaultoptions,
	      enum cfg_clause aclname) {
	const cfg_obj_t *obj = NULL;
	isc_result_t result;

	result = cfg_map_get(options, aclname, &obj);
	if (result == ISC_R_SUCCESS) {
		return;
	}

	obj = NULL;
	result = cfg_map_get(defaultoptions, aclname, &obj);
	INSIST(result == ISC_R_SUCCESS);

	cloneto(options, obj, aclname);
}

static const cfg_obj_t *
aclobj(const cfg_obj_t *o, const cfg_obj_t *v, enum cfg_clause name) {
	const cfg_obj_t *obj = NULL;

	cfg_map_get(v, name, &obj);
	if (obj == NULL) {
		cfg_map_get(o, name, &obj);
	}
	return obj;
}

static void
setacls(const cfg_obj_t *config, cfg_obj_t *voptions,
	const cfg_obj_t *defaultoptions) {
	const cfg_obj_t *options = NULL;
	const cfg_obj_t *query = NULL, *cache = NULL, *cacheon = NULL;
	const cfg_obj_t *recursion = NULL, *recursionon = NULL;

	cfg_map_get(config, CFG_CLAUSE_OPTIONS, &options);
	INSIST(options != NULL);

	/*
	 * This can be called in two different contexts: from the top-level
	 * option clause, or from the user-defined views.
	 */
	INSIST((options == voptions && defaultoptions != NULL) ||
	       (options != voptions && defaultoptions == NULL));

	query = aclobj(options, voptions, CFG_CLAUSE_ALLOW_QUERY);
	recursion = aclobj(options, voptions, CFG_CLAUSE_ALLOW_RECURSION);
	cache = aclobj(options, voptions, CFG_CLAUSE_ALLOW_QUERY_CACHE);

	cacheon = aclobj(options, voptions, CFG_CLAUSE_ALLOW_QUERY_CACHE_ON);
	recursionon = aclobj(options, voptions, CFG_CLAUSE_ALLOW_RECURSION_ON);

	bool aq = query != NULL && !query->cloned;
	bool aqc = cache != NULL && !cache->cloned;
	bool ar = recursion != NULL && !recursion->cloned;

	bool aqco = cacheon != NULL && !cacheon->cloned;
	bool aro = recursionon != NULL && !recursionon->cloned;

	/*
	 * "allow-query-cache" inherits from "allow-recursion" if set,
	 * otherwise from "allow-query" if set.
	 */
	if (!aqc) {
		if (ar) {
			cloneto(voptions, recursion,
				CFG_CLAUSE_ALLOW_QUERY_CACHE);
		} else if (aq) {
			cloneto(voptions, query, CFG_CLAUSE_ALLOW_QUERY_CACHE);
		}
	}

	/*
	 * "allow-recursion" inherits from "allow-query-cache" if set,
	 * otherwise from "allow-query" if set.
	 */
	if (!ar) {
		if (aqc) {
			cloneto(voptions, cache, CFG_CLAUSE_ALLOW_RECURSION);
		} else if (aq) {
			cloneto(voptions, query, CFG_CLAUSE_ALLOW_RECURSION);
		}
	}

	/*
	 * "allow-query-cache-on" inherits from "allow-recursion-on"
	 * if set, and vice versa.
	 */
	if (!aqco && aro) {
		cloneto(voptions, recursionon, CFG_CLAUSE_ALLOW_QUERY_CACHE_ON);
	} else if (!aro && aqco) {
		cloneto(voptions, cacheon, CFG_CLAUSE_ALLOW_RECURSION_ON);
	}

	if (options == voptions) {
		/*
		 * This is the top-level options clause. This clause gets copies
		 * of the default ACL if they are not defined. Those will be
		 * used for user views ACLs too.
		 */
		setdefaultacl(voptions, defaultoptions,
			      CFG_CLAUSE_ALLOW_QUERY_CACHE);
		setdefaultacl(voptions, defaultoptions,
			      CFG_CLAUSE_ALLOW_RECURSION);
		setdefaultacl(voptions, defaultoptions,
			      CFG_CLAUSE_ALLOW_QUERY_CACHE_ON);
		setdefaultacl(voptions, defaultoptions,
			      CFG_CLAUSE_ALLOW_RECURSION_ON);
	}
}

static void
options_merge(const cfg_obj_t *config, cfg_obj_t *effectiveoptions,
	      const cfg_obj_t *defaultoptions) {
	/*
	 * ACLs allow-query-cache, allow-recursion, allow-query-cache-on
	 * and allow-recursion-on need to be merged with the defaults
	 * carefully, because there are implicit dependency rules
	 * between them.
	 *
	 * Note: this is similar to the code in view_merge()
	 * below, but that's only called when views are explicitly
	 * configured in named.conf, so we need to do this at the
	 * options level too.
	 */
	setacls(config, effectiveoptions, defaultoptions);

	map_merge(config, effectiveoptions, defaultoptions);
}

/*
 * "view" has CFG_CLAUSEFLAG_MULTI, but unlike most such clauses, the
 * entries in the user configuration are *prepended* to the default
 * configuration instead of overriding the list.
 *
 * After all views have been cloned into the effective configuration,
 * we correct their ACL settings to take into account the mutual iheritance
 * of allow-recursion, allow-query-cache, and allow-query.
 */
static void
view_merge(const cfg_obj_t *config, cfg_obj_t *eff, const cfg_obj_t *def) {
	REQUIRE(cfg_obj_islist(eff));
	REQUIRE(cfg_obj_islist(def));

	cfg_list_addclone(eff, def, false);
	CFG_LIST_FOREACH(eff, elt) {
		const cfg_obj_t *name = cfg_tuple_get(elt->obj, "name");
		cfg_obj_t *voptions = NULL;

		if (name != NULL &&
		    strcmp(cfg_obj_asstring(name), "_bind") == 0)
		{
			continue;
		}

		voptions = UNCONST(cfg_tuple_get(elt->obj, "options"));
		setacls(config, voptions, NULL);
	}
}

/*%
 * Clauses that can be found within the top level of the named.conf
 * file only.
 */
static cfg_clausedef_t namedconf_clauses[] = {
	{ CFG_CLAUSE_ACL, &cfg_type_acl, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_CONTROLS, &cfg_type_controls, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_DNSSEC_POLICY, &cfg_type_dnssecpolicy,
	  CFG_CLAUSEFLAG_MULTI, policy_merge },
#if HAVE_LIBNGHTTP2
	{ CFG_CLAUSE_HTTP, &cfg_type_http_description,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_OPTIONAL, NULL },
#else
	{ CFG_CLAUSE_HTTP, &cfg_type_http_description,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
#endif
	{ CFG_CLAUSE_KEY_STORE, &cfg_type_keystore, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_LOGGING, &cfg_type_logging, 0, NULL },
	{ CFG_CLAUSE_LWRES, NULL, CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_MASTERS, &cfg_type_serverlist,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC, NULL },
	{ CFG_CLAUSE_OPTIONS, &cfg_type_options, 0, options_merge },
	{ CFG_CLAUSE_PARENTAL_AGENTS, &cfg_type_serverlist,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC, NULL },
	{ CFG_CLAUSE_PRIMARIES, &cfg_type_serverlist,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC, NULL },
	{ CFG_CLAUSE_REMOTE_SERVERS, &cfg_type_serverlist, CFG_CLAUSEFLAG_MULTI,
	  NULL },
#if defined(HAVE_LIBXML2) || defined(HAVE_JSON_C)
	{ CFG_CLAUSE_STATISTICS_CHANNELS, &cfg_type_statschannels,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_OPTIONAL, NULL },
#else
	{ CFG_CLAUSE_STATISTICS_CHANNELS, &cfg_type_statschannels,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
#endif
	{ CFG_CLAUSE_TEMPLATE, &cfg_type_template, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_BUILTIN_TRUST_ANCHORS, &cfg_type_builtin_dnsseckeys,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_BUILTINONLY |
		  CFG_CLAUSEFLAG_NODOC,
	  NULL },
	{ CFG_CLAUSE_TLS, &cfg_type_tlsconf, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_VIEW, &cfg_type_view, CFG_CLAUSEFLAG_MULTI, view_merge },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*%
 * Clauses that can occur at the top level or in the view
 * statement, but not in the options block.
 */
static cfg_clausedef_t namedconf_or_view_clauses[] = {
	{ CFG_CLAUSE_DLZ, &cfg_type_dlz, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_DYNDB, &cfg_type_dyndb, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_KEY, &cfg_type_key, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_MANAGED_KEYS, &cfg_type_dnsseckeys,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_PLUGIN, &cfg_type_plugin, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_SERVER, &cfg_type_server, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_TRUST_ANCHORS, &cfg_type_dnsseckeys, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_TRUSTED_KEYS, NULL,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_ZONE, &cfg_type_zone,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_NODOC, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*%
 * Clauses that can occur in a trust anchor file (previously
 * called bind.keys).
 */
static cfg_clausedef_t bindkeys_clauses[] = {
	{ CFG_CLAUSE_MANAGED_KEYS, &cfg_type_dnsseckeys,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_TRUST_ANCHORS, &cfg_type_dnsseckeys, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_TRUSTED_KEYS, NULL,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static const char *fstrm_model_enums[] = { "mpsc", "spsc", NULL };
static cfg_type_t cfg_type_fstrm_model = {
	"model",      cfg_parse_enum,  cfg_print_ustring,
	cfg_doc_enum, &cfg_rep_string, &fstrm_model_enums
};

/*%
 * Clauses that can be found within the 'options' statement.
 */
static cfg_clausedef_t options_clauses[] = {
	{ CFG_CLAUSE_ANSWER_COOKIE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_AUTOMATIC_INTERFACE_SCAN, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_AVOID_V4_UDP_PORTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_AVOID_V6_UDP_PORTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_BINDKEYS_FILE, &cfg_type_qstring, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_BLACKHOLE, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_COOKIE_ALGORITHM, &cfg_type_cookiealg, 0, NULL },
	{ CFG_CLAUSE_COOKIE_SECRET, &cfg_type_sstring, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_CORESIZE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DATASIZE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DEALLOCATE_ON_EXIT, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DIRECTORY, &cfg_type_qstring, CFG_CLAUSEFLAG_CHDIR, NULL },
	{ CFG_CLAUSE_DNSRPS_LIBRARY, &cfg_type_qstring, CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
#ifdef HAVE_DNSTAP
	{ CFG_CLAUSE_DNSTAP_OUTPUT, &cfg_type_dnstapoutput,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_DNSTAP_IDENTITY, &cfg_type_serverid,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_DNSTAP_VERSION, &cfg_type_qstringornone,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
#else  /* ifdef HAVE_DNSTAP */
	{ CFG_CLAUSE_DNSTAP_OUTPUT, &cfg_type_dnstapoutput,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_DNSTAP_IDENTITY, &cfg_type_serverid,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_DNSTAP_VERSION, &cfg_type_qstringornone,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
#endif /* ifdef HAVE_DNSTAP */
	{ CFG_CLAUSE_DSCP, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DUMP_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_FAKE_IQUERY, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_FILES, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_FLUSH_ZONES_ON_SHUTDOWN, &cfg_type_boolean, 0, NULL },
#ifdef HAVE_DNSTAP
	{ CFG_CLAUSE_FSTRM_SET_BUFFER_HINT, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_FSTRM_SET_FLUSH_TIMEOUT, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_FSTRM_SET_INPUT_QUEUE_SIZE, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_FSTRM_SET_OUTPUT_NOTIFY_THRESHOLD, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_FSTRM_SET_OUTPUT_QUEUE_MODEL, &cfg_type_fstrm_model,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_FSTRM_SET_OUTPUT_QUEUE_SIZE, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_FSTRM_SET_REOPEN_INTERVAL, &cfg_type_duration,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
#else  /* ifdef HAVE_DNSTAP */
	{ CFG_CLAUSE_FSTRM_SET_BUFFER_HINT, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_FSTRM_SET_FLUSH_TIMEOUT, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_FSTRM_SET_INPUT_QUEUE_SIZE, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_FSTRM_SET_OUTPUT_NOTIFY_THRESHOLD, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_FSTRM_SET_OUTPUT_QUEUE_MODEL, &cfg_type_fstrm_model,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_FSTRM_SET_OUTPUT_QUEUE_SIZE, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_FSTRM_SET_REOPEN_INTERVAL, &cfg_type_duration,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
#endif /* HAVE_DNSTAP */
#if defined(HAVE_GEOIP2)
	{ CFG_CLAUSE_GEOIP_DIRECTORY, &cfg_type_qstringornone, 0, NULL },
#else  /* if defined(HAVE_GEOIP2) */
	{ CFG_CLAUSE_GEOIP_DIRECTORY, &cfg_type_qstringornone,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
#endif /* HAVE_GEOIP2 */
	{ CFG_CLAUSE_GEOIP_USE_ECS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_HAS_OLD_CLIENTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_HEARTBEAT_INTERVAL, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_HOST_STATISTICS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_HOST_STATISTICS_MAX, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_HOSTNAME, &cfg_type_qstringornone, 0, NULL },
	{ CFG_CLAUSE_INTERFACE_INTERVAL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_KEEP_RESPONSE_ORDER, &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_OBSOLETE, NULL },
	{ CFG_CLAUSE_LISTEN_ON, &cfg_type_listenon, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_LISTEN_ON_V6, &cfg_type_listenon, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_LOCK_FILE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_MANAGED_KEYS_DIRECTORY, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_MATCH_MAPPED_ADDRESSES, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_MAX_RSA_EXPONENT_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MEMSTATISTICS, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_MEMSTATISTICS_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_MULTIPLE_CNAMES, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_NAMED_XFER, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_NOTIFY_RATE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_PID_FILE, &cfg_type_qstringornone, 0, NULL },
	{ CFG_CLAUSE_PORT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TLS_PORT, &cfg_type_uint32, 0, NULL },
#if HAVE_LIBNGHTTP2
	{ CFG_CLAUSE_HTTP_PORT, &cfg_type_uint32, CFG_CLAUSEFLAG_OPTIONAL,
	  NULL },
	{ CFG_CLAUSE_HTTP_LISTENER_CLIENTS, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_HTTP_STREAMS_PER_CONNECTION, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_OPTIONAL, NULL },
	{ CFG_CLAUSE_HTTPS_PORT, &cfg_type_uint32, CFG_CLAUSEFLAG_OPTIONAL,
	  NULL },
#else
	{ CFG_CLAUSE_HTTP_PORT, &cfg_type_uint32, CFG_CLAUSEFLAG_NOTCONFIGURED,
	  NULL },
	{ CFG_CLAUSE_HTTP_LISTENER_CLIENTS, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_HTTP_STREAMS_PER_CONNECTION, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_NOTCONFIGURED, NULL },
	{ CFG_CLAUSE_HTTPS_PORT, &cfg_type_uint32, CFG_CLAUSEFLAG_NOTCONFIGURED,
	  NULL },
#endif
	{ CFG_CLAUSE_QUERYLOG, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_RANDOM_DEVICE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_RECURSING_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_RECURSIVE_CLIENTS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_REUSEPORT, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_RESERVED_SOCKETS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_RESPONSELOG, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_SECROOTS_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_SERIAL_QUERIES, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_SERIAL_QUERY_RATE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_SERVER_ID, &cfg_type_serverid, 0, NULL },
	{ CFG_CLAUSE_SESSION_KEYALG, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_SESSION_KEYFILE, &cfg_type_qstringornone, 0, NULL },
	{ CFG_CLAUSE_SESSION_KEYNAME, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_SIG0CHECKS_QUOTA, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_SIG0CHECKS_QUOTA_EXEMPT, &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_SIT_SECRET, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_STACKSIZE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_STARTUP_NOTIFY_RATE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_STATISTICS_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_STATISTICS_INTERVAL, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_TCP_ADVERTISED_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_CLIENTS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_IDLE_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_INITIAL_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_KEEPALIVE_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_LISTEN_QUEUE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_PRIMARIES_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_RECEIVE_BUFFER, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_REUSE_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TCP_SEND_BUFFER, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TKEY_DHKEY, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_TKEY_DOMAIN, &cfg_type_qstring, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_TKEY_GSSAPI_CREDENTIAL, &cfg_type_qstring,
	  CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_TKEY_GSSAPI_KEYTAB, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_TRANSFER_MESSAGE_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TRANSFERS_IN, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TRANSFERS_OUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TRANSFERS_PER_NS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_TREAT_CR_AS_SPACE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_UDP_RECEIVE_BUFFER, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_UDP_SEND_BUFFER, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_UPDATE_QUOTA, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_USE_ID_POOL, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_USE_IXFR, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_USE_V4_UDP_PORTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_USE_V6_UDP_PORTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_VERSION, &cfg_type_qstringornone, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_type_t cfg_type_namelist = { "namelist",
					cfg_parse_bracketed_list,
					cfg_print_bracketed_list,
					cfg_doc_bracketed_list,
					&cfg_rep_list,
					&cfg_type_astring };

static keyword_type_t exceptionnames_kw = { "except-from", &cfg_type_namelist };

static cfg_type_t cfg_type_optional_exceptionnames = {
	"optional_allow",      parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_list,		&exceptionnames_kw
};

static cfg_tuplefielddef_t denyaddresses_fields[] = {
	{ "acl", &cfg_type_bracketed_aml, 0 },
	{ "except-from", &cfg_type_optional_exceptionnames, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_denyaddresses = {
	"denyaddresses", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	 &cfg_rep_tuple,  denyaddresses_fields
};

static cfg_tuplefielddef_t denyaliases_fields[] = {
	{ "name", &cfg_type_namelist, 0 },
	{ "except-from", &cfg_type_optional_exceptionnames, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_denyaliases = {
	"denyaliases", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple, &cfg_rep_tuple,	denyaliases_fields
};

static cfg_type_t cfg_type_algorithmlist = { "algorithmlist",
					     cfg_parse_bracketed_list,
					     cfg_print_bracketed_list,
					     cfg_doc_bracketed_list,
					     &cfg_rep_list,
					     &cfg_type_astring };

static cfg_tuplefielddef_t disablealgorithm_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "algorithms", &cfg_type_algorithmlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_disablealgorithm = {
	"disablealgorithm", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	    &cfg_rep_tuple,  disablealgorithm_fields
};

static cfg_type_t cfg_type_dsdigestlist = { "dsdigestlist",
					    cfg_parse_bracketed_list,
					    cfg_print_bracketed_list,
					    cfg_doc_bracketed_list,
					    &cfg_rep_list,
					    &cfg_type_astring };

static cfg_tuplefielddef_t disabledsdigest_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "digests", &cfg_type_dsdigestlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_disabledsdigest = {
	"disabledsdigest", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	   &cfg_rep_tuple,  disabledsdigest_fields
};

static const char *masterformat_enums[] = { "raw", "text", NULL };
static cfg_type_t cfg_type_masterformat = {
	"masterformat", cfg_parse_enum,	 cfg_print_ustring,
	cfg_doc_enum,	&cfg_rep_string, &masterformat_enums
};

static const char *masterstyle_enums[] = { "full", "relative", NULL };
static cfg_type_t cfg_type_masterstyle = {
	"masterstyle", cfg_parse_enum,	cfg_print_ustring,
	cfg_doc_enum,  &cfg_rep_string, &masterstyle_enums
};

static keyword_type_t blocksize_kw = { "block-size", &cfg_type_uint32 };

static cfg_type_t cfg_type_blocksize = { "blocksize",	  parse_keyvalue,
					 print_keyvalue,  doc_keyvalue,
					 &cfg_rep_uint32, &blocksize_kw };

static cfg_tuplefielddef_t resppadding_fields[] = {
	{ "acl", &cfg_type_bracketed_aml, 0 },
	{ "block-size", &cfg_type_blocksize, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_resppadding = {
	"resppadding", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple, &cfg_rep_tuple,	resppadding_fields
};

/*%
 *  dnstap {
 *      &lt;message type&gt; [query | response] ;
 *      ...
 *  }
 *
 *  ... where message type is one of: client, resolver, auth, forwarder,
 *                                    update, all
 */
static const char *dnstap_types[] = { "all",	   "auth",     "client",
				      "forwarder", "resolver", "update",
				      NULL };

static const char *dnstap_modes[] = { "query", "response", NULL };

static cfg_type_t cfg_type_dnstap_type = { "dnstap_type",     cfg_parse_enum,
					   cfg_print_ustring, cfg_doc_enum,
					   &cfg_rep_string,   dnstap_types };

static cfg_type_t cfg_type_dnstap_mode = {
	"dnstap_mode",	   parse_optional_enum, cfg_print_ustring,
	doc_optional_enum, &cfg_rep_string,	dnstap_modes
};

static cfg_tuplefielddef_t dnstap_fields[] = {
	{ "type", &cfg_type_dnstap_type, 0 },
	{ "mode", &cfg_type_dnstap_mode, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_dnstap_entry = { "dnstap_value",  cfg_parse_tuple,
					    cfg_print_tuple, cfg_doc_tuple,
					    &cfg_rep_tuple,  dnstap_fields };

static cfg_type_t cfg_type_dnstap = { "dnstap",
				      cfg_parse_bracketed_list,
				      cfg_print_bracketed_list,
				      cfg_doc_bracketed_list,
				      &cfg_rep_list,
				      &cfg_type_dnstap_entry };

/*%
 * dnstap-output
 */
static isc_result_t
parse_dtout(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const cfg_tuplefielddef_t *fields = type->of;

	cfg_tuple_create(pctx, type, &obj);

	/* Parse the mandatory "mode" and "path" fields */
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));
	CHECK(cfg_parse_obj(pctx, fields[1].type, &obj->value.tuple[1]));

	/* Parse "versions" and "size" fields in any order. */
	for (;;) {
		CHECK(cfg_peektoken(pctx, 0));
		if (pctx->token.type == isc_tokentype_string) {
			CHECK(cfg_gettoken(pctx, 0));
			if (strcasecmp(TOKEN_STRING(pctx), "size") == 0 &&
			    obj->value.tuple[2] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[2].type,
						    &obj->value.tuple[2]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "versions") ==
					   0 &&
				   obj->value.tuple[3] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[3].type,
						    &obj->value.tuple[3]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "suffix") ==
					   0 &&
				   obj->value.tuple[4] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[4].type,
						    &obj->value.tuple[4]));
			} else {
				cfg_parser_error(pctx, CFG_LOG_NEAR,
						 "unexpected token");
				CLEANUP(ISC_R_UNEXPECTEDTOKEN);
			}
		} else {
			break;
		}
	}

	/* Create void objects for missing optional values. */
	if (obj->value.tuple[2] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[2]));
	}
	if (obj->value.tuple[3] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[3]));
	}
	if (obj->value.tuple[4] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[4]));
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static void
print_dtout(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	cfg_print_obj(pctx, obj->value.tuple[0]); /* mode */
	cfg_print_obj(pctx, obj->value.tuple[1]); /* file */
	if (obj->value.tuple[2]->type->print != cfg_print_void) {
		cfg_print_cstr(pctx, " size ");
		cfg_print_obj(pctx, obj->value.tuple[2]);
	}
	if (obj->value.tuple[3]->type->print != cfg_print_void) {
		cfg_print_cstr(pctx, " versions ");
		cfg_print_obj(pctx, obj->value.tuple[3]);
	}
	if (obj->value.tuple[4]->type->print != cfg_print_void) {
		cfg_print_cstr(pctx, " suffix ");
		cfg_print_obj(pctx, obj->value.tuple[4]);
	}
}

static void
doc_dtout(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( file | unix ) <quoted_string>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ size ( unlimited | <size> ) ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ versions ( unlimited | <integer> ) ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ suffix ( increment | timestamp ) ]");
}

static const char *dtoutmode_enums[] = { "file", "unix", NULL };
static cfg_type_t cfg_type_dtmode = { "dtmode",		 cfg_parse_enum,
				      cfg_print_ustring, cfg_doc_enum,
				      &cfg_rep_string,	 &dtoutmode_enums };

static cfg_tuplefielddef_t dtout_fields[] = {
	{ "mode", &cfg_type_dtmode, 0 },
	{ "path", &cfg_type_qstring, 0 },
	{ "size", &cfg_type_sizenodefault, 0 },
	{ "versions", &cfg_type_logversions, 0 },
	{ "suffix", &cfg_type_logsuffix, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_dnstapoutput = { "dnstapoutput", parse_dtout,
					    print_dtout,    doc_dtout,
					    &cfg_rep_tuple, dtout_fields };

/*%
 *  response-policy {
 *	zone &lt;string&gt; [ policy (given|disabled|passthru|drop|tcp-only|
 *					nxdomain|nodata|cname &lt;domain&gt; ) ]
 *		      [ recursive-only yes|no ] [ log yes|no ]
 *		      [ max-policy-ttl number ]
 *		      [ nsip-enable yes|no ] [ nsdname-enable yes|no ];
 *  } [ recursive-only yes|no ] [ max-policy-ttl number ]
 *	 [ min-update-interval number ]
 *	 [ break-dnssec yes|no ] [ min-ns-dots number ]
 *	 [ qname-wait-recurse yes|no ] [ servfail-until-ready yes|no ]
 *	 [ nsip-enable yes|no ] [ nsdname-enable yes|no ]
 */

static void
doc_rpz_policy(cfg_printer_t *pctx, const cfg_type_t *type) {
	const char *const *p;
	/*
	 * This is cfg_doc_enum() without the trailing " )".
	 */
	cfg_print_cstr(pctx, "( ");
	for (p = type->of; *p != NULL; p++) {
		cfg_print_cstr(pctx, *p);
		if (p[1] != NULL) {
			cfg_print_cstr(pctx, " | ");
		}
	}
}

static void
doc_rpz_cname(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_terminal(pctx, type);
	cfg_print_cstr(pctx, " )");
}

/*
 * Parse
 *	given|disabled|passthru|drop|tcp-only|nxdomain|nodata|cname <domain>
 */
static isc_result_t
cfg_parse_rpz_policy(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const cfg_tuplefielddef_t *fields;

	cfg_tuple_create(pctx, type, &obj);

	fields = type->of;
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));
	/*
	 * parse cname domain only after "policy cname"
	 */
	if (strcasecmp("cname", cfg_obj_asstring(obj->value.tuple[0])) != 0) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[1]));
	} else {
		CHECK(cfg_parse_obj(pctx, fields[1].type,
				    &obj->value.tuple[1]));
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

/*
 * Parse a tuple consisting of any kind of required field followed
 * by 2 or more optional keyvalues that can be in any order.
 */
static isc_result_t
cfg_parse_kv_tuple(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	const cfg_tuplefielddef_t *fields, *f;
	cfg_obj_t *obj = NULL;
	int fn;
	isc_result_t result;

	cfg_tuple_create(pctx, type, &obj);

	/*
	 * The zone first field is required and always first.
	 */
	fields = type->of;
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));

	for (;;) {
		CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
		if (pctx->token.type != isc_tokentype_string) {
			break;
		}

		for (fn = 1, f = &fields[1];; ++fn, ++f) {
			if (f->name == NULL) {
				cfg_parser_error(pctx, 0, "unexpected '%s'",
						 TOKEN_STRING(pctx));
				CLEANUP(ISC_R_UNEXPECTEDTOKEN);
			}
			if (obj->value.tuple[fn] == NULL &&
			    strcasecmp(f->name, TOKEN_STRING(pctx)) == 0)
			{
				break;
			}
		}

		CHECK(cfg_gettoken(pctx, 0));
		CHECK(cfg_parse_obj(pctx, f->type, &obj->value.tuple[fn]));
	}

	for (fn = 1, f = &fields[1]; f->name != NULL; ++fn, ++f) {
		if (obj->value.tuple[fn] == NULL) {
			CHECK(cfg_parse_void(pctx, NULL,
					     &obj->value.tuple[fn]));
		}
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static void
cfg_print_kv_tuple(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	unsigned int i;
	const cfg_tuplefielddef_t *fields, *f;
	const cfg_obj_t *fieldobj;

	fields = obj->type->of;
	for (f = fields, i = 0; f->name != NULL; f++, i++) {
		fieldobj = obj->value.tuple[i];
		if (fieldobj->type->print == cfg_print_void) {
			continue;
		}
		if (i != 0) {
			cfg_print_cstr(pctx, " ");
			cfg_print_cstr(pctx, f->name);
			cfg_print_cstr(pctx, " ");
		}
		cfg_print_obj(pctx, fieldobj);
	}
}

static void
cfg_doc_kv_tuple(cfg_printer_t *pctx, const cfg_type_t *type) {
	const cfg_tuplefielddef_t *fields, *f;

	fields = type->of;
	for (f = fields; f->name != NULL; f++) {
		if ((f->flags & CFG_CLAUSEFLAG_NODOC) != 0) {
			continue;
		}
		if (f != fields) {
			cfg_print_cstr(pctx, " [ ");
			cfg_print_cstr(pctx, f->name);
			if (f->type->doc != cfg_doc_void) {
				cfg_print_cstr(pctx, " ");
			}
		}
		cfg_doc_obj(pctx, f->type);
		if (f != fields) {
			cfg_print_cstr(pctx, " ]");
		}
	}
}

static keyword_type_t zone_kw = { "zone", &cfg_type_astring };
static cfg_type_t cfg_type_rpz_zone = { "zone",		 parse_keyvalue,
					print_keyvalue,	 doc_keyvalue,
					&cfg_rep_string, &zone_kw };
/*
 * "no-op" is an obsolete equivalent of "passthru".
 */
static const char *rpz_policies[] = { "cname",	  "disabled", "drop",
				      "given",	  "no-op",    "nodata",
				      "nxdomain", "passthru", "tcp-only",
				      NULL };
static cfg_type_t cfg_type_rpz_policy_name = {
	"policy name",	cfg_parse_enum,	 cfg_print_ustring,
	doc_rpz_policy, &cfg_rep_string, &rpz_policies
};
static cfg_type_t cfg_type_rpz_cname = {
	"quoted_string", cfg_parse_astring, NULL,
	doc_rpz_cname,	 &cfg_rep_string,   NULL
};
static cfg_tuplefielddef_t rpz_policy_fields[] = {
	{ "policy name", &cfg_type_rpz_policy_name, 0 },
	{ "cname", &cfg_type_rpz_cname, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rpz_policy = { "policy tuple",  cfg_parse_rpz_policy,
					  cfg_print_tuple, cfg_doc_tuple,
					  &cfg_rep_tuple,  rpz_policy_fields };
static cfg_tuplefielddef_t rpz_zone_fields[] = {
	{ "zone name", &cfg_type_rpz_zone, 0 },
	{ "add-soa", &cfg_type_boolean, 0 },
	{ "log", &cfg_type_boolean, 0 },
	{ "max-policy-ttl", &cfg_type_duration, 0 },
	{ "min-update-interval", &cfg_type_duration, 0 },
	{ "policy", &cfg_type_rpz_policy, 0 },
	{ "recursive-only", &cfg_type_boolean, 0 },
	{ "nsip-enable", &cfg_type_boolean, 0 },
	{ "nsdname-enable", &cfg_type_boolean, 0 },
	{ "ede", &cfg_type_ustring, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rpz_tuple = { "rpz tuple",	     cfg_parse_kv_tuple,
					 cfg_print_kv_tuple, cfg_doc_kv_tuple,
					 &cfg_rep_tuple,     rpz_zone_fields };
static cfg_type_t cfg_type_rpz_list = { "zone list",
					cfg_parse_bracketed_list,
					cfg_print_bracketed_list,
					cfg_doc_bracketed_list,
					&cfg_rep_list,
					&cfg_type_rpz_tuple };
static cfg_tuplefielddef_t rpz_fields[] = {
	{ "zone list", &cfg_type_rpz_list, 0 },
	{ "add-soa", &cfg_type_boolean, 0 },
	{ "break-dnssec", &cfg_type_boolean, 0 },
	{ "max-policy-ttl", &cfg_type_duration, 0 },
	{ "min-update-interval", &cfg_type_duration, 0 },
	{ "min-ns-dots", &cfg_type_uint32, 0 },
	{ "nsip-wait-recurse", &cfg_type_boolean, 0 },
	{ "nsdname-wait-recurse", &cfg_type_boolean, 0 },
	{ "qname-wait-recurse", &cfg_type_boolean, 0 },
	{ "recursive-only", &cfg_type_boolean, 0 },
	{ "servfail-until-ready", &cfg_type_boolean, 0 },
	{ "nsip-enable", &cfg_type_boolean, 0 },
	{ "nsdname-enable", &cfg_type_boolean, 0 },
	{ "dnsrps-enable", &cfg_type_boolean, CFG_CLAUSEFLAG_OBSOLETE },
	{ "dnsrps-options", &cfg_type_bracketed_tokens,
	  CFG_CLAUSEFLAG_OBSOLETE },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_rpz = { "rpz",
				   cfg_parse_kv_tuple,
				   cfg_print_kv_tuple,
				   cfg_doc_kv_tuple,
				   &cfg_rep_tuple,
				   rpz_fields };

/*
 * Catalog zones
 */
static cfg_type_t cfg_type_catz_zone = { "zone",	  parse_keyvalue,
					 print_keyvalue,  doc_keyvalue,
					 &cfg_rep_string, &zone_kw };

static cfg_tuplefielddef_t catz_zone_fields[] = {
	{ "zone name", &cfg_type_catz_zone, 0 },
	{ "default-masters", &cfg_type_namesockaddrkeylist,
	  CFG_CLAUSEFLAG_NODOC },
	{ "default-primaries", &cfg_type_namesockaddrkeylist, 0 },
	{ "zone-directory", &cfg_type_qstring, 0 },
	{ "in-memory", &cfg_type_boolean, 0 },
	{ "min-update-interval", &cfg_type_duration, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_catz_tuple = {
	"catz tuple",	  cfg_parse_kv_tuple, cfg_print_kv_tuple,
	cfg_doc_kv_tuple, &cfg_rep_tuple,     catz_zone_fields
};
static cfg_type_t cfg_type_catz_list = { "zone list",
					 cfg_parse_bracketed_list,
					 cfg_print_bracketed_list,
					 cfg_doc_bracketed_list,
					 &cfg_rep_list,
					 &cfg_type_catz_tuple };
static cfg_tuplefielddef_t catz_fields[] = {
	{ "zone list", &cfg_type_catz_list, 0 }, { NULL, NULL, 0 }
};
static cfg_type_t cfg_type_catz = {
	"catz",		  cfg_parse_kv_tuple, cfg_print_kv_tuple,
	cfg_doc_kv_tuple, &cfg_rep_tuple,     catz_fields
};

/*
 * rate-limit
 */
static cfg_clausedef_t rrl_clauses[] = {
	{ CFG_CLAUSE_ALL_PER_SECOND, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_ERRORS_PER_SECOND, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_EXEMPT_CLIENTS, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_IPV4_PREFIX_LENGTH, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_IPV6_PREFIX_LENGTH, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_LOG_ONLY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_MAX_TABLE_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MIN_TABLE_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_NODATA_PER_SECOND, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_NXDOMAINS_PER_SECOND, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_QPS_SCALE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_REFERRALS_PER_SECOND, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_RESPONSES_PER_SECOND, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_SLIP, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_WINDOW, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *rrl_clausesets[] = { rrl_clauses, NULL };

static cfg_type_t cfg_type_rrl = { "rate-limit", cfg_parse_map, cfg_print_map,
				   cfg_doc_map,	 &cfg_rep_map,	rrl_clausesets };

static isc_result_t
parse_optional_uint32(cfg_parser_t *pctx, const cfg_type_t *type,
		      cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, ISC_LEXOPT_NUMBER | ISC_LEXOPT_CNUMBER));
	if (pctx->token.type == isc_tokentype_number) {
		CHECK(cfg_parse_obj(pctx, &cfg_type_uint32, ret));
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_void, ret));
	}
cleanup:
	return result;
}

static void
doc_optional_uint32(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ <integer> ]");
}

static cfg_type_t cfg_type_optional_uint32 = { "optional_uint32",
					       parse_optional_uint32,
					       NULL,
					       doc_optional_uint32,
					       NULL,
					       NULL };

static cfg_tuplefielddef_t prefetch_fields[] = {
	{ "trigger", &cfg_type_uint32, 0 },
	{ "eligible", &cfg_type_optional_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_prefetch = { "prefetch",	 cfg_parse_tuple,
					cfg_print_tuple, cfg_doc_tuple,
					&cfg_rep_tuple,	 prefetch_fields };
/*
 * DNS64.
 */
static cfg_clausedef_t dns64_clauses[] = {
	{ CFG_CLAUSE_BREAK_DNSSEC, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_CLIENTS, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_EXCLUDE, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_MAPPED, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_RECURSIVE_ONLY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_SUFFIX, &cfg_type_netaddr6, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL },
};

static cfg_clausedef_t *dns64_clausesets[] = { dns64_clauses, NULL };

static cfg_type_t cfg_type_dns64 = { "dns64",	    cfg_parse_netprefix_map,
				     cfg_print_map, cfg_doc_map,
				     &cfg_rep_map,  dns64_clausesets };

static const char *staleanswerclienttimeout_enums[] = { "disabled", "off",
							NULL };
static isc_result_t
parse_staleanswerclienttimeout(cfg_parser_t *pctx, const cfg_type_t *type,
			       cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_uint32, ret);
}

static void
doc_staleanswerclienttimeout(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_uint32);
}

static cfg_type_t cfg_type_staleanswerclienttimeout = {
	"staleanswerclienttimeout",
	parse_staleanswerclienttimeout,
	cfg_print_ustring,
	doc_staleanswerclienttimeout,
	&cfg_rep_string,
	staleanswerclienttimeout_enums
};

static void
prefetch_merge(const cfg_obj_t *config ISC_ATTR_UNUSED, cfg_obj_t *effectiveobj,
	       const cfg_obj_t *defaultobj) {
	cfg_obj_t *trigger = NULL;
	cfg_obj_t *eligible = NULL;

	trigger = (cfg_obj_t *)cfg_tuple_get(effectiveobj, "trigger");
	INSIST(cfg_obj_isuint32(trigger));

	eligible = (cfg_obj_t *)cfg_tuple_get(effectiveobj, "eligible");
	if (cfg_obj_isvoid(eligible)) {
		const cfg_obj_t *defaulteligible = NULL;

		defaulteligible = cfg_tuple_get(defaultobj, "eligible");
		INSIST(cfg_obj_isuint32(defaulteligible));

		eligible->value.uint32 = cfg_obj_asuint32(defaulteligible);
		eligible->type = &cfg_type_uint32;
	}

	INSIST(cfg_obj_isuint32(eligible));
}

static void
checknames_merge(const cfg_obj_t *config ISC_ATTR_UNUSED,
		 cfg_obj_t *effectiveobj, const cfg_obj_t *defaultobj) {
	/*
	 * Applies only to the top-level option `check-names` statement.
	 * The view and zone-level versions aren't merged into the defaults
	 * the way global options are.
	 */
	REQUIRE(cfg_obj_islist(effectiveobj));
	REQUIRE(cfg_obj_islist(defaultobj));

	CFG_LIST_FOREACH(defaultobj, delt) {
		const cfg_obj_t *checkname = cfg_listelt_value(delt);
		const cfg_obj_t *type = cfg_tuple_get(checkname, "type");
		bool found = false;

		CFG_LIST_FOREACH(effectiveobj, eelt) {
			const cfg_obj_t *echeckname = cfg_listelt_value(eelt);
			const cfg_obj_t *etype = cfg_tuple_get(echeckname,
							       "type");

			if (strcasecmp(type->value.string,
				       etype->value.string) == 0)
			{
				found = true;
				break;
			}
		}

		if (found == false) {
			cfg_listelt_t *eelt = NULL;

			cfg_listelt_create(&eelt);
			*eelt = (cfg_listelt_t){ .link = ISC_LINK_INITIALIZER };
			cfg_obj_clone(checkname, &eelt->obj);
			ISC_LIST_APPEND(*effectiveobj->value.list, eelt, link);
		}
	}
}

/*%
 * Clauses that can be found within the 'view' statement,
 * with defaults in the 'options' statement.
 */

static cfg_clausedef_t view_clauses[] = {
	{ CFG_CLAUSE_ACACHE_CLEANING_INTERVAL, NULL, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_ACACHE_ENABLE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_ADDITIONAL_FROM_AUTH, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_ADDITIONAL_FROM_CACHE, NULL, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_ALLOW_NEW_ZONES, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_ALLOW_PROXY, &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_ALLOW_PROXY_ON, &cfg_type_bracketed_aml,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_ALLOW_QUERY_CACHE, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_ALLOW_QUERY_CACHE_ON, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_ALLOW_RECURSION, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_ALLOW_RECURSION_ON, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_ALLOW_V6_SYNTHESIS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_ATTACH_CACHE, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_AUTH_NXDOMAIN, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_CACHE_FILE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_CATALOG_ZONES, &cfg_type_catz, 0, NULL },
	{ CFG_CLAUSE_CHECK_NAMES, &cfg_type_checknames, CFG_CLAUSEFLAG_MULTI,
	  checknames_merge },
	{ CFG_CLAUSE_CHECK_NS, &cfg_type_checkmode, 0, NULL },
	{ CFG_CLAUSE_CLEANING_INTERVAL, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_CLIENTS_PER_QUERY, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_DENY_ANSWER_ADDRESSES, &cfg_type_denyaddresses, 0, NULL },
	{ CFG_CLAUSE_DENY_ANSWER_ALIASES, &cfg_type_denyaliases, 0, NULL },
	{ CFG_CLAUSE_DISABLE_ALGORITHMS, &cfg_type_disablealgorithm,
	  CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_DISABLE_DS_DIGESTS, &cfg_type_disabledsdigest,
	  CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_DISABLE_EMPTY_ZONE, &cfg_type_astring,
	  CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_DNS64, &cfg_type_dns64, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_DNS64_CONTACT, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_DNS64_SERVER, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_DNSRPS_ENABLE, &cfg_type_boolean, CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
	{ CFG_CLAUSE_DNSRPS_OPTIONS, &cfg_type_bracketed_tokens,
	  CFG_CLAUSEFLAG_OBSOLETE, NULL },
	{ CFG_CLAUSE_DNSSEC_ACCEPT_EXPIRED, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_DNSSEC_ENABLE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DNSSEC_LOOKASIDE, NULL,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DNSSEC_MUST_BE_SECURE, NULL,
	  CFG_CLAUSEFLAG_MULTI | CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_DNSSEC_VALIDATION, &cfg_type_boolorauto, 0, NULL },
#ifdef HAVE_DNSTAP
	{ CFG_CLAUSE_DNSTAP, &cfg_type_dnstap, CFG_CLAUSEFLAG_OPTIONAL, NULL },
#else  /* ifdef HAVE_DNSTAP */
	{ CFG_CLAUSE_DNSTAP, &cfg_type_dnstap, CFG_CLAUSEFLAG_NOTCONFIGURED,
	  NULL },
#endif /* HAVE_DNSTAP */
	{ CFG_CLAUSE_DUAL_STACK_SERVERS, &cfg_type_nameportiplist, 0, NULL },
	{ CFG_CLAUSE_EDNS_UDP_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_EMPTY_CONTACT, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_EMPTY_SERVER, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_EMPTY_ZONES_ENABLE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_FETCH_GLUE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_FETCH_QUOTA_PARAMS, &cfg_type_fetchquota, 0, NULL },
	{ CFG_CLAUSE_FETCHES_PER_SERVER, &cfg_type_fetchesper, 0, NULL },
	{ CFG_CLAUSE_FETCHES_PER_ZONE, &cfg_type_fetchesper, 0, NULL },
	{ CFG_CLAUSE_FILTER_AAAA, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_FILTER_AAAA_ON_V4, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_FILTER_AAAA_ON_V6, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_GLUE_CACHE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_IPV4ONLY_ENABLE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_IPV4ONLY_CONTACT, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_IPV4ONLY_SERVER, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_IXFR_FROM_DIFFERENCES, &cfg_type_ixfrdifftype, 0, NULL },
	{ CFG_CLAUSE_LAME_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_LMDB_MAPSIZE, &cfg_type_sizeval, CFG_CLAUSEFLAG_OPTIONAL,
	  NULL },
	{ CFG_CLAUSE_MAX_ACACHE_SIZE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_MAX_CACHE_SIZE, &cfg_type_maxcachesize, 0, NULL },
	{ CFG_CLAUSE_MAX_CACHE_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MAX_DELEGATION_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MAX_CLIENTS_PER_QUERY, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MAX_DELEGATION_SERVERS, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_MAX_NCACHE_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MAX_RECURSION_DEPTH, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MAX_RECURSION_QUERIES, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MAX_QUERY_COUNT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MAX_QUERY_RESTARTS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MAX_STALE_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MAX_UDP_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_MAX_VALIDATIONS_PER_FETCH, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_MAX_VALIDATION_FAILURES_PER_FETCH, &cfg_type_uint32,
	  CFG_CLAUSEFLAG_EXPERIMENTAL, NULL },
	{ CFG_CLAUSE_MESSAGE_COMPRESSION, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_MIN_CACHE_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MIN_DELEGATION_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MIN_NCACHE_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_MIN_ROOTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_MINIMAL_ANY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_MINIMAL_RESPONSES, &cfg_type_minimal, 0, NULL },
	{ CFG_CLAUSE_NEW_ZONES_DIRECTORY, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_NO_CASE_COMPRESS, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_NOCOOKIE_UDP_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_NOSIT_UDP_SIZE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_NTA_LIFETIME, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_NTA_RECHECK, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_NXDOMAIN_REDIRECT, &cfg_type_astring,
	  CFG_CLAUSEFLAG_DEPRECATED, NULL },
	{ CFG_CLAUSE_PREFERRED_GLUE, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_PREFETCH, &cfg_type_prefetch, 0, prefetch_merge },
	{ CFG_CLAUSE_PROVIDE_IXFR, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_QNAME_MINIMIZATION, &cfg_type_qminmethod, 0, NULL },
	/*
	 * Note that the query-source option syntax is different
	 * from the other -source options.
	 */
	{ CFG_CLAUSE_QUERY_SOURCE, &cfg_type_querysource4, 0, NULL },
	{ CFG_CLAUSE_QUERY_SOURCE_V6, &cfg_type_querysource6, 0, NULL },
	{ CFG_CLAUSE_QUERYPORT_POOL_PORTS, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_QUERYPORT_POOL_UPDATEINTERVAL, NULL,
	  CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_RATE_LIMIT, &cfg_type_rrl, 0, NULL },
	{ CFG_CLAUSE_RECURSION, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUEST_NSID, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUEST_SIT, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_REQUEST_ZONEVERSION, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUIRE_SERVER_COOKIE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_RESOLVER_NONBACKOFF_TRIES, NULL, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_RESOLVER_QUERY_TIMEOUT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_RESOLVER_RETRY_INTERVAL, NULL, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_RESPONSE_PADDING, &cfg_type_resppadding, 0, NULL },
	{ CFG_CLAUSE_RESPONSE_POLICY, &cfg_type_rpz, 0, NULL },
	{ CFG_CLAUSE_RFC2308_TYPE1, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_ROOT_DELEGATION_ONLY, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_ROOT_KEY_SENTINEL, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_RRSET_ORDER, &cfg_type_rrsetorder, 0, NULL },
	{ CFG_CLAUSE_SEND_COOKIE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_SERVFAIL_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_SIG0KEY_CHECKS_LIMIT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_SIG0MESSAGE_CHECKS_LIMIT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_SORTLIST, &cfg_type_bracketed_aml, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_STALE_ANSWER_ENABLE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_STALE_ANSWER_CLIENT_TIMEOUT,
	  &cfg_type_staleanswerclienttimeout, 0, NULL },
	{ CFG_CLAUSE_STALE_ANSWER_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_STALE_CACHE_ENABLE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_STALE_REFRESH_TIME, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_SUPPRESS_INITIAL_NOTIFY, NULL, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_SYNTH_FROM_DNSSEC, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_TOPOLOGY, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_TRANSFER_FORMAT, &cfg_type_transferformat, 0, NULL },
	{ CFG_CLAUSE_TRUST_ANCHOR_TELEMETRY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_RESOLVER_USE_DNS64, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_USE_QUERYPORT_POOL, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_VALIDATE_EXCEPT, &cfg_type_namelist, 0, NULL },
	{ CFG_CLAUSE_V6_BIAS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_ZERO_NO_SOA_TTL_CACHE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*%
 * Clauses that can be found within the 'view' statement only.
 */
static cfg_clausedef_t view_only_clauses[] = {
	{ CFG_CLAUSE_MATCH_CLIENTS, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_MATCH_DESTINATIONS, &cfg_type_bracketed_aml, 0, NULL },
	{ CFG_CLAUSE_MATCH_RECURSIVE_ONLY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*%
 * Sig-validity-interval.
 */

static cfg_tuplefielddef_t validityinterval_fields[] = {
	{ "validity", &cfg_type_uint32, 0 },
	{ "re-sign", &cfg_type_optional_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_validityinterval = {
	"validityinterval", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	    &cfg_rep_tuple,  validityinterval_fields
};

/*%
 * Checkds type.
 */
static const char *checkds_enums[] = { "explicit", NULL };
static isc_result_t
parse_checkds_type(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_checkds_type(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_checkdstype = {
	"checkdstype",	  parse_checkds_type, cfg_print_ustring,
	doc_checkds_type, &cfg_rep_string,    checkds_enums,
};

/*%
 * Clauses that can be found in a 'dnssec-policy' statement.
 */
static cfg_clausedef_t dnssecpolicy_clauses[] = {
	{ CFG_CLAUSE_CDNSKEY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_CDS_DIGEST_TYPES, &cfg_type_algorithmlist, 0, NULL },
	{ CFG_CLAUSE_DNSKEY_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_INLINE_SIGNING, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_KEYS, &cfg_type_kaspkeys, 0, NULL },
	{ CFG_CLAUSE_MANUAL_MODE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_MAX_ZONE_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_NSEC3PARAM, &cfg_type_nsec3, 0, NULL },
	{ CFG_CLAUSE_OFFLINE_KSK, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_PARENT_DS_TTL, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_PARENT_PROPAGATION_DELAY, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_PARENT_REGISTRATION_DELAY, NULL, CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_PUBLISH_SAFETY, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_PURGE_KEYS, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_RETIRE_SAFETY, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_SIGNATURES_JITTER, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_SIGNATURES_REFRESH, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_SIGNATURES_VALIDITY, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_SIGNATURES_VALIDITY_DNSKEY, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE_ZONE_PROPAGATION_DELAY, &cfg_type_duration, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*
 * For min-transfer-rate-in.
 */
static cfg_tuplefielddef_t min_transfer_rate_fields[] = {
	{ "traffic_bytes", &cfg_type_uint32, 0 },
	{ "time_minutes", &cfg_type_uint32, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_min_transfer_rate_in = {
	"min-transfer-rate-in", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,		&cfg_rep_tuple,	 min_transfer_rate_fields
};

/*%
 * Clauses that can be found in a 'zone' statement,
 * with defaults in the 'view' or 'options' statement.
 *
 * Note: CFG_ZONE_* options indicate in which zone types this clause is
 * legal.
 */
/*
 * NOTE: To enable syntax which allows specifying port and protocol
 * within 'allow-*' clauses, replace 'cfg_type_bracketed_aml' with
 * 'cfg_type_transport_acl'.
 *
 * Example: allow-transfer port 853 protocol tls { ... };
 */
static cfg_clausedef_t zone_clauses[] = {
	{ CFG_CLAUSE_ALLOW_NOTIFY, &cfg_type_bracketed_aml,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_ALLOW_QUERY, &cfg_type_bracketed_aml,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT | CFG_ZONE_STATICSTUB,
	  NULL },
	{ CFG_CLAUSE_ALLOW_QUERY_ON, &cfg_type_bracketed_aml,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT | CFG_ZONE_STATICSTUB,
	  NULL },
	{ CFG_CLAUSE_ALLOW_TRANSFER, &cfg_type_transport_acl,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_ALLOW_UPDATE, &cfg_type_bracketed_aml, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE_ALLOW_UPDATE_FORWARDING, &cfg_type_bracketed_aml,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_ALSO_NOTIFY, &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_ALT_TRANSFER_SOURCE, NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_ALT_TRANSFER_SOURCE_V6, NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_AUTO_DNSSEC, NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_CHECK_DUP_RECORDS, &cfg_type_checkmode, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE_CHECK_INTEGRITY, &cfg_type_boolean, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE_CHECK_MX, &cfg_type_checkmode, CFG_ZONE_PRIMARY, NULL },
	{ CFG_CLAUSE_CHECK_MX_CNAME, &cfg_type_checkmode, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE_CHECK_SIBLING, &cfg_type_boolean, CFG_ZONE_PRIMARY, NULL },
	{ CFG_CLAUSE_CHECK_SPF, &cfg_type_warn, CFG_ZONE_PRIMARY, NULL },
	{ CFG_CLAUSE_CHECK_SRV_CNAME, &cfg_type_checkmode, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE_CHECK_SVCB, &cfg_type_boolean, CFG_ZONE_PRIMARY, NULL },
	{ CFG_CLAUSE_CHECK_WILDCARD, &cfg_type_boolean, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE_DIALUP, NULL,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_STUB |
		  CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_DNSSEC_DNSKEY_KSKONLY, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
	{ CFG_CLAUSE_DNSSEC_LOADKEYS_INTERVAL, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_DNSSEC_POLICY, &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_DNSSEC_SECURE_TO_INSECURE, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_CLAUSEFLAG_OBSOLETE, NULL },
	{ CFG_CLAUSE_DNSSEC_UPDATE_MODE, &cfg_type_dnssecupdatemode,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
	{ CFG_CLAUSE_FORWARD, &cfg_type_forwardtype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_STUB |
		  CFG_ZONE_STATICSTUB | CFG_ZONE_FORWARD,
	  NULL },
	{ CFG_CLAUSE_FORWARDERS, &cfg_type_portiplist,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_STUB |
		  CFG_ZONE_STATICSTUB | CFG_ZONE_FORWARD,
	  NULL },
	{ CFG_CLAUSE_KEY_DIRECTORY, &cfg_type_qstring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_MAINTAIN_IXFR_BASE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_MASTERFILE_FORMAT, &cfg_type_masterformat,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_MASTERFILE_STYLE, &cfg_type_masterstyle,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_MAX_IXFR_LOG_SIZE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_MAX_IXFR_RATIO, &cfg_type_ixfrratio,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_MAX_JOURNAL_SIZE, &cfg_type_size,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_MAX_RECORDS, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_MAX_RECORDS_PER_TYPE, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_MAX_TYPES_PER_NAME, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_MAX_REFRESH_TIME, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MAX_RETRY_TIME, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MIN_TRANSFER_RATE_IN, &cfg_type_min_transfer_rate_in,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MAX_TRANSFER_IDLE_IN, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MAX_TRANSFER_IDLE_OUT, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_MIRROR | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_MAX_TRANSFER_TIME_IN, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MAX_TRANSFER_TIME_OUT, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_MIRROR | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_MAX_ZONE_TTL, &cfg_type_maxduration,
	  CFG_ZONE_PRIMARY | CFG_ZONE_REDIRECT | CFG_CLAUSEFLAG_DEPRECATED,
	  NULL },
	{ CFG_CLAUSE_MIN_REFRESH_TIME, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MIN_RETRY_TIME, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_MULTI_MASTER, &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_NOTIFY, &cfg_type_notifytype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_NOTIFY_CFG, &cfg_type_notifycfg,
	  CFG_CLAUSEFLAG_MULTI | CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY |
		  CFG_ZONE_MIRROR,
	  NULL },
	{ CFG_CLAUSE_NOTIFY_DEFER, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_NOTIFY_DELAY, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_NOTIFY_SOURCE, &cfg_type_sockaddr4wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_NOTIFY_SOURCE_V6, &cfg_type_sockaddr6wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_NOTIFY_TO_SOA, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_NSEC3_TEST_ZONE, &cfg_type_boolean,
	  CFG_CLAUSEFLAG_TESTONLY | CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY,
	  NULL },
	{ CFG_CLAUSE_PARENTAL_SOURCE, &cfg_type_sockaddr4wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_PARENTAL_SOURCE_V6, &cfg_type_sockaddr6wild,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_PROVIDE_ZONEVERSION, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_SEND_REPORT_CHANNEL, &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_REQUEST_EXPIRE, &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_REQUEST_IXFR, &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_REQUEST_IXFR_MAX_DIFFS, &cfg_type_uint32,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_SERIAL_UPDATE_METHOD, &cfg_type_updatemethod,
	  CFG_ZONE_PRIMARY, NULL },
	{ CFG_CLAUSE_SIG_SIGNING_NODES, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_SIG_SIGNING_SIGNATURES, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_SIG_SIGNING_TYPE, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_SIG_VALIDITY_INTERVAL, &cfg_type_validityinterval,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
	{ CFG_CLAUSE_DNSKEY_SIG_VALIDITY, &cfg_type_uint32,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
	{ CFG_CLAUSE_TRANSFER_SOURCE, &cfg_type_sockaddr4wild,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_TRANSFER_SOURCE_V6, &cfg_type_sockaddr6wild,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB, NULL },
	{ CFG_CLAUSE_TRY_TCP_REFRESH, &cfg_type_boolean,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_UPDATE_CHECK_KSK, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_CLAUSEFLAG_OBSOLETE,
	  NULL },
	{ CFG_CLAUSE_USE_ALT_TRANSFER_SOURCE, NULL,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB |
		  CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_ZERO_NO_SOA_TTL, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_ZONE_STATISTICS, &cfg_type_zonestat,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*%
 * Clauses that can be found in a 'zone' statement only.
 *
 * Note: CFG_ZONE_* options indicate in which zone types this clause is
 * legal.
 */
static cfg_clausedef_t zone_only_clauses[] = {
	/*
	 * Note that the format of the check-names option is different between
	 * the zone options and the global/view options.  Ugh.
	 */
	{ CFG_CLAUSE_TYPE, &cfg_type_zonetype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_HINT |
		  CFG_ZONE_REDIRECT | CFG_ZONE_FORWARD,
	  NULL },
	{ CFG_CLAUSE_CHECK_NAMES, &cfg_type_checkmode,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_HINT | CFG_ZONE_STUB,
	  NULL },
	{ CFG_CLAUSE_CHECK_NS, &cfg_type_checkmode,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_HINT | CFG_ZONE_STUB,
	  NULL },
	{ CFG_CLAUSE_CHECKDS, &cfg_type_checkdstype,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_DATABASE, &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB,
	  NULL },
	{ CFG_CLAUSE_DELEGATION_ONLY, NULL,
	  CFG_ZONE_HINT | CFG_ZONE_STUB | CFG_ZONE_FORWARD |
		  CFG_CLAUSEFLAG_ANCIENT,
	  NULL },
	{ CFG_CLAUSE_DLZ, &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_REDIRECT, NULL },
	{ CFG_CLAUSE_FILE, &cfg_type_qstring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_HINT | CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_INITIAL_FILE, &cfg_type_qstring, CFG_ZONE_PRIMARY, NULL },
	{ CFG_CLAUSE_INLINE_SIGNING, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_IXFR_BASE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_IXFR_FROM_DIFFERENCES, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_IXFR_TMP_FILE, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_JOURNAL, &cfg_type_qstring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR, NULL },
	{ CFG_CLAUSE_LOG_REPORT_CHANNEL, &cfg_type_boolean,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_MASTERS, &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB |
		  CFG_ZONE_REDIRECT | CFG_CLAUSEFLAG_NODOC,
	  NULL },
	{ CFG_CLAUSE_PARENTAL_AGENTS, &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY, NULL },
	{ CFG_CLAUSE_PLUGIN, &cfg_type_plugin,
	  CFG_CLAUSEFLAG_MULTI | CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY |
		  CFG_ZONE_REDIRECT | CFG_ZONE_MIRROR,
	  NULL },
	{ CFG_CLAUSE_PRIMARIES, &cfg_type_namesockaddrkeylist,
	  CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR | CFG_ZONE_STUB |
		  CFG_ZONE_REDIRECT,
	  NULL },
	{ CFG_CLAUSE_PUBKEY, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_SERVER_ADDRESSES, &cfg_type_bracketed_netaddrlist,
	  CFG_ZONE_STATICSTUB, NULL },
	{ CFG_CLAUSE_SERVER_NAMES, &cfg_type_namelist, CFG_ZONE_STATICSTUB,
	  NULL },
	{ CFG_CLAUSE_UPDATE_POLICY, &cfg_type_updatepolicy, CFG_ZONE_PRIMARY,
	  NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t non_template_clauses[] = {
	{ CFG_CLAUSE_IN_VIEW, &cfg_type_astring, CFG_ZONE_INVIEW, NULL },
	{ CFG_CLAUSE_TEMPLATE, &cfg_type_astring,
	  CFG_ZONE_PRIMARY | CFG_ZONE_SECONDARY | CFG_ZONE_MIRROR |
		  CFG_ZONE_STUB | CFG_ZONE_STATICSTUB | CFG_ZONE_HINT |
		  CFG_ZONE_REDIRECT | CFG_ZONE_FORWARD,
	  NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

/*% The top-level named.conf syntax. */

static cfg_clausedef_t *namedconf_clausesets[] = { namedconf_clauses,
						   namedconf_or_view_clauses,
						   NULL };
cfg_type_t cfg_type_namedconf = { "namedconf",	     cfg_parse_mapbody,
				  cfg_print_mapbody, cfg_doc_mapbody,
				  &cfg_rep_map,	     namedconf_clausesets };

/*% The bind.keys syntax (trust-anchors). */
static cfg_clausedef_t *bindkeys_clausesets[] = { bindkeys_clauses, NULL };
cfg_type_t cfg_type_bindkeys = { "bindkeys",	    cfg_parse_mapbody,
				 cfg_print_mapbody, cfg_doc_mapbody,
				 &cfg_rep_map,	    bindkeys_clausesets };

/*% The "options" statement syntax. */

static cfg_clausedef_t *options_clausesets[] = { options_clauses, view_clauses,
						 zone_clauses, NULL };
static cfg_type_t cfg_type_options = { "options",     cfg_parse_map,
				       cfg_print_map, cfg_doc_map,
				       &cfg_rep_map,  options_clausesets };

/*% The "view" statement syntax. */

static cfg_clausedef_t *view_clausesets[] = { view_only_clauses,
					      namedconf_or_view_clauses,
					      view_clauses, zone_clauses,
					      NULL };

static cfg_type_t cfg_type_viewopts = { "view",	       cfg_parse_map,
					cfg_print_map, cfg_doc_map,
					&cfg_rep_map,  view_clausesets };

/*% The "zone" statement syntax. */

static cfg_clausedef_t *zone_clausesets[] = { non_template_clauses,
					      zone_only_clauses, zone_clauses,
					      NULL };
cfg_type_t cfg_type_zoneopts = { "zoneopts",  cfg_parse_map, cfg_print_map,
				 cfg_doc_map, &cfg_rep_map,  zone_clausesets };

/*%
 * The "template" statement syntax: any clause that "zone" can take,
 * except that zones can have a "template" option and templates cannot.
 */

static cfg_clausedef_t *template_clausesets[] = { zone_only_clauses,
						  zone_clauses, NULL };
static cfg_type_t cfg_type_templateopts = {
	"templateopts", cfg_parse_map, cfg_print_map,
	cfg_doc_map,	&cfg_rep_map,  template_clausesets
};

/*% The "dnssec-policy" statement syntax. */
static cfg_clausedef_t *dnssecpolicy_clausesets[] = { dnssecpolicy_clauses,
						      NULL };
cfg_type_t cfg_type_dnssecpolicyopts = {
	"dnssecpolicyopts", cfg_parse_map, cfg_print_map,
	cfg_doc_map,	    &cfg_rep_map,  dnssecpolicy_clausesets
};

/*% The "dynamically loadable zones" statement syntax. */

static cfg_clausedef_t dlz_clauses[] = {
	{ CFG_CLAUSE_DATABASE, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_SEARCH, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};
static cfg_clausedef_t *dlz_clausesets[] = { dlz_clauses, NULL };
static cfg_type_t cfg_type_dlz = { "dlz",	  cfg_parse_named_map,
				   cfg_print_map, cfg_doc_map,
				   &cfg_rep_map,  dlz_clausesets };

/*%
 * The "dyndb" statement syntax.
 */

static cfg_tuplefielddef_t dyndb_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "library", &cfg_type_qstring, 0 },
	{ "parameters", &cfg_type_bracketed_tokens, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_dyndb = { "dyndb",	      cfg_parse_tuple,
				     cfg_print_tuple, cfg_doc_tuple,
				     &cfg_rep_tuple,  dyndb_fields };

/*%
 * The "plugin" statement syntax.
 * Currently only one plugin type is supported: query.
 */

static const char *plugin_enums[] = { "query", NULL };
static cfg_type_t cfg_type_plugintype = { "plugintype",	     cfg_parse_enum,
					  cfg_print_ustring, cfg_doc_enum,
					  &cfg_rep_string,   plugin_enums };
static cfg_tuplefielddef_t plugin_fields[] = {
	{ "type", &cfg_type_plugintype, 0 },
	{ "library", &cfg_type_astring, 0 },
	{ "parameters", &cfg_type_optional_bracketed_tokens, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_plugin = { "plugin",	       cfg_parse_tuple,
				      cfg_print_tuple, cfg_doc_tuple,
				      &cfg_rep_tuple,  plugin_fields };

/*%
 * Clauses that can be found within the 'key' statement.
 */
static cfg_clausedef_t key_clauses[] = {
	{ CFG_CLAUSE_ALGORITHM, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_SECRET, &cfg_type_sstring, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *key_clausesets[] = { key_clauses, NULL };
static cfg_type_t cfg_type_key = { "key",	  cfg_parse_named_map,
				   cfg_print_map, cfg_doc_map,
				   &cfg_rep_map,  key_clausesets };

/*%
 * A key-store statement.
 */
static cfg_clausedef_t keystore_clauses[] = {
	{ CFG_CLAUSE_DIRECTORY, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_PKCS11_URI, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *keystore_clausesets[] = { keystore_clauses, NULL };
static cfg_type_t cfg_type_keystoreopts = {
	"keystoreopts", cfg_parse_map, cfg_print_map,
	cfg_doc_map,	&cfg_rep_map,  keystore_clausesets
};

static cfg_tuplefielddef_t keystore_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "options", &cfg_type_keystoreopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_keystore = { "key-store",	 cfg_parse_tuple,
					cfg_print_tuple, cfg_doc_tuple,
					&cfg_rep_tuple,	 keystore_fields };

/*%
 * Clauses that can be found in a 'server' statement.
 *
 * Please update lib/isccfg/check.c and
 * bin/tests/system/checkconf/good-server-christmas-tree.conf.in to
 * exercise the new clause when adding new clauses.
 */
static cfg_clausedef_t server_clauses[] = {
	{ CFG_CLAUSE_BOGUS, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_EDNS, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_EDNS_UDP_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_EDNS_VERSION, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_KEYS, &cfg_type_server_key_kludge, 0, NULL },
	{ CFG_CLAUSE_MAX_UDP_SIZE, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_NOTIFY_SOURCE, &cfg_type_sockaddr4wild, 0, NULL },
	{ CFG_CLAUSE_NOTIFY_SOURCE_V6, &cfg_type_sockaddr6wild, 0, NULL },
	{ CFG_CLAUSE_PADDING, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_PROVIDE_IXFR, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_QUERY_SOURCE, &cfg_type_server_querysource4, 0, NULL },
	{ CFG_CLAUSE_QUERY_SOURCE_V6, &cfg_type_server_querysource6, 0, NULL },
	{ CFG_CLAUSE_REQUEST_EXPIRE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUEST_IXFR, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUEST_IXFR_MAX_DIFFS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_REQUEST_NSID, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUEST_ZONEVERSION, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_REQUEST_SIT, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_REQUIRE_COOKIE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_SEND_COOKIE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_SUPPORT_IXFR, NULL, CFG_CLAUSEFLAG_ANCIENT, NULL },
	{ CFG_CLAUSE_TCP_KEEPALIVE, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_TCP_ONLY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_TRANSFER_FORMAT, &cfg_type_transferformat, 0, NULL },
	{ CFG_CLAUSE_TRANSFER_SOURCE, &cfg_type_sockaddr4wild, 0, NULL },
	{ CFG_CLAUSE_TRANSFER_SOURCE_V6, &cfg_type_sockaddr6wild, 0, NULL },
	{ CFG_CLAUSE_TRANSFERS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};
static cfg_clausedef_t *server_clausesets[] = { server_clauses, NULL };
static cfg_type_t cfg_type_server = { "server",	     cfg_parse_netprefix_map,
				      cfg_print_map, cfg_doc_map,
				      &cfg_rep_map,  server_clausesets };

/*%
 * Clauses that can be found in a 'channel' clause in the
 * 'logging' statement.
 *
 * These have some additional constraints that need to be
 * checked after parsing:
 *  - There must exactly one of file/syslog/null/stderr
 */

static const char *printtime_enums[] = { "iso8601", "iso8601-utc",
					 "iso8601-tzinfo", "local", NULL };
static isc_result_t
parse_printtime(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_printtime(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_printtime = { "printtime",	    parse_printtime,
					 cfg_print_ustring, doc_printtime,
					 &cfg_rep_string,   printtime_enums };

static cfg_clausedef_t channel_clauses[] = {
	/* Destinations.  We no longer require these to be first. */
	{ CFG_CLAUSE_FILE, &cfg_type_logfile, 0, NULL },
	{ CFG_CLAUSE_SYSLOG, &cfg_type_optional_facility, 0, NULL },
	{ CFG_CLAUSE_NULL, &cfg_type_void, 0, NULL },
	{ CFG_CLAUSE_STDERR, &cfg_type_void, 0, NULL },
	/* Options.  We now accept these for the null channel, too. */
	{ CFG_CLAUSE_SEVERITY, &cfg_type_logseverity, 0, NULL },
	{ CFG_CLAUSE_PRINT_TIME, &cfg_type_printtime, 0, NULL },
	{ CFG_CLAUSE_PRINT_SEVERITY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_PRINT_CATEGORY, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_BUFFERED, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};
static cfg_clausedef_t *channel_clausesets[] = { channel_clauses, NULL };
static cfg_type_t cfg_type_channel = { "channel",     cfg_parse_named_map,
				       cfg_print_map, cfg_doc_map,
				       &cfg_rep_map,  channel_clausesets };

/*% A list of log destination, used in the "category" clause. */
static cfg_type_t cfg_type_destinationlist = { "destinationlist",
					       cfg_parse_bracketed_list,
					       cfg_print_bracketed_list,
					       cfg_doc_bracketed_list,
					       &cfg_rep_list,
					       &cfg_type_astring };

/*%
 * Clauses that can be found in a 'logging' statement.
 */
static cfg_clausedef_t logging_clauses[] = {
	{ CFG_CLAUSE_CHANNEL, &cfg_type_channel, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_CATEGORY, &cfg_type_category, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};
static cfg_clausedef_t *logging_clausesets[] = { logging_clauses, NULL };
static cfg_type_t cfg_type_logging = { "logging",     cfg_parse_map,
				       cfg_print_map, cfg_doc_map,
				       &cfg_rep_map,  logging_clausesets };

/*%
 * For parsing an 'addzone' statement
 */
static cfg_tuplefielddef_t addzone_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "class", &cfg_type_optional_class, 0 },
	{ "view", &cfg_type_optional_class, 0 },
	{ "options", &cfg_type_zoneopts, 0 },
	{ NULL, NULL, 0 }
};
static cfg_type_t cfg_type_addzone = { "zone",		cfg_parse_tuple,
				       cfg_print_tuple, cfg_doc_tuple,
				       &cfg_rep_tuple,	addzone_fields };

static cfg_clausedef_t addzoneconf_clauses[] = {
	{ CFG_CLAUSE_ZONE, &cfg_type_addzone, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *addzoneconf_clausesets[] = { addzoneconf_clauses,
						     NULL };

cfg_type_t cfg_type_addzoneconf = { "addzoneconf",     cfg_parse_mapbody,
				    cfg_print_mapbody, cfg_doc_mapbody,
				    &cfg_rep_map,      addzoneconf_clausesets };

static isc_result_t
parse_unitstring(char *str, uint64_t *valuep) {
	char *endp;
	unsigned int len;
	uint64_t value;
	uint64_t unit;

	value = strtoull(str, &endp, 10);
	if (*endp == 0) {
		*valuep = value;
		return ISC_R_SUCCESS;
	}

	len = strlen(str);
	if (len < 2 || endp[1] != '\0') {
		return ISC_R_FAILURE;
	}

	switch (str[len - 1]) {
	case 'k':
	case 'K':
		unit = 1024;
		break;
	case 'm':
	case 'M':
		unit = 1024 * 1024;
		break;
	case 'g':
	case 'G':
		unit = 1024 * 1024 * 1024;
		break;
	default:
		return ISC_R_FAILURE;
	}
	if (value > ((uint64_t)UINT64_MAX / unit)) {
		return ISC_R_FAILURE;
	}
	*valuep = value * unit;
	return ISC_R_SUCCESS;
}

static isc_result_t
parse_sizeval(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	uint64_t val;

	UNUSED(type);

	CHECK(cfg_gettoken(pctx, 0));
	if (pctx->token.type != isc_tokentype_string) {
		CLEANUP(ISC_R_UNEXPECTEDTOKEN);
	}
	CHECK(parse_unitstring(TOKEN_STRING(pctx), &val));

	cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
		       &cfg_type_uint64, &obj);
	obj->value.uint64 = val;
	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	cfg_parser_error(pctx, CFG_LOG_NEAR,
			 "expected integer and optional unit");
	return result;
}

static isc_result_t
parse_sizeval_percent(cfg_parser_t *pctx, const cfg_type_t *type,
		      cfg_obj_t **ret) {
	char *endp;
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	uint64_t val;
	uint64_t percent;

	UNUSED(type);

	CHECK(cfg_gettoken(pctx, 0));
	if (pctx->token.type != isc_tokentype_string) {
		CLEANUP(ISC_R_UNEXPECTEDTOKEN);
	}

	percent = strtoull(TOKEN_STRING(pctx), &endp, 10);

	if (*endp == '%' && *(endp + 1) == 0) {
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_percentage, &obj);
		obj->value.uint32 = (uint32_t)percent;
		*ret = obj;
		return ISC_R_SUCCESS;
	} else {
		CHECK(parse_unitstring(TOKEN_STRING(pctx), &val));
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_uint64, &obj);
		obj->value.uint64 = val;
		*ret = obj;
		return ISC_R_SUCCESS;
	}

cleanup:
	cfg_parser_error(pctx, CFG_LOG_NEAR,
			 "expected integer and optional unit or percent");
	return result;
}

static void
doc_sizeval_percent(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);

	cfg_print_cstr(pctx, "( ");
	cfg_doc_terminal(pctx, &cfg_type_size);
	cfg_print_cstr(pctx, " | ");
	cfg_doc_terminal(pctx, &cfg_type_percentage);
	cfg_print_cstr(pctx, " )");
}

/*%
 * A size value (number + optional unit).
 */
static cfg_type_t cfg_type_sizeval = { "sizeval",	 parse_sizeval,
				       cfg_print_uint64, cfg_doc_terminal,
				       &cfg_rep_uint64,	 NULL };

/*%
 * A size, "unlimited", or "default".
 */

static isc_result_t
parse_size(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_sizeval, ret);
}

static void
doc_size(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_sizeval);
}

static const char *size_enums[] = { "default", "unlimited", NULL };
static cfg_type_t cfg_type_size = {
	"size",	  parse_size,	   cfg_print_ustring,
	doc_size, &cfg_rep_string, size_enums
};

/*%
 * A size or "unlimited", but not "default".
 */
static const char *sizenodefault_enums[] = { "unlimited", NULL };
static cfg_type_t cfg_type_sizenodefault = {
	"size_no_default", parse_size,	    cfg_print_ustring,
	doc_size,	   &cfg_rep_string, sizenodefault_enums
};

/*%
 * A size in absolute values or percents.
 */
static cfg_type_t cfg_type_sizeval_percent = {
	"sizeval_percent",   parse_sizeval_percent, cfg_print_ustring,
	doc_sizeval_percent, &cfg_rep_string,	    NULL
};

/*%
 * A size in absolute values or percents, or "unlimited", or "default"
 */

static isc_result_t
parse_maxcachesize(cfg_parser_t *pctx, const cfg_type_t *type,
		   cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_sizeval_percent,
				       ret);
}

static void
doc_maxcachesize(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( default | unlimited | ");
	cfg_doc_terminal(pctx, &cfg_type_sizeval);
	cfg_print_cstr(pctx, " | ");
	cfg_doc_terminal(pctx, &cfg_type_percentage);
	cfg_print_cstr(pctx, " )");
}

static const char *maxcachesize_enums[] = { "default", "unlimited", NULL };
static cfg_type_t cfg_type_maxcachesize = {
	"maxcachesize",	  parse_maxcachesize, cfg_print_ustring,
	doc_maxcachesize, &cfg_rep_string,    maxcachesize_enums
};

/*%
 * An IXFR size ratio: percentage, or "unlimited".
 */

static isc_result_t
parse_ixfrratio(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_percentage, ret);
}

static void
doc_ixfrratio(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( unlimited | ");
	cfg_doc_terminal(pctx, &cfg_type_percentage);
	cfg_print_cstr(pctx, " )");
}

static const char *ixfrratio_enums[] = { "unlimited", NULL };
static cfg_type_t cfg_type_ixfrratio = { "ixfr_ratio", parse_ixfrratio,
					 NULL,	       doc_ixfrratio,
					 NULL,	       ixfrratio_enums };

/*%
 * optional_keyvalue
 */
static isc_result_t
parse_maybe_optional_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type,
			      bool optional, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const keyword_type_t *kw = type->of;

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), kw->name) == 0)
	{
		CHECK(cfg_gettoken(pctx, 0));
		CHECK(kw->type->parse(pctx, kw->type, &obj));
		obj->type = type; /* XXX kludge */
	} else {
		if (optional) {
			CHECK(cfg_parse_void(pctx, NULL, &obj));
		} else {
			cfg_parser_error(pctx, CFG_LOG_NEAR, "expected '%s'",
					 kw->name);
			CLEANUP(ISC_R_UNEXPECTEDTOKEN);
		}
	}

	*ret = obj;
cleanup:
	return result;
}

static isc_result_t
parse_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return parse_maybe_optional_keyvalue(pctx, type, false, ret);
}

static isc_result_t
parse_optional_keyvalue(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret) {
	return parse_maybe_optional_keyvalue(pctx, type, true, ret);
}

static void
print_keyvalue(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	const keyword_type_t *kw = obj->type->of;
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	kw->type->print(pctx, obj);
}

static void
doc_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type) {
	const keyword_type_t *kw = type->of;
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	cfg_doc_obj(pctx, kw->type);
}

static void
doc_optional_keyvalue(cfg_printer_t *pctx, const cfg_type_t *type) {
	const keyword_type_t *kw = type->of;
	cfg_print_cstr(pctx, "[ ");
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	cfg_doc_obj(pctx, kw->type);
	cfg_print_cstr(pctx, " ]");
}

/*
 * NOTIFY.
 */
static const char *notify_enums[] = { "explicit", "master-only", "primary-only",
				      NULL };
static isc_result_t
parse_notify_type(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_notify_type(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_notifytype = {
	"notifytype",	 parse_notify_type, cfg_print_ustring,
	doc_notify_type, &cfg_rep_string,   notify_enums,
};

/*
 * Generalized DNS Notifications.
 */
static cfg_clausedef_t notify_clauses[] = {
	{ CFG_CLAUSE_NOTIFY, &cfg_type_boolean, 0, NULL }, /* this limits the
						     options for NOTIFY(SOA) */
	{ CFG_CLAUSE_NOTIFY_DEFER, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_NOTIFY_DELAY, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_NOTIFY_SOURCE, &cfg_type_sockaddr4wild, 0, NULL },
	{ CFG_CLAUSE_NOTIFY_SOURCE_V6, &cfg_type_sockaddr6wild, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL },
};

static cfg_clausedef_t *notify_clausesets[] = { notify_clauses, NULL };

static cfg_type_t cfg_type_notifycfg = { "notify-cfg",	cfg_parse_named_map,
					 cfg_print_map, cfg_doc_map,
					 &cfg_rep_map,	notify_clausesets };

static const char *minimal_enums[] = { "no-auth", "no-auth-recursive", NULL };
static isc_result_t
parse_minimal(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_minimal(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_minimal = {
	"minimal",   parse_minimal,   cfg_print_ustring,
	doc_minimal, &cfg_rep_string, minimal_enums,
};

static const char *ixfrdiff_enums[] = { "primary", "master", "secondary",
					"slave", NULL };
static isc_result_t
parse_ixfrdiff_type(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret);
}
static void
doc_ixfrdiff_type(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}
static cfg_type_t cfg_type_ixfrdifftype = {
	"ixfrdiff",	   parse_ixfrdiff_type, cfg_print_ustring,
	doc_ixfrdiff_type, &cfg_rep_string,	ixfrdiff_enums,
};

static keyword_type_t key_kw = { "key", &cfg_type_astring };

cfg_type_t cfg_type_keyref = { "keyref",     parse_keyvalue,  print_keyvalue,
			       doc_keyvalue, &cfg_rep_string, &key_kw };

static cfg_type_t cfg_type_optional_keyref = {
	"optional_keyref",     parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_string,		&key_kw
};

static const char *qminmethod_enums[] = { "strict", "relaxed", "disabled",
					  "off", NULL };

static cfg_type_t cfg_type_qminmethod = { "qminmethod",	     cfg_parse_enum,
					  cfg_print_ustring, cfg_doc_enum,
					  &cfg_rep_string,   qminmethod_enums };

/*%
 * A "controls" statement is represented as a map with the multivalued
 * "inet" and "unix" clauses.
 */

static keyword_type_t controls_allow_kw = { "allow", &cfg_type_bracketed_aml };

static cfg_type_t cfg_type_controls_allow = {
	"controls_allow", parse_keyvalue, print_keyvalue,
	doc_keyvalue,	  &cfg_rep_list,  &controls_allow_kw
};

static keyword_type_t controls_keys_kw = { "keys", &cfg_type_keylist };

static cfg_type_t cfg_type_controls_keys = {
	"controls_keys",       parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_list,		&controls_keys_kw
};

static keyword_type_t controls_readonly_kw = { "read-only", &cfg_type_boolean };

static cfg_type_t cfg_type_controls_readonly = {
	"controls_readonly",   parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_boolean,	&controls_readonly_kw
};

static cfg_tuplefielddef_t inetcontrol_fields[] = {
	{ "address", &cfg_type_controls_sockaddr, 0 },
	{ "allow", &cfg_type_controls_allow, 0 },
	{ "keys", &cfg_type_controls_keys, 0 },
	{ "read-only", &cfg_type_controls_readonly, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_inetcontrol = {
	"inetcontrol", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple, &cfg_rep_tuple,	inetcontrol_fields
};

static keyword_type_t controls_perm_kw = { "perm", &cfg_type_uint32 };

static cfg_type_t cfg_type_controls_perm = {
	"controls_perm", parse_keyvalue,  print_keyvalue,
	doc_keyvalue,	 &cfg_rep_uint32, &controls_perm_kw
};

static keyword_type_t controls_owner_kw = { "owner", &cfg_type_uint32 };

static cfg_type_t cfg_type_controls_owner = {
	"controls_owner", parse_keyvalue,  print_keyvalue,
	doc_keyvalue,	  &cfg_rep_uint32, &controls_owner_kw
};

static keyword_type_t controls_group_kw = { "group", &cfg_type_uint32 };

static cfg_type_t cfg_type_controls_group = {
	"controls_allow", parse_keyvalue,  print_keyvalue,
	doc_keyvalue,	  &cfg_rep_uint32, &controls_group_kw
};

static cfg_tuplefielddef_t unixcontrol_fields[] = {
	{ "path", &cfg_type_qstring, 0 },
	{ "perm", &cfg_type_controls_perm, 0 },
	{ "owner", &cfg_type_controls_owner, 0 },
	{ "group", &cfg_type_controls_group, 0 },
	{ "keys", &cfg_type_controls_keys, 0 },
	{ "read-only", &cfg_type_controls_readonly, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_unixcontrol = {
	"unixcontrol", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple, &cfg_rep_tuple,	unixcontrol_fields
};

static cfg_clausedef_t controls_clauses[] = {
	{ CFG_CLAUSE_INET, &cfg_type_inetcontrol, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_UNIX, &cfg_type_unixcontrol, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *controls_clausesets[] = { controls_clauses, NULL };
static cfg_type_t cfg_type_controls = { "controls",    cfg_parse_map,
					cfg_print_map, cfg_doc_map,
					&cfg_rep_map,  &controls_clausesets };

/*%
 * A "statistics-channels" statement is represented as a map with the
 * multivalued "inet" clauses.
 */
static void
doc_optional_bracketed_list(cfg_printer_t *pctx, const cfg_type_t *type) {
	const keyword_type_t *kw = type->of;
	cfg_print_cstr(pctx, "[ ");
	cfg_print_cstr(pctx, kw->name);
	cfg_print_cstr(pctx, " ");
	cfg_doc_obj(pctx, kw->type);
	cfg_print_cstr(pctx, " ]");
}

static cfg_type_t cfg_type_optional_allow = {
	"optional_allow", parse_optional_keyvalue,
	print_keyvalue,	  doc_optional_bracketed_list,
	&cfg_rep_list,	  &controls_allow_kw
};

static cfg_tuplefielddef_t statserver_fields[] = {
	{ "address", &cfg_type_controls_sockaddr, 0 }, /* reuse controls def */
	{ "allow", &cfg_type_optional_allow, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_statschannel = {
	"statschannel", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	&cfg_rep_tuple,	 statserver_fields
};

static cfg_clausedef_t statservers_clauses[] = {
	{ CFG_CLAUSE_INET, &cfg_type_statschannel, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *statservers_clausesets[] = { statservers_clauses,
						     NULL };

static cfg_type_t cfg_type_statschannels = {
	"statistics-channels", cfg_parse_map, cfg_print_map,
	cfg_doc_map,	       &cfg_rep_map,  &statservers_clausesets
};

/*%
 * An optional class, as used in view and zone statements.
 */
static isc_result_t
parse_optional_class(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);
	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string) {
		CHECK(cfg_parse_obj(pctx, &cfg_type_ustring, ret));
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_void, ret));
	}
cleanup:
	return result;
}

static void
doc_optional_class(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ <class> ]");
}

static cfg_type_t cfg_type_optional_class = { "optional_class",
					      parse_optional_class,
					      NULL,
					      doc_optional_class,
					      NULL,
					      NULL };

static isc_result_t
parse_querysource(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;

	REQUIRE(type != NULL);
	CHECK(cfg_peektoken(pctx, 0));

	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "address") == 0)
	{
		CHECK(cfg_gettoken(pctx, 0));
		CHECK(cfg_peektoken(pctx, 0));
	}

	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "none") == 0)
	{
		CHECK(cfg_gettoken(pctx, 0));
		cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
			       &cfg_type_none, ret);
	} else {
		CHECK(cfg_parse_sockaddr_generic(pctx, &cfg_type_querysource,
						 type, ret));
	}

cleanup:
	if (result != ISC_R_SUCCESS) {
		cfg_parser_error(pctx, CFG_LOG_NEAR, "invalid query source");
	}

	return result;
}

static void
print_querysource(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	isc_netaddr_t na;
	isc_netaddr_fromsockaddr(&na, obj->value.sockaddr);
	cfg_print_rawaddr(pctx, &na);
}

static void
doc__querysource(cfg_printer_t *pctx, const cfg_type_t *type, bool has_none) {
	const unsigned int *flagp = type->of;

	cfg_print_cstr(pctx, "[ address ] ( ");

	if ((*flagp & CFG_ADDR_V4OK) != 0) {
		cfg_print_cstr(pctx, "<ipv4_address>");
	} else if ((*flagp & CFG_ADDR_V6OK) != 0) {
		cfg_print_cstr(pctx, "<ipv6_address>");
	} else {
		UNREACHABLE();
	}

	cfg_print_cstr(pctx, " | *");
	if (has_none) {
		cfg_print_cstr(pctx, " | none");
	}
	cfg_print_cstr(pctx, " )");
}

static void
doc_querysource(cfg_printer_t *pctx, const cfg_type_t *type) {
	doc__querysource(pctx, type, true);
}

static void
doc_serverquerysource(cfg_printer_t *pctx, const cfg_type_t *type) {
	doc__querysource(pctx, type, false);
}

static unsigned int sockaddr4wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V4OK;
static unsigned int sockaddr6wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V6OK;

static unsigned int querysource4wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V4OK |
					     CFG_ADDR_TRAILINGOK;
static unsigned int querysource6wild_flags = CFG_ADDR_WILDOK | CFG_ADDR_V6OK |
					     CFG_ADDR_TRAILINGOK;

static cfg_type_t cfg_type_querysource4 = {
	"querysource4", parse_querysource,	NULL, doc_querysource,
	NULL,		&querysource4wild_flags
};

static cfg_type_t cfg_type_querysource6 = {
	"querysource6", parse_querysource,	NULL, doc_querysource,
	NULL,		&querysource6wild_flags
};

static cfg_type_t cfg_type_server_querysource4 = {
	"querysource4", parse_querysource,	NULL, doc_serverquerysource,
	NULL,		&querysource4wild_flags
};

static cfg_type_t cfg_type_server_querysource6 = {
	"querysource6", parse_querysource,	NULL, doc_serverquerysource,
	NULL,		&querysource6wild_flags
};

static cfg_type_t cfg_type_querysource = { "querysource",     NULL,
					   print_querysource, NULL,
					   &cfg_rep_sockaddr, NULL };

/*%
 * The socket address syntax in the "controls" statement is silly.
 * It allows both socket address families, but also allows "*",
 * which is gratuitously interpreted as the IPv4 wildcard address.
 */
static unsigned int controls_sockaddr_flags = CFG_ADDR_V4OK | CFG_ADDR_V6OK |
					      CFG_ADDR_WILDOK | CFG_ADDR_PORTOK;
static cfg_type_t cfg_type_controls_sockaddr = {
	"controls_sockaddr", cfg_parse_sockaddr, cfg_print_sockaddr,
	cfg_doc_sockaddr,    &cfg_rep_sockaddr,	 &controls_sockaddr_flags
};

/*%
 * Handle the special kludge syntax of the "keys" clause in the "server"
 * statement, which takes a single key with or without braces and semicolon.
 */
static isc_result_t
parse_server_key_kludge(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret) {
	isc_result_t result;
	bool braces = false;
	UNUSED(type);

	/* Allow opening brace. */
	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_special &&
	    pctx->token.value.as_char == '{')
	{
		CHECK(cfg_gettoken(pctx, 0));
		braces = true;
	}

	CHECK(cfg_parse_obj(pctx, &cfg_type_astring, ret));

	if (braces) {
		/* Skip semicolon if present. */
		CHECK(cfg_peektoken(pctx, 0));
		if (pctx->token.type == isc_tokentype_special &&
		    pctx->token.value.as_char == ';')
		{
			CHECK(cfg_gettoken(pctx, 0));
		}

		CHECK(cfg_parse_special(pctx, '}'));
	}
cleanup:
	return result;
}
static cfg_type_t cfg_type_server_key_kludge = {
	"server_key", parse_server_key_kludge, NULL, cfg_doc_terminal, NULL,
	NULL
};

/*%
 * An optional logging facility.
 */

static isc_result_t
parse_optional_facility(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string ||
	    pctx->token.type == isc_tokentype_qstring)
	{
		CHECK(cfg_parse_obj(pctx, &cfg_type_astring, ret));
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_void, ret));
	}
cleanup:
	return result;
}

static void
doc_optional_facility(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "[ <syslog_facility> ]");
}

static cfg_type_t cfg_type_optional_facility = { "optional_facility",
						 parse_optional_facility,
						 NULL,
						 doc_optional_facility,
						 NULL,
						 NULL };

/*%
 * A log severity.  Return as a string, except "debug N",
 * which is returned as a keyword object.
 */

static keyword_type_t debug_kw = { "debug", &cfg_type_uint32 };
static cfg_type_t cfg_type_debuglevel = { "debuglevel",	   parse_keyvalue,
					  print_keyvalue,  doc_keyvalue,
					  &cfg_rep_uint32, &debug_kw };

static isc_result_t
parse_logseverity(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, 0));
	if (pctx->token.type == isc_tokentype_string &&
	    strcasecmp(TOKEN_STRING(pctx), "debug") == 0)
	{
		CHECK(cfg_gettoken(pctx, 0)); /* read "debug" */
		CHECK(cfg_peektoken(pctx, ISC_LEXOPT_NUMBER));
		if (pctx->token.type == isc_tokentype_number) {
			CHECK(cfg_parse_uint32(pctx, NULL, ret));
		} else {
			/*
			 * The debug level is optional and defaults to 1.
			 * This makes little sense, but we support it for
			 * compatibility with BIND 8.
			 */
			cfg_obj_create(cfg_parser_currentfile(pctx), pctx->line,
				       &cfg_type_uint32, ret);
			(*ret)->value.uint32 = 1;
		}
		(*ret)->type = &cfg_type_debuglevel; /* XXX kludge */
	} else {
		CHECK(cfg_parse_obj(pctx, &cfg_type_loglevel, ret));
	}
cleanup:
	return result;
}

static cfg_type_t cfg_type_logseverity = { "log_severity", parse_logseverity,
					   NULL,	   cfg_doc_terminal,
					   NULL,	   NULL };

/*%
 * The "file" clause of the "channel" statement.
 * This is yet another special case.
 */

static const char *logversions_enums[] = { "unlimited", NULL };
static isc_result_t
parse_logversions(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return cfg_parse_enum_or_other(pctx, type, &cfg_type_uint32, ret);
}

static void
doc_logversions(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_uint32);
}

static cfg_type_t cfg_type_logversions = {
	"logversions",	 parse_logversions, cfg_print_ustring,
	doc_logversions, &cfg_rep_string,   logversions_enums
};

static const char *logsuffix_enums[] = { "increment", "timestamp", NULL };
static cfg_type_t cfg_type_logsuffix = { "logsuffix",	    cfg_parse_enum,
					 cfg_print_ustring, cfg_doc_enum,
					 &cfg_rep_string,   &logsuffix_enums };

static cfg_tuplefielddef_t logfile_fields[] = {
	{ "file", &cfg_type_qstring, 0 },
	{ "versions", &cfg_type_logversions, 0 },
	{ "size", &cfg_type_size, 0 },
	{ "suffix", &cfg_type_logsuffix, 0 },
	{ NULL, NULL, 0 }
};

static isc_result_t
parse_logfile(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	const cfg_tuplefielddef_t *fields = type->of;

	cfg_tuple_create(pctx, type, &obj);

	/* Parse the mandatory "file" field */
	CHECK(cfg_parse_obj(pctx, fields[0].type, &obj->value.tuple[0]));

	/* Parse "versions" and "size" fields in any order. */
	for (;;) {
		CHECK(cfg_peektoken(pctx, 0));
		if (pctx->token.type == isc_tokentype_string) {
			CHECK(cfg_gettoken(pctx, 0));
			if (strcasecmp(TOKEN_STRING(pctx), "versions") == 0 &&
			    obj->value.tuple[1] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[1].type,
						    &obj->value.tuple[1]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "size") ==
					   0 &&
				   obj->value.tuple[2] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[2].type,
						    &obj->value.tuple[2]));
			} else if (strcasecmp(TOKEN_STRING(pctx), "suffix") ==
					   0 &&
				   obj->value.tuple[3] == NULL)
			{
				CHECK(cfg_parse_obj(pctx, fields[3].type,
						    &obj->value.tuple[3]));
			} else {
				break;
			}
		} else {
			break;
		}
	}

	/* Create void objects for missing optional values. */
	if (obj->value.tuple[1] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[1]));
	}
	if (obj->value.tuple[2] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[2]));
	}
	if (obj->value.tuple[3] == NULL) {
		CHECK(cfg_parse_void(pctx, NULL, &obj->value.tuple[3]));
	}

	*ret = obj;
	return ISC_R_SUCCESS;

cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static void
print_logfile(cfg_printer_t *pctx, const cfg_obj_t *obj) {
	cfg_print_obj(pctx, obj->value.tuple[0]); /* file */
	if (obj->value.tuple[1]->type->print != cfg_print_void) {
		cfg_print_cstr(pctx, " versions ");
		cfg_print_obj(pctx, obj->value.tuple[1]);
	}
	if (obj->value.tuple[2]->type->print != cfg_print_void) {
		cfg_print_cstr(pctx, " size ");
		cfg_print_obj(pctx, obj->value.tuple[2]);
	}
	if (obj->value.tuple[3]->type->print != cfg_print_void) {
		cfg_print_cstr(pctx, " suffix ");
		cfg_print_obj(pctx, obj->value.tuple[3]);
	}
}

static void
doc_logfile(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "<quoted_string>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ versions ( unlimited | <integer> ) ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ size <size> ]");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ suffix ( increment | timestamp ) ]");
}

static cfg_type_t cfg_type_logfile = { "log_file",     parse_logfile,
				       print_logfile,  doc_logfile,
				       &cfg_rep_tuple, logfile_fields };

/*% An IPv4 address, "*" accepted as wildcard. */
static cfg_type_t cfg_type_sockaddr4wild = {
	"sockaddr4wild",  cfg_parse_sockaddr, cfg_print_sockaddr,
	cfg_doc_sockaddr, &cfg_rep_sockaddr,  &sockaddr4wild_flags
};

/*% An IPv6 address, "*" accepted as wildcard. */
static cfg_type_t cfg_type_sockaddr6wild = {
	"v6addrportwild", cfg_parse_sockaddr, cfg_print_sockaddr,
	cfg_doc_sockaddr, &cfg_rep_sockaddr,  &sockaddr6wild_flags
};

static keyword_type_t sourceaddr4_kw = { "source", &cfg_type_sockaddr4wild };

static cfg_type_t cfg_type_optional_sourceaddr4 = {
	"optional_sourceaddr4", parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue,	&cfg_rep_sockaddr,	 &sourceaddr4_kw
};

static keyword_type_t sourceaddr6_kw = { "source-v6", &cfg_type_sockaddr6wild };

static cfg_type_t cfg_type_optional_sourceaddr6 = {
	"optional_sourceaddr6", parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue,	&cfg_rep_sockaddr,	 &sourceaddr6_kw
};

/*%
 * rndc
 */

static cfg_clausedef_t rndcconf_options_clauses[] = {
	{ CFG_CLAUSE_DEFAULT_KEY, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_DEFAULT_PORT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_DEFAULT_SERVER, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_DEFAULT_SOURCE_ADDRESS, &cfg_type_netaddr4wild, 0, NULL },
	{ CFG_CLAUSE_DEFAULT_SOURCE_ADDRESS_V6, &cfg_type_netaddr6wild, 0,
	  NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *rndcconf_options_clausesets[] = {
	rndcconf_options_clauses, NULL
};

static cfg_type_t cfg_type_rndcconf_options = {
	"rndcconf_options", cfg_parse_map, cfg_print_map,
	cfg_doc_map,	    &cfg_rep_map,  rndcconf_options_clausesets
};

static cfg_clausedef_t rndcconf_server_clauses[] = {
	{ CFG_CLAUSE_KEY, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_PORT, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_SOURCE_ADDRESS, &cfg_type_netaddr4wild, 0, NULL },
	{ CFG_CLAUSE_SOURCE_ADDRESS_V6, &cfg_type_netaddr6wild, 0, NULL },
	{ CFG_CLAUSE_ADDRESSES, &cfg_type_bracketed_sockaddrnameportlist, 0,
	  NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *rndcconf_server_clausesets[] = {
	rndcconf_server_clauses, NULL
};

static cfg_type_t cfg_type_rndcconf_server = {
	"rndcconf_server", cfg_parse_named_map, cfg_print_map,
	cfg_doc_map,	   &cfg_rep_map,	rndcconf_server_clausesets
};

static cfg_clausedef_t rndcconf_clauses[] = {
	{ CFG_CLAUSE_KEY, &cfg_type_key, CFG_CLAUSEFLAG_MULTI, NULL },
	{ CFG_CLAUSE_SERVER, &cfg_type_rndcconf_server, CFG_CLAUSEFLAG_MULTI,
	  NULL },
	{ CFG_CLAUSE_OPTIONS, &cfg_type_rndcconf_options, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *rndcconf_clausesets[] = { rndcconf_clauses, NULL };

cfg_type_t cfg_type_rndcconf = { "rndcconf",	    cfg_parse_mapbody,
				 cfg_print_mapbody, cfg_doc_mapbody,
				 &cfg_rep_map,	    rndcconf_clausesets };

static cfg_clausedef_t rndckey_clauses[] = {
	{ CFG_CLAUSE_KEY, &cfg_type_key, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *rndckey_clausesets[] = { rndckey_clauses, NULL };

cfg_type_t cfg_type_rndckey = { "rndckey",	   cfg_parse_mapbody,
				cfg_print_mapbody, cfg_doc_mapbody,
				&cfg_rep_map,	   rndckey_clausesets };

/*
 * session.key has exactly the same syntax as rndc.key, but it's defined
 * separately for clarity (and so we can extend it someday, if needed).
 */
cfg_type_t cfg_type_sessionkey = { "sessionkey",      cfg_parse_mapbody,
				   cfg_print_mapbody, cfg_doc_mapbody,
				   &cfg_rep_map,      rndckey_clausesets };

static cfg_tuplefielddef_t nameport_fields[] = {
	{ "name", &cfg_type_astring, 0 },
	{ "port", &cfg_type_optional_port, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_nameport = { "nameport",	 cfg_parse_tuple,
					cfg_print_tuple, cfg_doc_tuple,
					&cfg_rep_tuple,	 nameport_fields };

static void
doc_sockaddrnameport(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( ");
	cfg_print_cstr(pctx, "<quoted_string>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv4_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv6_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " )");
}

static isc_result_t
parse_sockaddrnameport(cfg_parser_t *pctx, const cfg_type_t *type,
		       cfg_obj_t **ret) {
	isc_result_t result;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string ||
	    pctx->token.type == isc_tokentype_qstring)
	{
		if (cfg_lookingat_netaddr(pctx, CFG_ADDR_V4OK | CFG_ADDR_V6OK))
		{
			CHECK(cfg_parse_sockaddr(pctx, &cfg_type_sockaddr,
						 ret));
		} else {
			CHECK(cfg_parse_tuple(pctx, &cfg_type_nameport, ret));
		}
	} else {
		cfg_parser_error(pctx, CFG_LOG_NEAR,
				 "expected IP address or hostname");
		return ISC_R_UNEXPECTEDTOKEN;
	}
cleanup:
	return result;
}

static cfg_type_t cfg_type_sockaddrnameport = { "sockaddrnameport_element",
						parse_sockaddrnameport,
						NULL,
						doc_sockaddrnameport,
						NULL,
						NULL };

static cfg_type_t cfg_type_bracketed_sockaddrnameportlist = {
	"bracketed_sockaddrnameportlist",
	cfg_parse_bracketed_list,
	cfg_print_bracketed_list,
	cfg_doc_bracketed_list,
	&cfg_rep_list,
	&cfg_type_sockaddrnameport
};

/*%
 * A list of socket addresses or name with an optional default port,
 * as used in the dual-stack-servers option.  E.g.,
 * "port 1234 { dual-stack-servers.net; 10.0.0.1; 1::2 port 69; }"
 */
static cfg_tuplefielddef_t nameportiplist_fields[] = {
	{ "port", &cfg_type_optional_port, 0 },
	{ "addresses", &cfg_type_bracketed_sockaddrnameportlist, 0 },
	{ NULL, NULL, 0 }
};

static cfg_type_t cfg_type_nameportiplist = {
	"nameportiplist", cfg_parse_tuple, cfg_print_tuple,
	cfg_doc_tuple,	  &cfg_rep_tuple,  nameportiplist_fields
};

/*%
 * remote servers element.
 */

static void
doc_remoteselement(cfg_printer_t *pctx, const cfg_type_t *type) {
	UNUSED(type);
	cfg_print_cstr(pctx, "( ");
	cfg_print_cstr(pctx, "<server-list>");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv4_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " | ");
	cfg_print_cstr(pctx, "<ipv6_address>");
	cfg_print_cstr(pctx, " ");
	cfg_print_cstr(pctx, "[ port <integer> ]");
	cfg_print_cstr(pctx, " )");
}

static isc_result_t
parse_remoteselement(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret) {
	isc_result_t result;
	cfg_obj_t *obj = NULL;
	UNUSED(type);

	CHECK(cfg_peektoken(pctx, CFG_LEXOPT_QSTRING));
	if (pctx->token.type == isc_tokentype_string ||
	    pctx->token.type == isc_tokentype_qstring)
	{
		if (cfg_lookingat_netaddr(pctx, CFG_ADDR_V4OK | CFG_ADDR_V6OK))
		{
			CHECK(cfg_parse_sockaddr(pctx, &cfg_type_sockaddr,
						 ret));
		} else {
			CHECK(cfg_parse_astring(pctx, &cfg_type_astring, ret));
		}
	} else {
		cfg_parser_error(pctx, CFG_LOG_NEAR,
				 "expected IP address or remote servers list "
				 "name");
		return ISC_R_UNEXPECTEDTOKEN;
	}
cleanup:
	CLEANUP_OBJ(obj);
	return result;
}

static cfg_type_t cfg_type_remoteselement = { "remotes_element",
					      parse_remoteselement,
					      NULL,
					      doc_remoteselement,
					      NULL,
					      NULL };

static int
cmp_clause(const void *ap, const void *bp) {
	const cfg_clausedef_t *a = (const cfg_clausedef_t *)ap;
	const cfg_clausedef_t *b = (const cfg_clausedef_t *)bp;
	return strcmp(cfg_clause_as_string[a->name],
		      cfg_clause_as_string[b->name]);
}

bool
cfg_clause_validforzone(enum cfg_clause name, unsigned int ztype) {
	const cfg_clausedef_t *clause;
	bool valid = false;

	for (clause = zone_clauses; clause->name != CFG_CLAUSE__NONE; clause++)
	{
		if ((clause->flags & ztype) == 0 || clause->name != name) {
			continue;
		}
		valid = true;
	}
	for (clause = zone_only_clauses; clause->name != CFG_CLAUSE__NONE;
	     clause++)
	{
		if ((clause->flags & ztype) == 0 || clause->name != name) {
			continue;
		}
		valid = true;
	}
	for (clause = non_template_clauses; clause->name != CFG_CLAUSE__NONE;
	     clause++)
	{
		if ((clause->flags & ztype) == 0 || clause->name != name) {
			continue;
		}
		valid = true;
	}

	return valid;
}

void
cfg_print_zonegrammar(const unsigned int zonetype, unsigned int flags,
		      void (*f)(void *closure, const char *text, int textlen),
		      void *closure) {
#define NCLAUSES                                                      \
	ARRAY_SIZE(non_template_clauses) + ARRAY_SIZE(zone_clauses) + \
		ARRAY_SIZE(zone_only_clauses) - 2

	cfg_printer_t pctx;
	cfg_clausedef_t clauses[NCLAUSES];
	cfg_clausedef_t *clause = clauses;

	pctx.f = f;
	pctx.closure = closure;
	pctx.indent = 0;
	pctx.flags = flags;

	memmove(clause, zone_clauses, sizeof(zone_clauses));
	clause += ARRAY_SIZE(zone_clauses) - 1;
	memmove(clause, zone_only_clauses, sizeof(zone_only_clauses));
	clause += ARRAY_SIZE(zone_only_clauses) - 1;
	memmove(clause, non_template_clauses, sizeof(non_template_clauses));

	qsort(clauses, NCLAUSES - 1, sizeof(clause[0]), cmp_clause);

	cfg_print_cstr(&pctx, "zone <string> [ <class> ] {\n");
	pctx.indent++;

	switch (zonetype) {
	case CFG_ZONE_PRIMARY:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type primary;\n");
		break;
	case CFG_ZONE_SECONDARY:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type secondary;\n");
		break;
	case CFG_ZONE_MIRROR:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type mirror;\n");
		break;
	case CFG_ZONE_STUB:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type stub;\n");
		break;
	case CFG_ZONE_HINT:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type hint;\n");
		break;
	case CFG_ZONE_FORWARD:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type forward;\n");
		break;
	case CFG_ZONE_STATICSTUB:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type static-stub;\n");
		break;
	case CFG_ZONE_REDIRECT:
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, "type redirect;\n");
		break;
	case CFG_ZONE_INVIEW:
		/* no zone type is specified for these */
		break;
	default:
		UNREACHABLE();
	}

	for (clause = clauses; clause->name != CFG_CLAUSE__NONE; clause++) {
		if (((pctx.flags & CFG_PRINTER_ACTIVEONLY) != 0) &&
		    (((clause->flags & CFG_CLAUSEFLAG_OBSOLETE) != 0) ||
		     ((clause->flags & CFG_CLAUSEFLAG_TESTONLY) != 0)))
		{
			continue;
		}
		if ((clause->flags & CFG_CLAUSEFLAG_ANCIENT) != 0 ||
		    (clause->flags & CFG_CLAUSEFLAG_NODOC) != 0)
		{
			continue;
		}

		if ((clause->flags & zonetype) == 0 ||
		    clause->name == CFG_CLAUSE_TYPE)
		{
			continue;
		}
		cfg_print_indent(&pctx);
		cfg_print_cstr(&pctx, cfg_clause_as_string[clause->name]);
		cfg_print_cstr(&pctx, " ");
		cfg_doc_obj(&pctx, clause->type);
		cfg_print_cstr(&pctx, ";");
		cfg_print_clauseflags(&pctx, clause->flags);
		cfg_print_cstr(&pctx, "\n");
	}

	pctx.indent--;
	cfg_print_cstr(&pctx, "};\n");
}

/*%
 * "tls" and related statement syntax.
 */
static cfg_type_t cfg_type_tlsprotos = { "tls_protocols",
					 cfg_parse_bracketed_list,
					 cfg_print_bracketed_list,
					 cfg_doc_bracketed_list,
					 &cfg_rep_list,
					 &cfg_type_astring };

static cfg_clausedef_t tls_clauses[] = {
	{ CFG_CLAUSE_KEY_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_CERT_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_CA_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_REMOTE_HOSTNAME, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_DHPARAM_FILE, &cfg_type_qstring, 0, NULL },
	{ CFG_CLAUSE_PROTOCOLS, &cfg_type_tlsprotos, 0, NULL },
	{ CFG_CLAUSE_CIPHERS, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_CIPHER_SUITES, &cfg_type_astring, 0, NULL },
	{ CFG_CLAUSE_PREFER_SERVER_CIPHERS, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE_SESSION_TICKETS, &cfg_type_boolean, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *tls_clausesets[] = { tls_clauses, NULL };
static cfg_type_t cfg_type_tlsconf = { "tlsconf",     cfg_parse_named_map,
				       cfg_print_map, cfg_doc_map,
				       &cfg_rep_map,  tls_clausesets };

static keyword_type_t tls_kw = { "tls", &cfg_type_astring };
static cfg_type_t cfg_type_optional_tls = {
	"tlsoptional",	       parse_optional_keyvalue, print_keyvalue,
	doc_optional_keyvalue, &cfg_rep_string,		&tls_kw
};

/* http and https */

static cfg_type_t cfg_type_bracketed_http_endpoint_list = {
	"bracketed_http_endpoint_list",
	cfg_parse_bracketed_list,
	cfg_print_bracketed_list,
	cfg_doc_bracketed_list,
	&cfg_rep_list,
	&cfg_type_qstring
};

static cfg_clausedef_t cfg_http_description_clauses[] = {
	{ CFG_CLAUSE_ENDPOINTS, &cfg_type_bracketed_http_endpoint_list, 0,
	  NULL },
	{ CFG_CLAUSE_LISTENER_CLIENTS, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE_STREAMS_PER_CONNECTION, &cfg_type_uint32, 0, NULL },
	{ CFG_CLAUSE__NONE, NULL, 0, NULL }
};

static cfg_clausedef_t *http_description_clausesets[] = {
	cfg_http_description_clauses, NULL
};

static cfg_type_t cfg_type_http_description = {
	"http_desc", cfg_parse_named_map, cfg_print_map,
	cfg_doc_map, &cfg_rep_map,	  http_description_clausesets
};

cfg_obj_t *
cfg_effective_config(const cfg_obj_t *userconfig,
		     const cfg_obj_t *defaultconfig) {
	cfg_obj_t *effective = NULL;

	REQUIRE(defaultconfig != NULL &&
		defaultconfig->type == &cfg_type_namedconf);
	REQUIRE(userconfig != NULL && userconfig->type == &cfg_type_namedconf);

	cfg_obj_clone(userconfig, &effective);
	map_merge(effective, effective, defaultconfig);

	return effective;
}
