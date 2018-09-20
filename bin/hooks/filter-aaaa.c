/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/ht.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <ns/client.h>
#include <ns/hooks.h>
#include <ns/log.h>
#include <ns/query.h>
#include <ns/types.h>

#include <dns/acl.h>
#include <dns/db.h>
#include <dns/enumtype.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/rdataset.h>
#include <dns/result.h>
#include <dns/types.h>

#define CHECK(op)						\
	do {							\
		result = (op);					\
		if (result != ISC_R_SUCCESS) {			\
			goto cleanup;				\
		}						\
	} while (0)

/*
 * Possible values for the settings of filter-aaaa-on-v4 and
 * filter-aaaa-on-v6: "no" is NONE, "yes" is FILTER, "break-dnssec"
 * is BREAK_DNSSEC.
 */
typedef enum {
	NONE = 0,
	FILTER = 1,
	BREAK_DNSSEC = 2
} filter_aaaa_t;

/*
 * Persistent data for use by this module. This will be associated
 * with client object address in the hash table, and will remain
 * accessible until the client object is detached.
 */
typedef struct filter_data {
	filter_aaaa_t mode;
	uint32_t flags;
} filter_data_t;

/*
 * Memory pool for use with persistent data.
 */
static isc_mempool_t *datapool = NULL;

/*
 * Hash table associating 'qctx' with its data.
 */
static isc_ht_t *qctx_ht = NULL;

/*
 * Per-client flags set by this module
 */
#define FILTER_AAAA_RECURSING	0x0001	/* Recursing for A */
#define FILTER_AAAA_FILTERED	0x0002	/* AAAA was removed from answer */

/*
 * Client attribute tests.
 */
#define WANTDNSSEC(c)	(((c)->attributes & NS_CLIENTATTR_WANTDNSSEC) != 0)
#define RECURSIONOK(c)	(((c)->query.attributes & \
				  NS_QUERYATTR_RECURSIONOK) != 0)

/*
 * Hook registration structures: pointers to these structures will
 * be added to a hook table when this module is registered.
 */
static bool
filter_qctx_initialize(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t filter_init = {
	.action = filter_qctx_initialize,
	.action_data = &qctx_ht,
};

static bool
filter_respond_begin(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t filter_respbegin = {
	.action = filter_respond_begin,
	.action_data = &qctx_ht,
};

static bool
filter_respond_any_found(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t filter_respanyfound = {
	.action = filter_respond_any_found,
	.action_data = &qctx_ht,
};

static bool
filter_prep_response_begin(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t filter_prepresp = {
	.action = filter_prep_response_begin,
	.action_data = &qctx_ht,
};

static bool
filter_query_done_send(void *arg, void *cbdata, isc_result_t *resp);
static ns_hook_t filter_donesend = {
	.action = filter_query_done_send,
	.action_data = &qctx_ht,
};

static bool
filter_qctx_destroy(void *arg, void *cbdata, isc_result_t *resp);
ns_hook_t filter_destroy = {
	.action = filter_qctx_destroy,
	.action_data = &qctx_ht,
};

/**
 ** Support for parsing of parameters and configuration of the module.
 **/

/*
 * Values configured when the module is loaded.
 */
static filter_aaaa_t v4_aaaa = NONE;
static filter_aaaa_t v6_aaaa = NONE;
static dns_acl_t *aaaa_acl = NULL;

/*
 * Support for parsing of parameters.
 */
static const char *filter_aaaa_enums[] = { "break-dnssec", NULL };

static isc_result_t
parse_filter_aaaa(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret) {
	return (cfg_parse_enum_or_other(pctx, type, &cfg_type_boolean, ret));
}

static void
doc_filter_aaaa(cfg_printer_t *pctx, const cfg_type_t *type) {
	cfg_doc_enum_or_other(pctx, type, &cfg_type_boolean);
}

static cfg_type_t cfg_type_filter_aaaa = {
	"filter_aaaa", parse_filter_aaaa, cfg_print_ustring,
	doc_filter_aaaa, &cfg_rep_string, filter_aaaa_enums,
};

static cfg_clausedef_t param_clauses[] = {
	{ "filter-aaaa", &cfg_type_bracketed_aml, 0 },
	{ "filter-aaaa-on-v4", &cfg_type_filter_aaaa, 0 },
	{ "filter-aaaa-on-v6", &cfg_type_filter_aaaa, 0 },
};

static cfg_clausedef_t *param_clausesets[] = {
	param_clauses,
	NULL
};

static cfg_type_t cfg_type_parameters = {
	"filter-aaaa-params", cfg_parse_mapbody, cfg_print_mapbody,
	cfg_doc_mapbody, &cfg_rep_map, param_clausesets
};

static isc_result_t
parse_filter_aaaa_on(const cfg_obj_t *param_obj, const char *param_name,
		     filter_aaaa_t *dstp)
{
	const cfg_obj_t *obj = NULL;
	isc_result_t result;

	result = cfg_map_get(param_obj, param_name, &obj);
	if (result != ISC_R_SUCCESS) {
		return (ISC_R_SUCCESS);
	}

	if (cfg_obj_isboolean(obj)) {
		if (cfg_obj_asboolean(obj)) {
			*dstp = FILTER;
		} else {
			*dstp = NONE;
		}
	} else if (strcasecmp(cfg_obj_asstring(obj), "break-dnssec") == 0) {
		*dstp = BREAK_DNSSEC;
	} else {
		result = ISC_R_UNEXPECTED;
	}

	return (result);
}

static isc_result_t
parse_parameters(const char *parameters, const void *cfg,
		 void *actx, ns_hookctx_t *hctx)
{
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *param_obj = NULL;
	const cfg_obj_t *obj = NULL;
	isc_buffer_t b;

	CHECK(cfg_parser_create(hctx->mctx, hctx->lctx, &parser));

	isc_buffer_constinit(&b, parameters, strlen(parameters));
	isc_buffer_add(&b, strlen(parameters));
	CHECK(cfg_parse_buffer(parser, &b, &cfg_type_parameters,
			       &param_obj));

	CHECK(parse_filter_aaaa_on(param_obj, "filter-aaaa-on-v4", &v4_aaaa));
	CHECK(parse_filter_aaaa_on(param_obj, "filter-aaaa-on-v6", &v6_aaaa));

	obj = NULL;
	result = cfg_map_get(param_obj, "filter-aaaa", &obj);
	if (result == ISC_R_SUCCESS) {
		CHECK(cfg_acl_fromconfig(obj, (const cfg_obj_t *) cfg,
					 hctx->lctx,
					 (cfg_aclconfctx_t *) actx,
					 hctx->mctx, 0, &aaaa_acl));
	} else {
		CHECK(dns_acl_any(hctx->mctx, &aaaa_acl));
	}

 cleanup:
	if (param_obj != NULL) {
		cfg_obj_destroy(parser, &param_obj);
	}
	if (parser != NULL) {
		cfg_parser_destroy(&parser);
	}
	return (result);
}

/**
 ** Mandatory hook API functions:
 **
 ** - hook_destroy
 ** - hook_register
 ** - hook_version
 **/

/*
 * Called by ns_hookmodule_load() to register hook functions into
 * a hook table.
 */
isc_result_t
hook_register(const char *parameters,
	      const char *cfg_file, unsigned long cfg_line,
	      const void *cfg, void *actx,
	      ns_hookctx_t *hctx, ns_hooktable_t *hooktable)
{
	isc_result_t result;

	/*
	 * Depending on how dlopen() works on the current platform, we
	 * may not have access to named's global namespace, in which
	 * case we need to initialize libisc/libdns/libns. We compare
	 * the address of a global reference variable to its address
	 * in the calling program to determine whether this is necessary.
	 */
	if (hctx->refvar != &isc_bind9) {
		isc_lib_register();
		isc_log_setcontext(hctx->lctx);
		dns_log_setcontext(hctx->lctx);
		ns_log_setcontext(hctx->lctx);
	}

	isc_hash_set_initializer(hctx->hashinit);

	isc_log_write(hctx->lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_HOOKS, ISC_LOG_INFO,
		      "loading 'filter-aaaa' "
		      "module from %s:%lu, %s parameters",
		      cfg_file, cfg_line, parameters != NULL ? "with" : "no");

	if (parameters != NULL) {
		CHECK(parse_parameters(parameters, cfg, actx, hctx));
	}

	ns_hook_add(hooktable, hctx->mctx, NS_QUERY_QCTX_INITIALIZED,
		    &filter_init);
	ns_hook_add(hooktable, hctx->mctx, NS_QUERY_RESPOND_BEGIN,
		    &filter_respbegin);
	ns_hook_add(hooktable, hctx->mctx, NS_QUERY_RESPOND_ANY_FOUND,
		    &filter_respanyfound);
	ns_hook_add(hooktable, hctx->mctx, NS_QUERY_PREP_RESPONSE_BEGIN,
		    &filter_prepresp);
	ns_hook_add(hooktable, hctx->mctx, NS_QUERY_DONE_SEND,
		    &filter_donesend);
	ns_hook_add(hooktable, hctx->mctx, NS_QUERY_QCTX_DESTROYED,
		    &filter_destroy);

	CHECK(isc_mempool_create(hctx->mctx, sizeof(filter_data_t),
				 &datapool));

	CHECK(isc_ht_init(&qctx_ht, hctx->mctx, 16));

	/*
	 * Fill the mempool with 1K filter_aaaa state objects at
	 * a time; ideally after a single allocation, the mempool will
	 * have enough to handle all the simultaneous queries the system
	 * requires and it won't be necessary to allocate more.
	 *
	 * We don't set any limit on the number of free state objects
	 * so that they'll always be returned to the pool and not
	 * freed until the pool is destroyed on shutdown.
	 */
	isc_mempool_setfillcount(datapool, 1024);
	isc_mempool_setfreemax(datapool, UINT_MAX);

 cleanup:
	if (result != ISC_R_SUCCESS) {
		if (datapool != NULL) {
			isc_mempool_destroy(&datapool);
		}
	}
	return (result);
}

/*
 * Called by ns_hookmodule_unload_all(); frees memory allocated by
 * the module when it was registered.
 */
void
hook_destroy(void) {
	if (qctx_ht != NULL) {
		isc_ht_destroy(&qctx_ht);
	}
	if (datapool != NULL) {
		isc_mempool_destroy(&datapool);
	}
	if (aaaa_acl != NULL) {
		dns_acl_detach(&aaaa_acl);
	}

	return;
}

/*
 * Returns hook module API version for compatibility checks.
 */
int
hook_version(void) {
	return (NS_HOOK_VERSION);
}

/**
 ** "filter-aaaa" feature implementation begins here.
 **/

/*
 * Check whether this is an IPv4 client.
 */
static bool
is_v4_client(ns_client_t *client) {
	if (isc_sockaddr_pf(&client->peeraddr) == AF_INET)
		return (true);
	if (isc_sockaddr_pf(&client->peeraddr) == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&client->peeraddr.type.sin6.sin6_addr))
		return (true);
	return (false);
}

/*
 * Check whether this is an IPv6 client.
 */
static bool
is_v6_client(ns_client_t *client) {
	if (isc_sockaddr_pf(&client->peeraddr) == AF_INET6 &&
	    !IN6_IS_ADDR_V4MAPPED(&client->peeraddr.type.sin6.sin6_addr))
		return (true);
	return (false);
}

/*
 * Initialize filter state, fetching it from a memory pool and storing it
 * in a hash table keyed according to the client object; this enables
 * us to retrieve persistent data related to a client query for as long
 * as the object persists..
 */
static bool
filter_qctx_initialize(void *arg, void *cbdata, isc_result_t *resp) {
	isc_result_t result;
	query_ctx_t *qctx = (query_ctx_t *) arg;
	isc_ht_t **htp = (isc_ht_t **) cbdata;
	filter_data_t *data;

	result = isc_ht_find(*htp, (const unsigned char *)&qctx->client,
			     sizeof(qctx->client), NULL);
	if (result == ISC_R_NOTFOUND) {
		data = isc_mempool_get(datapool);

		result = isc_ht_add(*htp, (const unsigned char *)&qctx->client,
				    sizeof(qctx->client), data);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		data->mode = NONE;
		data->flags = 0;
	}

	*resp = ISC_R_UNSET;
	return (false);
}

static filter_data_t *
get_data(query_ctx_t *qctx, isc_ht_t **htp) {
	filter_data_t *data;
	isc_result_t result;

	result = isc_ht_find(*htp, (const unsigned char *)&qctx->client,
			     sizeof(qctx->client), (void **)&data);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	return (data);
}

/*
 * Determine whether this client should have AAAA filtered or not,
 * based on the client address family and the settings of
 * filter-aaaa-on-v4 and filter-aaaa-on-v6.
 */
static bool
filter_prep_response_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	filter_data_t *data = get_data(qctx, cbdata);
	isc_result_t result;

	if (v4_aaaa != NONE || v6_aaaa != NONE) {
		result = ns_client_checkaclsilent(qctx->client, NULL,
						  aaaa_acl, true);
		if (result == ISC_R_SUCCESS &&
		    v4_aaaa != NONE &&
		    is_v4_client(qctx->client))
		{
			data->mode = v4_aaaa;
		} else if (result == ISC_R_SUCCESS &&
			   v6_aaaa != NONE &&
			   is_v6_client(qctx->client))
		{
			data->mode = v6_aaaa;
		}
	}

	*resp = ISC_R_UNSET;
	return (false);
}

/*
 * Hide AAAA rrsets if there is a matching A. Trigger recursion if
 * necessary to find out whether an A exists.
 *
 * (This version is for processing answers to explicit AAAA
 * queries; ANY queries are handled in query_filter_aaaa_any().)
 */
static bool
filter_respond_begin(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	filter_data_t *data = get_data(qctx, cbdata);
	isc_result_t result = ISC_R_UNSET;

	if (data->mode != BREAK_DNSSEC &&
	    (data->mode != FILTER ||
	     (WANTDNSSEC(qctx->client) && qctx->sigrdataset != NULL &&
	      dns_rdataset_isassociated(qctx->sigrdataset))))
	{
		*resp = result;
		return (false);
	}

	if (qctx->qtype == dns_rdatatype_aaaa) {
		dns_rdataset_t *trdataset;
		trdataset = ns_client_newrdataset(qctx->client);
		result = dns_db_findrdataset(qctx->db, qctx->node,
					     qctx->version,
					     dns_rdatatype_a, 0,
					     qctx->client->now,
					     trdataset, NULL);
		if (dns_rdataset_isassociated(trdataset)) {
			dns_rdataset_disassociate(trdataset);
		}
		ns_client_putrdataset(qctx->client, &trdataset);

		/*
		 * We found an AAAA. If we also found an A, then the AAAA
		 * must not be rendered.
		 *
		 * If the A is not in our cache, then any result other than
		 * DNS_R_DELEGATION or ISC_R_NOTFOUND means there is no A,
		 * and so AAAAs are okay.
		 *
		 * We assume there is no A if we can't recurse for this
		 * client. That might be the wrong answer, but what else
		 * can we do?  Besides, the fact that we have the AAAA and
		 * are using this mechanism in the first place suggests
		 * that we care more about As than AAAAs, and would have
		 * cached an A if it existed.
		 */
		if (result == ISC_R_SUCCESS) {
			qctx->client->message->flags &= ~DNS_MESSAGEFLAG_AD;
			qctx->rdataset->attributes |= DNS_RDATASETATTR_RENDERED;
			if (qctx->sigrdataset != NULL &&
			    dns_rdataset_isassociated(qctx->sigrdataset))
			{
				qctx->sigrdataset->attributes |=
					DNS_RDATASETATTR_RENDERED;
			}

			data->flags |= FILTER_AAAA_FILTERED;
		} else if (!qctx->authoritative &&
			   RECURSIONOK(qctx->client) &&
			   (result == DNS_R_DELEGATION ||
			    result == ISC_R_NOTFOUND))
		{
			/*
			 * This is an ugly kludge to recurse
			 * for the A and discard the result.
			 *
			 * Continue to add the AAAA now.
			 * We'll make a note to not render it
			 * if the recursion for the A succeeds.
			 */
			result = (*qctx->methods.query_recurse)(qctx->client,
						 dns_rdatatype_a,
						 qctx->client->query.qname,
						 NULL, NULL, qctx->resuming);
			if (result == ISC_R_SUCCESS) {
				data->flags |= FILTER_AAAA_RECURSING;
				qctx->client->query.attributes |=
					NS_QUERYATTR_RECURSING;
			}
		}
	} else if (qctx->qtype == dns_rdatatype_a &&
		   (data->flags & FILTER_AAAA_RECURSING) != 0)
	{
		dns_rdataset_t *mrdataset = NULL;
		dns_rdataset_t *sigrdataset = NULL;

		result = dns_message_findname(qctx->client->message,
					      DNS_SECTION_ANSWER, qctx->fname,
					      dns_rdatatype_aaaa, 0,
					      NULL, &mrdataset);
		if (result == ISC_R_SUCCESS) {
			qctx->client->message->flags &= ~DNS_MESSAGEFLAG_AD;
			mrdataset->attributes |= DNS_RDATASETATTR_RENDERED;
		}

		result = dns_message_findname(qctx->client->message,
					      DNS_SECTION_ANSWER, qctx->fname,
					      dns_rdatatype_rrsig,
					      dns_rdatatype_aaaa,
					      NULL, &sigrdataset);
		if (result == ISC_R_SUCCESS) {
			qctx->client->message->flags &= ~DNS_MESSAGEFLAG_AD;
			sigrdataset->attributes |= DNS_RDATASETATTR_RENDERED;
		}

		data->flags &= ~FILTER_AAAA_RECURSING;

		result = (*qctx->methods.query_done)(qctx);

		*resp = result;

		return (true);
	}

	*resp = result;
	return (false);
}

/*
 * When answering an ANY query, remove AAAA if A is present.
 */
static bool
filter_respond_any_found(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	filter_data_t *data = get_data(qctx, cbdata);
	dns_name_t *name = NULL;
	dns_rdataset_t *aaaa = NULL, *aaaa_sig = NULL;
	dns_rdataset_t *a = NULL;
	bool have_a = true;

	if (data->mode == NONE) {
		*resp = ISC_R_UNSET;
		return (false);
	}

	dns_message_findname(qctx->client->message, DNS_SECTION_ANSWER,
			     (qctx->fname != NULL)
			      ? qctx->fname
			      : qctx->tname,
			     dns_rdatatype_any, 0, &name, NULL);

	/*
	 * If we're not authoritative, just assume there's an
	 * A even if it wasn't in the cache and therefore isn't
	 * in the message.  But if we're authoritative, then
	 * if there was an A, it should be here.
	 */
	if (qctx->authoritative && name != NULL) {
		dns_message_findtype(name, dns_rdatatype_a, 0, &a);
		if (a == NULL) {
			have_a = false;
		}
	}

	if (name != NULL) {
		dns_message_findtype(name, dns_rdatatype_aaaa, 0, &aaaa);
		dns_message_findtype(name, dns_rdatatype_rrsig,
				     dns_rdatatype_aaaa, &aaaa_sig);
	}

	if (have_a && aaaa != NULL &&
	    (aaaa_sig == NULL || !WANTDNSSEC(qctx->client) ||
	     data->mode == BREAK_DNSSEC))
	{
		qctx->client->message->flags &= ~DNS_MESSAGEFLAG_AD;
		aaaa->attributes |= DNS_RDATASETATTR_RENDERED;
		if (aaaa_sig != NULL) {
			aaaa_sig->attributes |= DNS_RDATASETATTR_RENDERED;
		}
	}

	*resp = ISC_R_UNSET;
	return (false);
}

/*
 * Hide AAAA rrsets in the additional section if there is a matching A,
 * and hide NS in the authority section if AAAA was filtered in the answer
 * section.
 */
static bool
filter_query_done_send(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) arg;
	filter_data_t *data = get_data(qctx, cbdata);
	isc_result_t result;

	if (data->mode == NONE) {
		*resp = ISC_R_UNSET;
		return (false);
	}

	result = dns_message_firstname(qctx->client->message,
				       DNS_SECTION_ADDITIONAL);
	while (result == ISC_R_SUCCESS) {
		dns_name_t *name = NULL;
		dns_rdataset_t *aaaa = NULL, *aaaa_sig = NULL;
		dns_rdataset_t *a = NULL;

		dns_message_currentname(qctx->client->message,
					DNS_SECTION_ADDITIONAL,
					&name);

		result = dns_message_nextname(qctx->client->message,
					      DNS_SECTION_ADDITIONAL);

		dns_message_findtype(name, dns_rdatatype_a, 0, &a);
		if (a == NULL) {
			continue;
		}

		dns_message_findtype(name, dns_rdatatype_aaaa, 0,
				     &aaaa);
		if (aaaa == NULL) {
			continue;
		}

		dns_message_findtype(name, dns_rdatatype_rrsig,
				     dns_rdatatype_aaaa, &aaaa_sig);

		if (aaaa_sig == NULL || !WANTDNSSEC(qctx->client) ||
		    data->mode == BREAK_DNSSEC)
		{
			aaaa->attributes |= DNS_RDATASETATTR_RENDERED;
			if (aaaa_sig != NULL) {
				aaaa_sig->attributes |=
					DNS_RDATASETATTR_RENDERED;
			}
		}
	}

	if ((data->flags & FILTER_AAAA_FILTERED) != 0) {
		result = dns_message_firstname(qctx->client->message,
					       DNS_SECTION_AUTHORITY);
		while (result == ISC_R_SUCCESS) {
			dns_name_t *name = NULL;
			dns_rdataset_t *ns = NULL, *ns_sig = NULL;

			dns_message_currentname(qctx->client->message,
						DNS_SECTION_AUTHORITY,
						&name);

			result = dns_message_findtype(name, dns_rdatatype_ns,
						      0, &ns);
			if (result == ISC_R_SUCCESS) {
				qctx->client->message->flags &=
					~DNS_MESSAGEFLAG_AD;
				ns->attributes |= DNS_RDATASETATTR_RENDERED;
			}

			result = dns_message_findtype(name, dns_rdatatype_rrsig,
						      dns_rdatatype_ns,
						      &ns_sig);
			if (result == ISC_R_SUCCESS) {
				ns_sig->attributes |= DNS_RDATASETATTR_RENDERED;
			}

			result = dns_message_nextname(qctx->client->message,
						      DNS_SECTION_AUTHORITY);
		}
	}

	*resp = ISC_R_UNSET;
	return (false);
}

/*
 * If the client is being detached, then we can delete our persistent
 * data from hash table and return it to the memory pool.
 */
static bool
filter_qctx_destroy(void *arg, void *cbdata, isc_result_t *resp) {
	isc_result_t result;
	query_ctx_t *qctx = (query_ctx_t *) arg;
	isc_ht_t **htp = (isc_ht_t **) cbdata;
	filter_data_t *data;

	if (!qctx->detach_client) {
		return (false);
	}

	data = get_data(qctx, htp);

	result = isc_ht_delete(*htp, (const unsigned char *)&qctx->client,
			       sizeof(qctx->client));
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	isc_mempool_put(datapool, data);

	*resp = ISC_R_UNSET;
	return (false);
}
