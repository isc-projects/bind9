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

#include <isc/hash.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/result.h>
#include <dns/view.h>

#include <ns/client.h>
#include <ns/hooks.h>
#include <ns/log.h>
#include <ns/query.h>

ns_hook_destroy_t hook_destroy;
ns_hook_register_t hook_register;
ns_hook_version_t hook_version;

/*
 * Per-client flags set by this module
 */
#define FILTER_AAAA_RECURSING	0x0001	/* Recursing for A */
#define FILTER_AAAA_FILTERED	0x0002	/* AAAA was removed from answer */


/*% Want DNSSEC? */
#define WANTDNSSEC(c)		(((c)->attributes & \
				  NS_CLIENTATTR_WANTDNSSEC) != 0)
/*% Recursion OK? */
#define RECURSIONOK(c)		(((c)->query.attributes & \
				  NS_QUERYATTR_RECURSIONOK) != 0)

static bool
filter_respond_begin(void *hookdata, void *cbdata, isc_result_t *resp);

static bool
filter_respond_any_found(void *hookdata, void *cbdata, isc_result_t *resp);

static bool
filter_prep_response_begin(void *hookdata, void *cbdata, isc_result_t *resp);

static bool
filter_query_done_send(void *hookdata, void *cbdata, isc_result_t *resp);

ns_hook_t filter_respbegin = {
	.callback = filter_respond_begin,
};
ns_hook_t filter_respanyfound = {
	.callback = filter_respond_any_found,
};
ns_hook_t filter_prepresp = {
	.callback = filter_prep_response_begin,
};
ns_hook_t filter_donesend = {
	.callback = filter_query_done_send,
};

isc_result_t
hook_register(const char *parameters, const char *file, unsigned long line,
	      ns_hookctx_t *hctx, ns_hooktable_t *hooktable, void **instp)
{
	UNUSED(parameters);
	UNUSED(instp);

	/*
	 * Depending on how dlopen() was called, we may not have
	 * access to named's global namespace, in which case we need
	 * to initialize libisc/libdns/libns
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
		      "loading params for 'filter-aaaa' module from %s:%lu",
		      file, line);

	/*
	 * TODO:
	 * configure with parameters here
	 */

	ns_hook_add(hooktable, NS_QUERY_RESPOND_BEGIN,
		    &filter_respbegin);
	ns_hook_add(hooktable, NS_QUERY_RESPOND_ANY_FOUND,
		    &filter_respanyfound);
	ns_hook_add(hooktable, NS_QUERY_PREP_RESPONSE_BEGIN,
		    &filter_prepresp);
	ns_hook_add(hooktable, NS_QUERY_DONE_SEND,
		    &filter_donesend);

	/*
	 * TODO:
	 * Set up a serial number that can be used for accessing
	 * data blobs in qctx, client, view;
	 * return an instance pointer for later destruction
	 */
	return (ISC_R_SUCCESS);
}

void
hook_destroy(void **instp) {
	UNUSED(instp);

	return;
}

int
hook_version(unsigned int *flags) {
	UNUSED(flags);

	return (NS_HOOK_VERSION);
}

/*
 * Check whether this is a V4 client.
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
 * Check whether this is a V6 client.
 */
static bool
is_v6_client(ns_client_t *client) {
	if (isc_sockaddr_pf(&client->peeraddr) == AF_INET6 &&
	    !IN6_IS_ADDR_V4MAPPED(&client->peeraddr.type.sin6.sin6_addr))
		return (true);
	return (false);
}

/*
 * The filter-aaaa-on-v4 option suppresses AAAAs for IPv4
 * clients if there is an A; filter-aaaa-on-v6 option does
 * the same for IPv6 clients.
 */
static bool
filter_prep_response_begin(void *hookdata, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) hookdata;
	isc_result_t result;

	UNUSED(cbdata);

	qctx->filter_aaaa = dns_aaaa_ok;
	if (qctx->client->view->v4_aaaa != dns_aaaa_ok ||
	    qctx->client->view->v6_aaaa != dns_aaaa_ok)
	{
		result = ns_client_checkaclsilent(qctx->client, NULL,
						  qctx->client->view->aaaa_acl,
						  true);
		if (result == ISC_R_SUCCESS &&
		    qctx->client->view->v4_aaaa != dns_aaaa_ok &&
		    is_v4_client(qctx->client))
		{
			qctx->filter_aaaa = qctx->client->view->v4_aaaa;
		} else if (result == ISC_R_SUCCESS &&
			   qctx->client->view->v6_aaaa != dns_aaaa_ok &&
			   is_v6_client(qctx->client))
		{
			qctx->filter_aaaa = qctx->client->view->v6_aaaa;
		}
	}

	*resp = ISC_R_UNSET;
	return (false);
}

/*
 * Optionally hide AAAA rrsets if there is a matching A.
 * (This version is for processing answers to explicit AAAA
 * queries; ANY queries are handled in query_filter_aaaa_any().)
 */
static bool
filter_respond_begin(void *hookdata, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) hookdata;
	isc_result_t result = ISC_R_UNSET;

	UNUSED(cbdata);

	if (qctx->filter_aaaa != dns_aaaa_break_dnssec &&
	    (qctx->filter_aaaa != dns_aaaa_filter ||
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
			qctx->rdataset->attributes |= DNS_RDATASETATTR_RENDERED;
			if (qctx->sigrdataset != NULL &&
			    dns_rdataset_isassociated(qctx->sigrdataset))
			{
				qctx->sigrdataset->attributes |=
					DNS_RDATASETATTR_RENDERED;
			}
			qctx->client->hookflags |= FILTER_AAAA_FILTERED;
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
				qctx->client->hookflags |=
					FILTER_AAAA_RECURSING;
				qctx->client->query.attributes |=
					NS_QUERYATTR_RECURSING;
			}
		}
	} else if (qctx->qtype == dns_rdatatype_a &&
		   ((qctx->client->hookflags & FILTER_AAAA_RECURSING) != 0))
	{

		dns_rdataset_t *mrdataset = NULL;
		dns_rdataset_t *sigrdataset = NULL;

		result = dns_message_findname(qctx->client->message,
					      DNS_SECTION_ANSWER, qctx->fname,
					      dns_rdatatype_aaaa, 0,
					      NULL, &mrdataset);
		if (result == ISC_R_SUCCESS) {
			mrdataset->attributes |= DNS_RDATASETATTR_RENDERED;
		}

		result = dns_message_findname(qctx->client->message,
					      DNS_SECTION_ANSWER, qctx->fname,
					      dns_rdatatype_rrsig,
					      dns_rdatatype_aaaa,
					      NULL, &sigrdataset);
		if (result == ISC_R_SUCCESS) {
			sigrdataset->attributes |= DNS_RDATASETATTR_RENDERED;
		}

		qctx->client->hookflags &= ~FILTER_AAAA_RECURSING;

		result = (*qctx->methods.query_done)(qctx);

		*resp = result;
		return (true);

	}

	*resp = result;
	return (false);
}

static bool
filter_respond_any_found(void *hookdata, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) hookdata;
	dns_name_t *name = NULL;
	dns_rdataset_t *aaaa = NULL, *aaaa_sig = NULL;
	dns_rdataset_t *a = NULL;
	bool have_a = true;

	UNUSED(cbdata);

	if (qctx->filter_aaaa == dns_aaaa_ok) {
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
	     qctx->filter_aaaa == dns_aaaa_break_dnssec))
	{
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
 * and hide NS in the additional section if AAAA was filtered in the answer
 * section.
 */
static bool
filter_query_done_send(void *hookdata, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *) hookdata;
	isc_result_t result;

	UNUSED(cbdata);

	if (qctx->filter_aaaa == dns_aaaa_ok) {
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
		     qctx->filter_aaaa == dns_aaaa_break_dnssec)
		{
			aaaa->attributes |= DNS_RDATASETATTR_RENDERED;
			if (aaaa_sig != NULL) {
				aaaa_sig->attributes |=
					DNS_RDATASETATTR_RENDERED;
			}
		}
	}

	if ((qctx->client->hookflags & FILTER_AAAA_FILTERED) != 0) {
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
