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

#include <stdbool.h>

#include <isc/mem.h>
#include <isc/stats.h>
#include <isc/util.h>

#include <dns/stats.h>
#include <dns/tkey.h>

#include <ns/query.h>
#include <ns/server.h>
#include <ns/stats.h>

#define SCTX_MAGIC    ISC_MAGIC('S', 'c', 't', 'x')
#define SCTX_VALID(s) ISC_MAGIC_VALID(s, SCTX_MAGIC)

#define CHECKFATAL(op)                                  \
	do {                                            \
		result = (op);                          \
		RUNTIME_CHECK(result == ISC_R_SUCCESS); \
	} while (0)

void
ns_server_create(isc_mem_t *mctx, ns_matchview_t matchingview,
		 ns_server_t **sctxp) {
	ns_server_t *sctx = NULL;

	REQUIRE(sctxp != NULL && *sctxp == NULL);

	sctx = isc_mem_get(mctx, sizeof(*sctx));
	*sctx = (ns_server_t){
		.udpsize = 1232,
		.transfer_tcp_message_size = 20480,

		.fuzztype = isc_fuzz_none,

		.matchingview = matchingview,
		.answercookie = true,
	};

	isc_mem_attach(mctx, &sctx->mctx);

	/*
	 * See here for more details:
	 * https://github.com/jemalloc/jemalloc/issues/2483
	 */

	isc_refcount_init(&sctx->references, 1);

	isc_quota_init(&sctx->xfroutquota, 10);
	isc_quota_init(&sctx->tcpquota, 10);
	isc_quota_init(&sctx->recursionquota, 100);
	isc_quota_init(&sctx->updquota, 100);
	isc_quota_init(&sctx->sig0checksquota, 1);
	ISC_LIST_INIT(sctx->http_quotas);
	isc_mutex_init(&sctx->http_quotas_lock);

	ns_stats_create(mctx, ns_statscounter_max, &sctx->nsstats);

	dns_rdatatypestats_create(mctx, &sctx->rcvquerystats);

	dns_opcodestats_create(mctx, &sctx->opcodestats);

	dns_rcodestats_create(mctx, &sctx->rcodestats);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSIN,
			      &sctx->udpinstats4);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSOUT,
			      &sctx->udpoutstats4);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSIN,
			      &sctx->udpinstats6);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSOUT,
			      &sctx->udpoutstats6);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSIN,
			      &sctx->tcpinstats4);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSOUT,
			      &sctx->tcpoutstats4);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSIN,
			      &sctx->tcpinstats6);

	isc_histomulti_create(mctx, DNS_SIZEHISTO_SIGBITSOUT,
			      &sctx->tcpoutstats6);

	ISC_LIST_INIT(sctx->altsecrets);

	sctx->magic = SCTX_MAGIC;
	*sctxp = sctx;
}

void
ns_server_attach(ns_server_t *src, ns_server_t **dest) {
	REQUIRE(SCTX_VALID(src));
	REQUIRE(dest != NULL && *dest == NULL);

	isc_refcount_increment(&src->references);

	*dest = src;
}

void
ns_server_detach(ns_server_t **sctxp) {
	ns_server_t *sctx;

	REQUIRE(sctxp != NULL && SCTX_VALID(*sctxp));
	sctx = *sctxp;
	*sctxp = NULL;

	if (isc_refcount_decrement(&sctx->references) == 1) {
		ISC_LIST_FOREACH (sctx->altsecrets, altsecret, link) {
			ISC_LIST_UNLINK(sctx->altsecrets, altsecret, link);
			isc_mem_put(sctx->mctx, altsecret, sizeof(*altsecret));
		}

		if (sctx->sig0checksquota_exempt != NULL) {
			dns_acl_detach(&sctx->sig0checksquota_exempt);
		}

		isc_quota_destroy(&sctx->sig0checksquota);
		isc_quota_destroy(&sctx->updquota);
		isc_quota_destroy(&sctx->recursionquota);
		isc_quota_destroy(&sctx->tcpquota);
		isc_quota_destroy(&sctx->xfroutquota);

		ISC_LIST_FOREACH (sctx->http_quotas, http_quota, link) {
			ISC_LIST_DEQUEUE(sctx->http_quotas, http_quota, link);
			isc_quota_destroy(http_quota);
			isc_mem_put(sctx->mctx, http_quota,
				    sizeof(*http_quota));
		}
		isc_mutex_destroy(&sctx->http_quotas_lock);

		if (sctx->server_id != NULL) {
			isc_mem_free(sctx->mctx, sctx->server_id);
		}

		if (sctx->blackholeacl != NULL) {
			dns_acl_detach(&sctx->blackholeacl);
		}
		if (sctx->tkeyctx != NULL) {
			dns_tkeyctx_destroy(&sctx->tkeyctx);
		}

		if (sctx->nsstats != NULL) {
			ns_stats_detach(&sctx->nsstats);
		}

		if (sctx->rcvquerystats != NULL) {
			dns_stats_detach(&sctx->rcvquerystats);
		}
		if (sctx->opcodestats != NULL) {
			dns_stats_detach(&sctx->opcodestats);
		}
		if (sctx->rcodestats != NULL) {
			dns_stats_detach(&sctx->rcodestats);
		}

		if (sctx->udpinstats4 != NULL) {
			isc_histomulti_destroy(&sctx->udpinstats4);
		}
		if (sctx->tcpinstats4 != NULL) {
			isc_histomulti_destroy(&sctx->tcpinstats4);
		}
		if (sctx->udpoutstats4 != NULL) {
			isc_histomulti_destroy(&sctx->udpoutstats4);
		}
		if (sctx->tcpoutstats4 != NULL) {
			isc_histomulti_destroy(&sctx->tcpoutstats4);
		}

		if (sctx->udpinstats6 != NULL) {
			isc_histomulti_destroy(&sctx->udpinstats6);
		}
		if (sctx->tcpinstats6 != NULL) {
			isc_histomulti_destroy(&sctx->tcpinstats6);
		}
		if (sctx->udpoutstats6 != NULL) {
			isc_histomulti_destroy(&sctx->udpoutstats6);
		}
		if (sctx->tcpoutstats6 != NULL) {
			isc_histomulti_destroy(&sctx->tcpoutstats6);
		}

		sctx->magic = 0;

		isc_mem_putanddetach(&sctx->mctx, sctx, sizeof(*sctx));
	}
}

isc_result_t
ns_server_setserverid(ns_server_t *sctx, const char *serverid) {
	REQUIRE(SCTX_VALID(sctx));

	if (sctx->server_id != NULL) {
		isc_mem_free(sctx->mctx, sctx->server_id);
	}

	if (serverid != NULL) {
		sctx->server_id = isc_mem_strdup(sctx->mctx, serverid);
	}

	return ISC_R_SUCCESS;
}

void
ns_server_setoption(ns_server_t *sctx, unsigned int option, bool value) {
	REQUIRE(SCTX_VALID(sctx));
	if (value) {
		sctx->options |= option;
	} else {
		sctx->options &= ~option;
	}
}

bool
ns_server_getoption(ns_server_t *sctx, unsigned int option) {
	REQUIRE(SCTX_VALID(sctx));

	return (sctx->options & option) != 0;
}

void
ns_server_append_http_quota(ns_server_t *sctx, isc_quota_t *http_quota) {
	REQUIRE(SCTX_VALID(sctx));
	REQUIRE(http_quota != NULL);

	LOCK(&sctx->http_quotas_lock);
	ISC_LINK_INIT(http_quota, link);
	ISC_LIST_APPEND(sctx->http_quotas, http_quota, link);
	UNLOCK(&sctx->http_quotas_lock);
}
