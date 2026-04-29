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

#include <isc/async.h>
#include <isc/loop.h>

#include <dns/resolver.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zonefetch.h>
#include <dns/zoneproperties.h>

#include "zone_p.h"

void
dns_zonefetch_run(void *arg) {
	dns_zonefetch_t *fetch = (dns_zonefetch_t *)arg;
	dns_zone_t *zone;
	dns_view_t *view;
	isc_loop_t *loop;
	isc_result_t result;
	dns_resolver_t *resolver = NULL;

	zone = fetch->zone;
	if (dns__zone_exiting(zone)) {
		result = ISC_R_SHUTTINGDOWN;
		goto cancel;
	}
	view = dns_zone_getview(zone);
	loop = dns_zone_getloop(zone);

	INSIST(view != NULL);
	INSIST(loop != NULL);

	result = fetch->fetchmethods.start_fetch(fetch);
	if (result != ISC_R_SUCCESS) {
		goto cancel;
	}

	result = dns_view_getresolver(view, &resolver);
	if (result != ISC_R_SUCCESS) {
		goto cancel;
	}

	if (isc_log_wouldlog(ISC_LOG_DEBUG(3))) {
		char namebuf[DNS_NAME_FORMATSIZE];
		char typebuf[DNS_RDATATYPE_FORMATSIZE];
		dns_name_format(fetch->qname, namebuf, sizeof(namebuf));
		dns_rdatatype_format(fetch->qtype, typebuf, sizeof(typebuf));
		dns_zone_logc(zone, DNS_LOGCATEGORY_DNSSEC, ISC_LOG_DEBUG(3),
			      "Do fetch for %s/%s request", namebuf, typebuf);
	}

	result = dns_resolver_createfetch(
		resolver, fetch->qname, fetch->qtype, NULL, NULL, NULL, NULL, 0,
		fetch->options, 0, NULL, NULL, NULL, loop, dns_zonefetch_done,
		fetch, NULL, &fetch->rrset, &fetch->sigset, &fetch->fetch);

	dns_resolver_detach(&resolver);

cancel:
	if (result == ISC_R_SUCCESS) {
		return;
	} else if (result != ISC_R_SHUTTINGDOWN) {
		char namebuf[DNS_NAME_FORMATSIZE];

		if (DNS_NAME_VALID(fetch->qname)) {
			char typebuf[DNS_RDATATYPE_FORMATSIZE];
			dns_name_format(fetch->qname, namebuf, sizeof(namebuf));
			dns_rdatatype_format(fetch->qtype, typebuf,
					     sizeof(typebuf));
			dns_zone_log(zone, ISC_LOG_WARNING,
				     "Failed fetch for %s/%s request", namebuf,
				     typebuf);
		} else {
			dns_zone_nameonly(zone, namebuf, sizeof(namebuf));
			dns_zone_log(zone, ISC_LOG_WARNING,
				     "Failed fetch for zone %s", namebuf);
		}
	}

	/*
	 * Fetch failed, cancel.
	 */
	dns__zone_lock(zone);

	dns_name_t *zname = dns_fixedname_name(&fetch->name);
	isc_mem_t *mctx = dns_zone_getmctx(zone);
	bool free_needed;

	isc_refcount_decrement(dns__zone_irefs(zone));
	dns_name_free(zname, mctx);

	fetch->fetchmethods.cancel_fetch(fetch);

	isc_mem_putanddetach(&fetch->mctx, fetch, sizeof(*fetch));
	free_needed = dns__zone_free_check(zone);

	dns__zone_unlock(zone);

	if (free_needed) {
		dns__zone_free(zone);
	}
}

void
dns_zonefetch_done(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	isc_result_t result = ISC_R_NOMORE;
	isc_result_t eresult;
	dns_zonefetch_t *fetch = NULL;
	dns_zone_t *zone = NULL;
	dns_view_t *view = NULL;
	isc_mem_t *mctx = NULL;
	dns_name_t *zname = NULL;
	dns_rdataset_t *rrset = NULL;
	dns_rdataset_t *sigset = NULL;

	INSIST(resp != NULL);

	fetch = resp->arg;

	INSIST(fetch != NULL);

	mctx = fetch->mctx;
	zone = fetch->zone;
	zname = dns_fixedname_name(&fetch->name);
	rrset = &fetch->rrset;
	sigset = &fetch->sigset;
	view = dns_zone_getview(zone);
	eresult = resp->result;

	/* Free resources which are not of interest */
	if (resp->node != NULL) {
		dns_db_detachnode(&resp->node);
	}
	if (resp->cache != NULL) {
		dns_db_detach(&resp->cache);
	}
	dns_resolver_destroyfetch(&fetch->fetch);

	dns__zone_lock(zone);
	if (dns__zone_exiting(zone) || view == NULL) {
		goto cleanup;
	}

	result = fetch->fetchmethods.done_fetch(fetch, eresult);

cleanup:
	isc_refcount_decrement(dns__zone_irefs(zone));

	dns_rdataset_cleanup(rrset);
	dns_rdataset_cleanup(sigset);

	fetch->fetchmethods.cleanup_fetch(fetch);

	dns_resolver_freefresp(&resp);

	if (result == DNS_R_CONTINUE) {
		dns__zone_unlock(zone);
		fetch->fetchmethods.continue_fetch(fetch);
	} else {
		bool free_needed = false;
		dns_name_free(zname, mctx);
		isc_mem_putanddetach(&fetch->mctx, fetch,
				     sizeof(dns_zonefetch_t));
		free_needed = dns__zone_free_check(zone);

		dns__zone_unlock(zone);

		if (free_needed) {
			dns__zone_free(zone);
		}
	}
}

static void
zonefetch_schedule(dns_zonefetch_t *fetch, dns_name_t *name) {
	dns_zone_t *zone = fetch->zone;

	isc_refcount_increment0(dns__zone_irefs(zone));

	if (name != NULL) {
		dns_name_t *fname = dns_fixedname_initname(&fetch->name);
		dns_name_dup(name, fetch->mctx, fname);
	}

	dns_rdataset_init(&fetch->rrset);
	dns_rdataset_init(&fetch->sigset);

	isc_async_run(dns_zone_getloop(zone), dns_zonefetch_run, fetch);
}

void
dns_zonefetch_schedule(dns_zonefetch_t *fetch, dns_name_t *name) {
	REQUIRE(fetch != NULL);
	REQUIRE(name != NULL);

	zonefetch_schedule(fetch, name);
}

void
dns_zonefetch_reschedule(dns_zonefetch_t *fetch) {
	REQUIRE(fetch != NULL);

	zonefetch_schedule(fetch, NULL);
}

isc_result_t
dns_zonefetch_verify(dns_zonefetch_t *fetch, isc_result_t eresult,
		     dns_trust_t trust) {
	char namebuf[DNS_NAME_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];
	dns_rdataset_t *rrset = NULL;
	dns_rdataset_t *sigset = NULL;

	REQUIRE(fetch != NULL);

	rrset = &fetch->rrset;
	sigset = &fetch->sigset;
	dns_name_format(fetch->qname, namebuf, sizeof(namebuf));
	dns_rdatatype_format(fetch->qtype, typebuf, sizeof(typebuf));

	if (eresult != ISC_R_SUCCESS) {
		dns_zone_logc(fetch->zone, DNS_LOGCATEGORY_DNSSEC,
			      ISC_LOG_WARNING, "Unable to fetch %s/%s: %s",
			      namebuf, typebuf, isc_result_totext(eresult));
		return eresult;
	}

	/* No records found */
	if (!dns_rdataset_isassociated(rrset)) {
		dns_zone_logc(fetch->zone, DNS_LOGCATEGORY_DNSSEC,
			      ISC_LOG_WARNING, "No %s records found for '%s'",
			      typebuf, namebuf);
		return ISC_R_NOTFOUND;
	}

	/* No RRSIGs found */
	if (!dns_rdataset_isassociated(sigset)) {
		dns_zone_logc(fetch->zone, DNS_LOGCATEGORY_DNSSEC,
			      ISC_LOG_WARNING, "No %s RRSIGs found for '%s'",
			      typebuf, namebuf);
		return DNS_R_NOVALIDSIG;
	}

	/* Check trust level */
	if (rrset->trust < trust) {
		dns_zone_logc(fetch->zone, DNS_LOGCATEGORY_DNSSEC,
			      ISC_LOG_WARNING,
			      "Invalid %s RRset for '%s' trust level %u",
			      typebuf, namebuf, rrset->trust);
		return DNS_R_NOVALIDSIG;
	}

	return ISC_R_SUCCESS;
}
