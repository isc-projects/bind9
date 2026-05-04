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

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/nta.h>
#include <dns/qp.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/time.h>

struct dns_ntatable {
	unsigned int magic;
	isc_mem_t *mctx;
	dns_view_t *view;
	isc_refcount_t references;
	dns_qpmulti_t *table;
};

struct dns__nta {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_loop_t *loop;
	isc_refcount_t references;
	dns_ntatable_t *ntatable;
	bool forced;
	isc_timer_t *timer;
	dns_fetch_t *fetch;
	dns_rdataset_t rdataset;
	dns_rdataset_t sigrdataset;
	dns_name_t name;
	isc_stdtime_t expiry;
};

#define NTA_MAGIC     ISC_MAGIC('N', 'T', 'A', 'n')
#define VALID_NTA(nn) ISC_MAGIC_VALID(nn, NTA_MAGIC)

static void
dns__nta_shutdown(dns__nta_t *nta);

static void
qp_attach(void *uctx, void *pval, uint32_t ival);
static void
qp_detach(void *uctx, void *pval, uint32_t ival);
static size_t
qp_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival);
static void
qp_triename(void *uctx, char *buf, size_t size);

static dns_qpmethods_t qpmethods = {
	qp_attach,
	qp_detach,
	qp_makekey,
	qp_triename,
};

static void
dns__nta_destroy(dns__nta_t *nta) {
	REQUIRE(nta->timer == NULL);

	nta->magic = 0;
	dns_ntatable_detach(&nta->ntatable);
	dns_rdataset_cleanup(&nta->rdataset);
	dns_rdataset_cleanup(&nta->sigrdataset);
	if (nta->fetch != NULL) {
		dns_resolver_cancelfetch(nta->fetch);
		dns_resolver_destroyfetch(&nta->fetch);
	}
	isc_loop_detach(&nta->loop);
	dns_name_free(&nta->name, nta->mctx);
	isc_mem_putanddetach(&nta->mctx, nta, sizeof(*nta));
}

#if DNS_NTA_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns__nta, dns__nta_destroy);
#else
ISC_REFCOUNT_IMPL(dns__nta, dns__nta_destroy);
#endif

void
dns_ntatable_create(dns_view_t *view, dns_ntatable_t **ntatablep) {
	dns_ntatable_t *ntatable = NULL;

	REQUIRE(ntatablep != NULL && *ntatablep == NULL);

	ntatable = isc_mem_get(view->mctx, sizeof(*ntatable));
	*ntatable = (dns_ntatable_t){
		.magic = NTATABLE_MAGIC,
		.mctx = isc_mem_ref(view->mctx),
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};

	dns_view_weakattach(view, &ntatable->view);

	dns_qpmulti_create(view->mctx, &qpmethods, view, &ntatable->table);

	*ntatablep = ntatable;
}

static void
dns__ntatable_destroy(dns_ntatable_t *ntatable) {
	ntatable->magic = 0;
	INSIST(ntatable->table == NULL);
	INSIST(ntatable->view == NULL);
	isc_mem_putanddetach(&ntatable->mctx, ntatable, sizeof(*ntatable));
}

#if DNS_NTA_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_ntatable, dns__ntatable_destroy);
#else
ISC_REFCOUNT_IMPL(dns_ntatable, dns__ntatable_destroy);
#endif

static void
fetch_done(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	dns__nta_t *nta = resp->arg;
	isc_result_t eresult = resp->result;
	dns_ntatable_t *ntatable = nta->ntatable;
	isc_stdtime_t now = isc_stdtime_now();
	isc_stdtime_t expiry;

	rcu_read_lock();
	dns_view_t *view = rcu_dereference(ntatable->view);

	dns_rdataset_cleanup(&nta->rdataset);
	dns_rdataset_cleanup(&nta->sigrdataset);
	if (nta->fetch == resp->fetch) {
		nta->fetch = NULL;
	}
	dns_resolver_destroyfetch(&resp->fetch);

	if (resp->node != NULL) {
		dns_db_detachnode(&resp->node);
	}
	if (resp->cache != NULL) {
		dns_db_detach(&resp->cache);
	}

	dns_resolver_freefresp(&resp);

	expiry = CMM_LOAD_SHARED(nta->expiry);

	switch (eresult) {
	case ISC_R_SUCCESS:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NXDOMAIN:
	case DNS_R_NCACHENXRRSET:
	case DNS_R_NXRRSET:
		if (expiry > now) {
			CMM_STORE_SHARED(nta->expiry, now);
			expiry = now;
		}
		break;
	default:
		break;
	}

	/*
	 * If we're expiring before the next recheck, we might
	 * as well stop the timer now.
	 */
	if (nta->timer != NULL &&
	    (view == NULL || expiry - now < view->nta_recheck))
	{
		isc_timer_stop(nta->timer);
	}

	rcu_read_unlock();
	dns__nta_detach(&nta); /* for dns_resolver_createfetch() */
}

static void
checkbogus(void *arg) {
	dns__nta_t *nta = arg;
	dns_ntatable_t *ntatable = nta->ntatable;
	dns_resolver_t *resolver = NULL;
	isc_result_t result;

	if (nta->fetch != NULL) {
		dns_resolver_cancelfetch(nta->fetch);
		nta->fetch = NULL;
	}
	dns_rdataset_cleanup(&nta->rdataset);
	dns_rdataset_cleanup(&nta->sigrdataset);

	rcu_read_lock();
	dns_view_t *view = rcu_dereference(ntatable->view);
	if (view == NULL) {
		isc_timer_stop(nta->timer);
		rcu_read_unlock();
		return;
	}

	result = dns_view_getresolver(view, &resolver);
	if (result != ISC_R_SUCCESS) {
		rcu_read_unlock();
		return;
	}

	dns__nta_ref(nta); /* for dns_resolver_createfetch */
	result = dns_resolver_createfetch(
		resolver, &nta->name, dns_rdatatype_nsec, NULL, NULL, NULL,
		NULL, 0, DNS_FETCHOPT_NONTA, 0, NULL, NULL, NULL, nta->loop,
		fetch_done, nta, NULL, &nta->rdataset, &nta->sigrdataset,
		&nta->fetch);
	if (result != ISC_R_SUCCESS) {
		dns__nta_detach(&nta); /* for dns_resolver_createfetch() */
	}
	dns_resolver_detach(&resolver);
	rcu_read_unlock();
}

static void
settimer(dns_view_t *view, dns__nta_t *nta, uint32_t lifetime) {
	REQUIRE(VALID_NTA(nta));

	if (view->nta_recheck == 0 || lifetime <= view->nta_recheck) {
		return;
	}

	isc_interval_t interval;
	isc_interval_set(&interval, view->nta_recheck, 0);

	isc_timer_create(nta->loop, checkbogus, nta, &nta->timer);
	isc_timer_start(nta->timer, isc_timertype_ticker, &interval);
}

static void
nta_create(dns_ntatable_t *ntatable, const dns_name_t *name,
	   dns__nta_t **target) {
	dns__nta_t *nta = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(target != NULL && *target == NULL);

	nta = isc_mem_get(ntatable->mctx, sizeof(dns__nta_t));
	*nta = (dns__nta_t){
		.ntatable = dns_ntatable_ref(ntatable),
		.name = DNS_NAME_INITEMPTY,
		.magic = NTA_MAGIC,
	};
	isc_mem_attach(ntatable->mctx, &nta->mctx);
	isc_loop_attach(isc_loop(), &nta->loop);

	dns_rdataset_init(&nta->rdataset);
	dns_rdataset_init(&nta->sigrdataset);

	isc_refcount_init(&nta->references, 1);

	dns_name_dup(name, nta->mctx, &nta->name);

	*target = nta;
}

isc_result_t
dns_ntatable_add(dns_ntatable_t *ntatable, const dns_name_t *name, bool force,
		 isc_stdtime_t now, uint32_t lifetime) {
	isc_result_t result = ISC_R_SUCCESS;
	dns__nta_t *nta = NULL, *old_nta = NULL;
	dns_qp_t *qp = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));

	rcu_read_lock();
	dns_view_t *view = rcu_dereference(ntatable->view);
	dns_qpmulti_t *table = rcu_dereference(ntatable->table);
	if (view == NULL || table == NULL) {
		rcu_read_unlock();
		return ISC_R_SUCCESS;
	}

	dns_qpmulti_write(table, &qp);
	nta_create(ntatable, name, &nta);
	nta->forced = force;
	result = dns_qp_insert(qp, nta, 0);
	switch (result) {
	case ISC_R_EXISTS:
		result = dns_qp_deletename(qp, name, DNS_DBNAMESPACE_NORMAL,
					   (void *)&old_nta, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		dns__nta_shutdown(old_nta);
		dns__nta_detach(&old_nta);

		result = dns_qp_insert(qp, nta, 0);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		FALLTHROUGH;
	case ISC_R_SUCCESS:
		CMM_STORE_SHARED(nta->expiry, now + lifetime);
		if (!force) {
			settimer(view, nta, lifetime);
		}
		break;
	default:
		UNREACHABLE();
	}

	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(table, &qp);

	rcu_read_unlock();

	return result;
}

isc_result_t
dns_ntatable_delete(dns_ntatable_t *ntatable, const dns_name_t *name) {
	isc_result_t result;
	dns_qp_t *qp = NULL;
	void *pval = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(name != NULL);

	rcu_read_lock();
	dns_qpmulti_t *table = rcu_dereference(ntatable->table);
	if (table == NULL) {
		rcu_read_unlock();
		return ISC_R_SUCCESS;
	}

	dns_qpmulti_write(table, &qp);
	result = dns_qp_deletename(qp, name, DNS_DBNAMESPACE_NORMAL, &pval,
				   NULL);
	if (result == ISC_R_SUCCESS) {
		dns__nta_t *n = pval;
		dns__nta_shutdown(n);
		dns__nta_detach(&n);
	}
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(table, &qp);

	rcu_read_unlock();

	return result;
}

static void
delete_expired(void *arg) {
	dns__nta_t *nta = arg;
	dns_ntatable_t *ntatable = nta->ntatable;
	isc_result_t result;
	dns_qp_t *qp = NULL;
	void *pval = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));

	rcu_read_lock();
	dns_view_t *view = rcu_dereference(ntatable->view);
	dns_qpmulti_t *table = rcu_dereference(ntatable->table);
	if (view == NULL || table == NULL) {
		goto unlock;
	}

	dns_qpmulti_write(table, &qp);
	result = dns_qp_getname(qp, &nta->name, DNS_DBNAMESPACE_NORMAL, &pval,
				NULL);
	if (result == ISC_R_SUCCESS && nta == pval) {
		char nb[DNS_NAME_FORMATSIZE];
		dns_name_format(&nta->name, nb, sizeof(nb));
		isc_log_write(DNS_LOGCATEGORY_DNSSEC, DNS_LOGMODULE_NTA,
			      ISC_LOG_INFO, "deleting expired NTA at %s", nb);

		result = dns_qp_deletename(qp, &nta->name,
					   DNS_DBNAMESPACE_NORMAL, NULL, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		dns__nta_shutdown(nta);
		dns__nta_unref(nta);
	}
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(table, &qp);
unlock:
	rcu_read_unlock();
	dns__nta_detach(&nta);
	dns_ntatable_detach(&ntatable);
}

bool
dns_ntatable_covered(dns_ntatable_t *ntatable, isc_stdtime_t now,
		     const dns_name_t *name, const dns_name_t *anchor) {
	isc_result_t result;
	dns__nta_t *nta = NULL;
	bool answer = false;
	dns_qpread_t qpr;
	void *pval = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(dns_name_isabsolute(name));

	rcu_read_lock();
	dns_view_t *view = rcu_dereference(ntatable->view);
	dns_qpmulti_t *table = rcu_dereference(ntatable->table);
	if (view == NULL || table == NULL) {
		goto unlock;
	}

	dns_qpmulti_query(table, &qpr);
	result = dns_qp_lookup(&qpr, name, DNS_DBNAMESPACE_NORMAL, NULL, NULL,
			       &pval, NULL);
	nta = pval;

	switch (result) {
	case ISC_R_SUCCESS:
		/* Exact match */
		break;
	case DNS_R_PARTIALMATCH:
		/*
		 * Found a NTA that's an ancestor of 'name'; we
		 * now have to make sure 'anchor' isn't below it.
		 */
		if (!dns_name_issubdomain(&nta->name, anchor)) {
			goto done;
		}
		/* Ancestor match */
		break;
	default:
		/* Found nothing */
		goto done;
	}

	if (CMM_LOAD_SHARED(nta->expiry) <= now) {
		/* NTA is expired */
		dns__nta_ref(nta);
		dns_ntatable_ref(nta->ntatable);
		isc_async_run(nta->loop, delete_expired, nta);
		goto done;
	}

	answer = true;
done:
	dns_qpread_destroy(table, &qpr);
unlock:
	rcu_read_unlock();

	return answer;
}

static isc_result_t
putstr(isc_buffer_t *b, const char *str) {
	RETERR(isc_buffer_reserve(b, strlen(str)));

	isc_buffer_putstr(b, str);
	return ISC_R_SUCCESS;
}

isc_result_t
dns_ntatable_totext(dns_ntatable_t *ntatable, const char *view,
		    isc_buffer_t *buf) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_stdtime_t now = isc_stdtime_now();
	dns_qpread_t qpr;
	dns_qpiter_t iter;
	bool first = true;
	void *pval = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));

	rcu_read_lock();
	dns_qpmulti_t *table = rcu_dereference(ntatable->table);
	if (table == NULL) {
		rcu_read_unlock();
		return ISC_R_SUCCESS;
	}

	dns_qpmulti_query(table, &qpr);
	dns_qpiter_init(&qpr, &iter);

	while (dns_qpiter_next(&iter, &pval, NULL) == ISC_R_SUCCESS) {
		dns__nta_t *n = pval;
		char nbuf[DNS_NAME_FORMATSIZE];
		char tbuf[ISC_FORMATHTTPTIMESTAMP_SIZE];
		char obuf[DNS_NAME_FORMATSIZE + ISC_FORMATHTTPTIMESTAMP_SIZE +
			  sizeof("expired:  \n")];
		isc_time_t t;
		isc_stdtime_t expiry = CMM_LOAD_SHARED(n->expiry);

		dns_name_format(&n->name, nbuf, sizeof(nbuf));

		if (expiry != 0xffffffffU) {
			/* Normal NTA entries */
			isc_time_set(&t, expiry, 0);
			isc_time_formattimestamp(&t, tbuf, sizeof(tbuf));

			snprintf(obuf, sizeof(obuf), "%s%s%s%s: %s %s",
				 first ? "" : "\n", nbuf,
				 view != NULL ? "/" : "",
				 view != NULL ? view : "",
				 expiry <= now ? "expired" : "expiry", tbuf);
		} else {
			/* "validate-except" entries */
			snprintf(obuf, sizeof(obuf), "%s%s%s%s: %s",
				 first ? "" : "\n", nbuf,
				 view != NULL ? "/" : "",
				 view != NULL ? view : "", "permanent");
		}

		first = false;
		CHECK(putstr(buf, obuf));
	}

cleanup:
	dns_qpread_destroy(table, &qpr);
	rcu_read_unlock();
	return result;
}

isc_result_t
dns_ntatable_save(dns_ntatable_t *ntatable, FILE *fp) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_stdtime_t now = isc_stdtime_now();
	dns_qpread_t qpr;
	dns_qpiter_t iter;
	bool written = false;
	void *pval = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));

	rcu_read_lock();
	dns_qpmulti_t *table = rcu_dereference(ntatable->table);
	if (table == NULL) {
		rcu_read_unlock();
		return ISC_R_SUCCESS;
	}

	dns_qpmulti_query(table, &qpr);
	dns_qpiter_init(&qpr, &iter);

	while (dns_qpiter_next(&iter, &pval, NULL) == ISC_R_SUCCESS) {
		dns__nta_t *n = pval;
		isc_buffer_t b;
		char nbuf[DNS_NAME_FORMATSIZE + 1], tbuf[80];
		isc_stdtime_t expiry = CMM_LOAD_SHARED(n->expiry);

		/*
		 * Skip this node if the expiry is already in the
		 * past, or if this is a "validate-except" entry.
		 */
		if (expiry <= now || expiry == 0xffffffffU) {
			continue;
		}

		isc_buffer_init(&b, nbuf, sizeof(nbuf));
		result = dns_name_totext(&n->name, 0, &b);
		if (result != ISC_R_SUCCESS) {
			continue;
		}

		/* Zero terminate */
		isc_buffer_putuint8(&b, 0);

		isc_buffer_init(&b, tbuf, sizeof(tbuf));
		dns_time32_totext(expiry, &b);

		/* Zero terminate */
		isc_buffer_putuint8(&b, 0);

		fprintf(fp, "%s %s %s\n", nbuf,
			n->forced ? "forced" : "regular", tbuf);
		written = true;
	}

	dns_qpread_destroy(table, &qpr);
	rcu_read_unlock();

	if (result == ISC_R_SUCCESS && !written) {
		result = ISC_R_NOTFOUND;
	}

	return result;
}

static void
dns__nta_shutdown_cb(void *arg) {
	dns__nta_t *nta = arg;

	REQUIRE(VALID_NTA(nta));

	if (isc_log_wouldlog(ISC_LOG_DEBUG(3))) {
		char nb[DNS_NAME_FORMATSIZE];
		dns_name_format(&nta->name, nb, sizeof(nb));
		isc_log_write(DNS_LOGCATEGORY_DNSSEC, DNS_LOGMODULE_NTA,
			      ISC_LOG_DEBUG(3), "shutting down NTA %p at %s",
			      nta, nb);
	}
	if (nta->timer) {
		isc_timer_stop(nta->timer);
		isc_timer_destroy(&nta->timer);
	}

	dns__nta_detach(&nta);
}

static void
dns__nta_shutdown(dns__nta_t *nta) {
	REQUIRE(VALID_NTA(nta));

	dns__nta_ref(nta);
	isc_async_run(nta->loop, dns__nta_shutdown_cb, nta);
}

void
dns_ntatable_shutdown(dns_ntatable_t *ntatable) {
	REQUIRE(VALID_NTATABLE(ntatable));

	dns_view_t *view = rcu_xchg_pointer(&ntatable->view, NULL);
	dns_qpmulti_t *table = rcu_xchg_pointer(&ntatable->table, NULL);

	synchronize_rcu();

	dns_qpread_t qpr;
	dns_qpiter_t iter;
	void *pval = NULL;

	dns_qpmulti_query(table, &qpr);

	dns_qpiter_init(&qpr, &iter);
	while (dns_qpiter_next(&iter, &pval, NULL) == ISC_R_SUCCESS) {
		dns__nta_t *nta = pval;

		dns__nta_shutdown(nta);
		dns__nta_detach(&nta);
	}

	dns_qpread_destroy(table, &qpr);
	dns_view_weakdetach(&view);
	dns_qpmulti_destroy(&table);
}

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns__nta_t *nta = pval;
	dns__nta_ref(nta);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns__nta_t *nta = pval;
	dns__nta_detach(&nta);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	dns__nta_t *nta = pval;
	return dns_qpkey_fromname(key, &nta->name, DNS_DBNAMESPACE_NORMAL);
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	dns_view_t *view = uctx;
	snprintf(buf, size, "view %s forwarder table", view->name);
}
