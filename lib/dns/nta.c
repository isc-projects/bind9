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
#include <isc/buffer.h>
#include <isc/event.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/nta.h>
#include <dns/rbt.h>
#include <dns/rdataset.h>
#include <dns/resolver.h>
#include <dns/time.h>

struct dns_ntatable {
	/* Unlocked. */
	unsigned int magic;
	dns_view_t *view;
	isc_rwlock_t rwlock;
	isc_loopmgr_t *loopmgr;
	isc_task_t *task;
	/* Protected by atomics */
	isc_refcount_t references;
	/* Locked by rwlock. */
	dns_rbt_t *table;
	bool shuttingdown;
};

struct dns__nta {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_ntatable_t *ntatable;
	bool forced;
	isc_loop_t *loop;
	isc_timer_t *timer;
	dns_fetch_t *fetch;
	dns_rdataset_t rdataset;
	dns_rdataset_t sigrdataset;
	dns_fixedname_t fn;
	dns_name_t *name;
	isc_stdtime_t expiry;
};

#define NTA_MAGIC     ISC_MAGIC('N', 'T', 'A', 'n')
#define VALID_NTA(nn) ISC_MAGIC_VALID(nn, NTA_MAGIC)

static void
dns__nta_shutdown(dns__nta_t *nta);

static void
dns__nta_destroy(dns__nta_t *nta) {
	isc_refcount_destroy(&nta->references);
	nta->magic = 0;
	REQUIRE(nta->timer == NULL);
	if (dns_rdataset_isassociated(&nta->rdataset)) {
		dns_rdataset_disassociate(&nta->rdataset);
	}
	if (dns_rdataset_isassociated(&nta->sigrdataset)) {
		dns_rdataset_disassociate(&nta->sigrdataset);
	}
	if (nta->fetch != NULL) {
		dns_resolver_cancelfetch(nta->fetch);
		dns_resolver_destroyfetch(&nta->fetch);
	}
	isc_mem_putanddetach(&nta->mctx, nta, sizeof(*nta));
}

ISC_REFCOUNT_IMPL(dns__nta, dns__nta_destroy);

static void
dns__nta_free(void *data, void *arg) {
	dns__nta_t *nta = (dns__nta_t *)data;

	UNUSED(arg);

	dns__nta_shutdown(nta);
	dns__nta_detach(&nta); /* for nta_create() */
}

isc_result_t
dns_ntatable_create(dns_view_t *view, isc_taskmgr_t *taskmgr,
		    isc_loopmgr_t *loopmgr, dns_ntatable_t **ntatablep) {
	dns_ntatable_t *ntatable;
	isc_result_t result;

	REQUIRE(ntatablep != NULL && *ntatablep == NULL);

	ntatable = isc_mem_get(view->mctx, sizeof(*ntatable));
	*ntatable = (dns_ntatable_t){
		.loopmgr = loopmgr,
		.view = view,
	};

	result = isc_task_create(taskmgr, &ntatable->task, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_ntatable;
	}
	isc_task_setname(ntatable->task, "ntatable", ntatable);

	result = dns_rbt_create(view->mctx, dns__nta_free, NULL,
				&ntatable->table);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_task;
	}

	isc_rwlock_init(&ntatable->rwlock, 0, 0);

	isc_refcount_init(&ntatable->references, 1);

	ntatable->magic = NTATABLE_MAGIC;
	*ntatablep = ntatable;

	return (ISC_R_SUCCESS);

cleanup_task:
	isc_task_detach(&ntatable->task);

cleanup_ntatable:
	isc_mem_put(view->mctx, ntatable, sizeof(*ntatable));

	return (result);
}

static void
dns__ntatable_destroy(dns_ntatable_t *ntatable) {
	isc_refcount_destroy(&ntatable->references);
	ntatable->magic = 0;
	dns_rbt_destroy(&ntatable->table);
	isc_rwlock_destroy(&ntatable->rwlock);
	isc_task_detach(&ntatable->task);
	isc_mem_put(ntatable->view->mctx, ntatable, sizeof(*ntatable));
}

ISC_REFCOUNT_IMPL(dns_ntatable, dns__ntatable_destroy);

static void
fetch_done(isc_task_t *task, isc_event_t *event) {
	dns_fetchevent_t *devent = (dns_fetchevent_t *)event;
	dns__nta_t *nta = devent->ev_arg;
	isc_result_t eresult = devent->result;
	dns_ntatable_t *ntatable = nta->ntatable;
	dns_view_t *view = ntatable->view;
	isc_stdtime_t now;

	UNUSED(task);

	if (dns_rdataset_isassociated(&nta->rdataset)) {
		dns_rdataset_disassociate(&nta->rdataset);
	}
	if (dns_rdataset_isassociated(&nta->sigrdataset)) {
		dns_rdataset_disassociate(&nta->sigrdataset);
	}
	if (nta->fetch == devent->fetch) {
		nta->fetch = NULL;
	}
	dns_resolver_destroyfetch(&devent->fetch);

	if (devent->node != NULL) {
		dns_db_detachnode(devent->db, &devent->node);
	}
	if (devent->db != NULL) {
		dns_db_detach(&devent->db);
	}

	isc_event_free(&event);
	isc_stdtime_get(&now);

	switch (eresult) {
	case ISC_R_SUCCESS:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NXDOMAIN:
	case DNS_R_NCACHENXRRSET:
	case DNS_R_NXRRSET:
		RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);
		if (nta->expiry > now) {
			nta->expiry = now;
		}
		RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);
		break;
	default:
		break;
	}

	/*
	 * If we're expiring before the next recheck, we might
	 * as well stop the timer now.
	 */
	RWLOCK(&ntatable->rwlock, isc_rwlocktype_read);
	if (nta->timer != NULL && nta->expiry - now < view->nta_recheck) {
		isc_timer_stop(nta->timer);
	}
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_read);

	dns__nta_detach(&nta); /* for dns_resolver_createfetch() */
	dns_view_weakdetach(&view);
}

static void
checkbogus(void *arg) {
	dns__nta_t *nta = arg;
	dns_ntatable_t *ntatable = nta->ntatable;
	dns_view_t *view = NULL;
	isc_result_t result;

	if (nta->fetch != NULL) {
		dns_resolver_cancelfetch(nta->fetch);
		nta->fetch = NULL;
	}
	if (dns_rdataset_isassociated(&nta->rdataset)) {
		dns_rdataset_disassociate(&nta->rdataset);
	}
	if (dns_rdataset_isassociated(&nta->sigrdataset)) {
		dns_rdataset_disassociate(&nta->sigrdataset);
	}

	dns__nta_ref(nta); /* for dns_resolver_createfetch */
	dns_view_weakattach(ntatable->view, &view);
	result = dns_resolver_createfetch(
		view->resolver, nta->name, dns_rdatatype_nsec, NULL, NULL, NULL,
		NULL, 0, DNS_FETCHOPT_NONTA, 0, NULL, ntatable->task,
		fetch_done, nta, &nta->rdataset, &nta->sigrdataset,
		&nta->fetch);
	if (result != ISC_R_SUCCESS) {
		dns__nta_detach(&nta); /* for dns_resolver_createfetch() */
		dns_view_weakdetach(&view);
	}
}

static void
settimer(dns_ntatable_t *ntatable, dns__nta_t *nta, uint32_t lifetime) {
	dns_view_t *view = NULL;
	isc_interval_t interval;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(VALID_NTA(nta));

	view = ntatable->view;
	if (view->nta_recheck == 0 || lifetime <= view->nta_recheck) {
		return;
	}

	isc_timer_create(nta->loop, checkbogus, nta, &nta->timer);
	isc_interval_set(&interval, view->nta_recheck, 0);
	isc_timer_start(nta->timer, isc_timertype_ticker, &interval);
}

static void
nta_create(dns_ntatable_t *ntatable, const dns_name_t *name,
	   dns__nta_t **target) {
	dns__nta_t *nta = NULL;
	dns_view_t *view;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(target != NULL && *target == NULL);

	view = ntatable->view;

	nta = isc_mem_get(view->mctx, sizeof(dns__nta_t));
	*nta = (dns__nta_t){
		.ntatable = ntatable,
		.loop = isc_loop_current(ntatable->loopmgr),
		.magic = NTA_MAGIC,
	};

	isc_mem_attach(view->mctx, &nta->mctx);

	dns_rdataset_init(&nta->rdataset);
	dns_rdataset_init(&nta->sigrdataset);

	isc_refcount_init(&nta->references, 1);

	nta->name = dns_fixedname_initname(&nta->fn);
	dns_name_copy(name, nta->name);

	*target = nta;
}

isc_result_t
dns_ntatable_add(dns_ntatable_t *ntatable, const dns_name_t *name, bool force,
		 isc_stdtime_t now, uint32_t lifetime) {
	isc_result_t result = ISC_R_SUCCESS;
	dns__nta_t *nta = NULL;
	dns_rbtnode_t *node = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	if (ntatable->shuttingdown) {
		goto unlock;
	}

	nta_create(ntatable, name, &nta);

	nta->expiry = now + lifetime;
	nta->forced = force;

	result = dns_rbt_addnode(ntatable->table, name, &node);
	switch (result) {
	case ISC_R_EXISTS:
		result = ISC_R_SUCCESS;
		if (node->data != NULL) {
			/* NTA already exists, just update the timer */
			dns__nta_t *node_nta = (dns__nta_t *)node->data;
			node_nta->expiry = nta->expiry;
			dns__nta_detach(&nta); /* for nta_create */
			break;
		}
		/* Node was empty, update as if new */
		FALLTHROUGH;
	case ISC_R_SUCCESS:
		INSIST(node != NULL);
		INSIST(node->data == NULL);
		if (!force) {
			settimer(ntatable, nta, lifetime);
		}
		node->data = nta;
		break;
	default:
		break;
	}

unlock:
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	return (result);
}

/*
 * Caller must hold a write lock on rwlock.
 */
static isc_result_t
deletenode(dns_ntatable_t *ntatable, const dns_name_t *name) {
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	result = dns_rbt_findnode(ntatable->table, name, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	switch (result) {
	case ISC_R_SUCCESS:
		if (node->data == NULL) {
			/* Found empty node */
			return (ISC_R_NOTFOUND);
		}

		result = dns_rbt_deletenode(ntatable->table, node, false);
		return (result);
	case DNS_R_PARTIALMATCH:
		return (ISC_R_NOTFOUND);
	default:
		return (result);
	}
}

isc_result_t
dns_ntatable_delete(dns_ntatable_t *ntatable, const dns_name_t *name) {
	isc_result_t result;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(name != NULL);

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);
	result = deletenode(ntatable, name);
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	return (result);
}

bool
dns_ntatable_covered(dns_ntatable_t *ntatable, isc_stdtime_t now,
		     const dns_name_t *name, const dns_name_t *anchor) {
	isc_result_t result;
	dns_fixedname_t fn;
	dns_rbtnode_t *node;
	dns_name_t *foundname;
	dns__nta_t *nta = NULL;
	bool answer = false;
	isc_rwlocktype_t locktype;
	char nb[DNS_NAME_FORMATSIZE];

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(dns_name_isabsolute(name));

	foundname = dns_fixedname_initname(&fn);

	locktype = isc_rwlocktype_read;
relock:
	RWLOCK(&ntatable->rwlock, locktype);
again:
	node = NULL;
	result = dns_rbt_findnode(ntatable->table, name, foundname, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	switch (result) {
	case ISC_R_SUCCESS:
		/* Found a node */
		break;
	case DNS_R_PARTIALMATCH:
		if (!dns_name_issubdomain(foundname, anchor)) {
			goto unlock;
		}
		/* Found a parental node */
		result = ISC_R_SUCCESS;
		break;
	default:
		goto unlock;
	}

	INSIST(result == ISC_R_SUCCESS);
	nta = (dns__nta_t *)node->data;
	if (nta->expiry > now) {
		/* We got non-expired answer */
		answer = true;
		goto unlock;
	}

	/* Deal with expired NTA */
	if (locktype == isc_rwlocktype_read) {
		RWUNLOCK(&ntatable->rwlock, locktype);
		locktype = isc_rwlocktype_write;
		goto relock;
	}

	dns_name_format(foundname, nb, sizeof(nb));
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC, DNS_LOGMODULE_NTA,
		      ISC_LOG_INFO, "deleting expired NTA at %s", nb);

	/* We already found the node under the lock, so just delete it */
	result = dns_rbt_deletenode(ntatable->table, node, false);
	INSIST(result == ISC_R_SUCCESS);

	/* Look again */
	goto again;

unlock:
	RWUNLOCK(&ntatable->rwlock, locktype);

	return (answer);
}

static isc_result_t
putstr(isc_buffer_t **b, const char *str) {
	isc_result_t result;

	result = isc_buffer_reserve(b, strlen(str));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	isc_buffer_putstr(*b, str);
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_ntatable_totext(dns_ntatable_t *ntatable, const char *view,
		    isc_buffer_t **buf) {
	isc_result_t result;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	bool first = true;
	isc_stdtime_t now;

	REQUIRE(VALID_NTATABLE(ntatable));

	isc_stdtime_get(&now);

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, ntatable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_SUCCESS;
		}
		goto cleanup;
	}
	for (;;) {
		dns_rbtnodechain_current(&chain, NULL, NULL, &node);
		if (node->data != NULL) {
			dns__nta_t *n = (dns__nta_t *)node->data;
			char nbuf[DNS_NAME_FORMATSIZE];
			char tbuf[ISC_FORMATHTTPTIMESTAMP_SIZE];
			char obuf[DNS_NAME_FORMATSIZE +
				  ISC_FORMATHTTPTIMESTAMP_SIZE +
				  sizeof("expired:  \n")];
			dns_fixedname_t fn;
			dns_name_t *name;
			isc_time_t t;

			name = dns_fixedname_initname(&fn);
			dns_rbt_fullnamefromnode(node, name);
			dns_name_format(name, nbuf, sizeof(nbuf));

			if (n->expiry != 0xffffffffU) {
				/* Normal NTA entries */
				isc_time_set(&t, n->expiry, 0);
				isc_time_formattimestamp(&t, tbuf,
							 sizeof(tbuf));

				snprintf(obuf, sizeof(obuf), "%s%s%s%s: %s %s",
					 first ? "" : "\n", nbuf,
					 view != NULL ? "/" : "",
					 view != NULL ? view : "",
					 n->expiry <= now ? "expired"
							  : "expiry",
					 tbuf);
			} else {
				/* "validate-except" entries */
				snprintf(obuf, sizeof(obuf), "%s%s%s%s: %s",
					 first ? "" : "\n", nbuf,
					 view != NULL ? "/" : "",
					 view != NULL ? view : "", "permanent");
			}

			first = false;
			result = putstr(buf, obuf);
			if (result != ISC_R_SUCCESS) {
				goto cleanup;
			}
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE) {
				result = ISC_R_SUCCESS;
			}
			break;
		}
	}

cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_read);
	return (result);
}

isc_result_t
dns_ntatable_save(dns_ntatable_t *ntatable, FILE *fp) {
	isc_result_t result;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	isc_stdtime_t now;
	bool written = false;

	REQUIRE(VALID_NTATABLE(ntatable));

	isc_stdtime_get(&now);

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, ntatable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
		goto cleanup;
	}

	for (;;) {
		dns_rbtnodechain_current(&chain, NULL, NULL, &node);
		if (node->data != NULL) {
			isc_buffer_t b;
			char nbuf[DNS_NAME_FORMATSIZE + 1], tbuf[80];
			dns_fixedname_t fn;
			dns_name_t *name;
			dns__nta_t *n = (dns__nta_t *)node->data;

			/*
			 * Skip this node if the expiry is already in the
			 * past, or if this is a "validate-except" entry.
			 */
			if (n->expiry <= now || n->expiry == 0xffffffffU) {
				goto skip;
			}

			name = dns_fixedname_initname(&fn);
			dns_rbt_fullnamefromnode(node, name);

			isc_buffer_init(&b, nbuf, sizeof(nbuf));
			result = dns_name_totext(name, false, &b);
			if (result != ISC_R_SUCCESS) {
				goto skip;
			}

			/* Zero terminate. */
			isc_buffer_putuint8(&b, 0);

			isc_buffer_init(&b, tbuf, sizeof(tbuf));
			dns_time32_totext(n->expiry, &b);

			/* Zero terminate. */
			isc_buffer_putuint8(&b, 0);

			fprintf(fp, "%s %s %s\n", nbuf,
				n->forced ? "forced" : "regular", tbuf);
			written = true;
		}
	skip:
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE) {
				result = ISC_R_SUCCESS;
			}
			break;
		}
	}

cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_read);

	if (result == ISC_R_SUCCESS && !written) {
		result = ISC_R_NOTFOUND;
	}

	return (result);
}

static void
dns__nta_shutdown_cb(dns__nta_t *nta) {
	REQUIRE(VALID_NTA(nta));

	if (nta->timer) {
		isc_timer_stop(nta->timer); /* This is superfluous */
		isc_timer_destroy(&nta->timer);
	}

	dns__nta_detach(&nta);
}

static void
dns__nta_shutdown(dns__nta_t *nta) {
	REQUIRE(VALID_NTA(nta));

	if (nta->timer != NULL) {
		isc_timer_stop(nta->timer);
	}

	dns__nta_ref(nta);
	isc_async_run(nta->loop, (isc_job_cb)dns__nta_shutdown_cb, nta);
}

void
dns_ntatable_shutdown(dns_ntatable_t *ntatable) {
	isc_result_t result;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;

	REQUIRE(VALID_NTATABLE(ntatable));

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);
	ntatable->shuttingdown = true;

	dns_rbtnodechain_init(&chain);
	result = dns_rbtnodechain_first(&chain, ntatable->table, NULL, NULL);
	while (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		dns_rbtnodechain_current(&chain, NULL, NULL, &node);
		if (node->data != NULL) {
			dns__nta_t *nta = (dns__nta_t *)node->data;
			dns__nta_shutdown(nta);
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}

	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);
}
