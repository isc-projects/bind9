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
#include <isc/hash.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/rwlock.h>
#include <isc/sockaddr.h>
#include <isc/spinlock.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/types.h>
#include <dns/unreachcache.h>

typedef struct dns_ucentry dns_ucentry_t;

typedef struct dns_uckey {
	const isc_sockaddr_t *remote;
	const isc_sockaddr_t *local;
} dns__uckey_t;

struct dns_unreachcache {
	unsigned int magic;
	isc_mem_t *mctx;
	uint16_t expire_min_s;
	uint16_t expire_max_s;
	uint16_t backoff_eligible_s;
	struct cds_lfht *ht;
	struct cds_list_head *lru;
	uint32_t nloops;
};

#define UNREACHCACHE_MAGIC    ISC_MAGIC('U', 'R', 'C', 'a')
#define VALID_UNREACHCACHE(m) ISC_MAGIC_VALID(m, UNREACHCACHE_MAGIC)

#define UNREACHCACHE_INIT_SIZE (1 << 4) /* Must be power of 2 */
#define UNREACHCACHE_MIN_SIZE  (1 << 5) /* Must be power of 2 */

struct dns_ucentry {
	isc_loop_t *loop;
	isc_stdtime_t expire;
	unsigned int exp_backoff_n;
	uint16_t wait_time;
	bool confirmed;

	struct cds_lfht_node ht_node;
	struct rcu_head rcu_head;
	struct cds_list_head lru_head;

	isc_sockaddr_t remote;
	isc_sockaddr_t local;
};

static void
ucentry_destroy(struct rcu_head *rcu_head);

static bool
ucentry_alive(struct cds_lfht *ht, dns_ucentry_t *unreach, isc_stdtime_t now,
	      bool alive_or_waiting);

dns_unreachcache_t *
dns_unreachcache_new(isc_mem_t *mctx, const uint16_t expire_min_s,
		     const uint16_t expire_max_s,
		     const uint16_t backoff_eligible_s) {
	REQUIRE(expire_min_s > 0);
	REQUIRE(expire_min_s <= expire_max_s);

	uint32_t nloops = isc_loopmgr_nloops();
	dns_unreachcache_t *uc = isc_mem_get(mctx, sizeof(*uc));
	*uc = (dns_unreachcache_t){
		.magic = UNREACHCACHE_MAGIC,
		.expire_min_s = expire_min_s,
		.expire_max_s = expire_max_s,
		.backoff_eligible_s = backoff_eligible_s,
		.nloops = nloops,
	};

	uc->ht = cds_lfht_new(UNREACHCACHE_INIT_SIZE, UNREACHCACHE_MIN_SIZE, 0,
			      CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	INSIST(uc->ht != NULL);

	uc->lru = isc_mem_cget(mctx, uc->nloops, sizeof(uc->lru[0]));
	for (size_t i = 0; i < uc->nloops; i++) {
		CDS_INIT_LIST_HEAD(&uc->lru[i]);
	}

	isc_mem_attach(mctx, &uc->mctx);

	return uc;
}

void
dns_unreachcache_destroy(dns_unreachcache_t **ucp) {
	REQUIRE(ucp != NULL && *ucp != NULL);
	REQUIRE(VALID_UNREACHCACHE(*ucp));
	dns_unreachcache_t *uc = *ucp;
	*ucp = NULL;
	uc->magic = 0;

	dns_ucentry_t *unreach = NULL;
	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(uc->ht, &iter, unreach, ht_node) {
		INSIST(!cds_lfht_del(uc->ht, &unreach->ht_node));
		ucentry_destroy(&unreach->rcu_head);
	}
	RUNTIME_CHECK(!cds_lfht_destroy(uc->ht, NULL));

	isc_mem_cput(uc->mctx, uc->lru, uc->nloops, sizeof(uc->lru[0]));

	isc_mem_putanddetach(&uc->mctx, uc, sizeof(dns_unreachcache_t));
}

static int
ucentry_match(struct cds_lfht_node *ht_node, const void *key0) {
	const dns__uckey_t *key = key0;
	dns_ucentry_t *unreach = caa_container_of(ht_node, dns_ucentry_t,
						  ht_node);

	return isc_sockaddr_equal(&unreach->remote, key->remote) &&
	       isc_sockaddr_equal(&unreach->local, key->local);
}

static uint32_t
ucentry_hash(const dns__uckey_t *key) {
	return isc_sockaddr_hash(key->remote, false) ^
	       isc_sockaddr_hash(key->local, false);
}

static dns_ucentry_t *
ucentry_lookup(struct cds_lfht *ht, uint32_t hashval, dns__uckey_t *key) {
	struct cds_lfht_iter iter;

	cds_lfht_lookup(ht, hashval, ucentry_match, key, &iter);

	return cds_lfht_entry(cds_lfht_iter_get_node(&iter), dns_ucentry_t,
			      ht_node);
}

static dns_ucentry_t *
ucentry_new(isc_loop_t *loop, const isc_sockaddr_t *remote,
	    const isc_sockaddr_t *local, const isc_stdtime_t expire,
	    const isc_stdtime_t wait_time) {
	isc_mem_t *mctx = isc_loop_getmctx(loop);
	dns_ucentry_t *unreach = isc_mem_get(mctx, sizeof(*unreach));
	*unreach = (dns_ucentry_t){
		.remote = *remote,
		.local = *local,
		.expire = expire,
		.wait_time = wait_time,
		.loop = isc_loop_ref(loop),
		.lru_head = CDS_LIST_HEAD_INIT(unreach->lru_head),
	};

	return unreach;
}

static void
ucentry_destroy(struct rcu_head *rcu_head) {
	dns_ucentry_t *unreach = caa_container_of(rcu_head, dns_ucentry_t,
						  rcu_head);
	isc_loop_t *loop = unreach->loop;
	isc_mem_t *mctx = isc_loop_getmctx(loop);

	isc_mem_put(mctx, unreach, sizeof(*unreach));
	isc_loop_unref(loop);
}

static void
ucentry_evict_async(void *arg) {
	dns_ucentry_t *unreach = arg;

	RUNTIME_CHECK(unreach->loop == isc_loop());

	cds_list_del(&unreach->lru_head);
	call_rcu(&unreach->rcu_head, ucentry_destroy);
}

static void
ucentry_evict(struct cds_lfht *ht, dns_ucentry_t *unreach) {
	if (!cds_lfht_del(ht, &unreach->ht_node)) {
		if (unreach->loop == isc_loop()) {
			ucentry_evict_async(unreach);
			return;
		}
		isc_async_run(unreach->loop, ucentry_evict_async, unreach);
	}
}

static bool
ucentry_alive(struct cds_lfht *ht, dns_ucentry_t *unreach, isc_stdtime_t now,
	      bool alive_or_waiting) {
	if (cds_lfht_is_node_deleted(&unreach->ht_node)) {
		return false;
	} else if (unreach->expire < now) {
		bool is_waiting = unreach->expire + unreach->wait_time >= now;

		if (is_waiting) {
			/*
			 * Wait some minimum time before evicting an expired
			 * entry so we can support exponential backoff for
			 * nodes which enter again shortly after expiring.
			 *
			 * The return value depends on whether the caller is
			 * interested to know if the node is in either active or
			 * waiting state (i.e. not eviceted), or is interested
			 * only if it's still alive (i.e. not expired).
			 */
			return alive_or_waiting;
		}

		/* The entry is already expired, evict it before returning. */
		ucentry_evict(ht, unreach);
		return false;
	}

	return true;
}

static void
ucentry_purge(struct cds_lfht *ht, struct cds_list_head *lru,
	      isc_stdtime_t now) {
	size_t count = 10;
	dns_ucentry_t *unreach;
	cds_list_for_each_entry_rcu(unreach, lru, lru_head) {
		if (ucentry_alive(ht, unreach, now, true)) {
			break;
		}
		if (--count == 0) {
			break;
		}
	}
}

static void
ucentry_backoff(const dns_unreachcache_t *uc, const isc_stdtime_t now,
		dns_ucentry_t *new, const dns_ucentry_t *old) {
	/*
	 * Perform exponential backoff if this is an expired entry wating to be
	 * evicted. Otherwise it's a duplicate entry and no backoff is required
	 * as we will just update the cache with a new entry that has the same
	 * expiration time as the old one, but calculated freshly, based on the
	 * current time.
	 */
	if (old->expire < now) {
		new->exp_backoff_n = old->exp_backoff_n + 1;
	} else {
		new->exp_backoff_n = old->exp_backoff_n;
	}
	for (size_t i = 0; i < new->exp_backoff_n; i++) {
		new->expire += uc->expire_min_s;
		if (new->expire > now + uc->expire_max_s) {
			new->expire = now + uc->expire_max_s;
			break;
		}
	}
}

void
dns_unreachcache_add(dns_unreachcache_t *uc, const isc_sockaddr_t *remote,
		     const isc_sockaddr_t *local) {
	REQUIRE(VALID_UNREACHCACHE(uc));
	REQUIRE(remote != NULL);
	REQUIRE(local != NULL);

	isc_loop_t *loop = isc_loop();
	isc_tid_t tid = isc_tid();
	struct cds_list_head *lru = &uc->lru[tid];
	isc_stdtime_t now = isc_stdtime_now();
	isc_stdtime_t expire = now + uc->expire_min_s;
	bool exp_backoff_activated = false;

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(uc->ht);
	INSIST(ht != NULL);

	dns__uckey_t key = {
		.remote = remote,
		.local = local,
	};
	uint32_t hashval = ucentry_hash(&key);

	dns_ucentry_t *unreach = ucentry_new(loop, remote, local, expire,
					     uc->backoff_eligible_s);
	struct cds_lfht_node *ht_node;
	do {
		ht_node = cds_lfht_add_unique(ht, hashval, ucentry_match, &key,
					      &unreach->ht_node);
		if (ht_node != &unreach->ht_node) {
			/* The entry already exists, get it. */
			dns_ucentry_t *found = caa_container_of(
				ht_node, dns_ucentry_t, ht_node);

			/*
			 * Consider unreachability as confirmed only if
			 * an entry is submitted at least twice, i.e. there
			 * was an older entry (which is exactly this case).
			 */
			unreach->confirmed = true;

			/*
			 * Recalculate the expire time of the new entry based
			 * on the old entry's exponential backoff value.
			 */
			if (!exp_backoff_activated) {
				exp_backoff_activated = true;
				ucentry_backoff(uc, now, unreach, found);
			}

			/*
			 * Evict the old entry, so we can try to insert the new
			 * one again.
			 */
			ucentry_evict(ht, found);
		}
	} while (ht_node != &unreach->ht_node);

	/* No locking, instead we are using per-thread lists */
	cds_list_add_tail_rcu(&unreach->lru_head, lru);

	ucentry_purge(ht, lru, now);

	rcu_read_unlock();
}

isc_result_t
dns_unreachcache_find(dns_unreachcache_t *uc, const isc_sockaddr_t *remote,
		      const isc_sockaddr_t *local) {
	REQUIRE(VALID_UNREACHCACHE(uc));
	REQUIRE(remote != NULL);
	REQUIRE(local != NULL);

	isc_result_t result = ISC_R_NOTFOUND;
	isc_stdtime_t now = isc_stdtime_now();

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(uc->ht);
	INSIST(ht != NULL);

	dns__uckey_t key = {
		.remote = remote,
		.local = local,
	};
	uint32_t hashval = ucentry_hash(&key);

	dns_ucentry_t *found = ucentry_lookup(ht, hashval, &key);
	if (found != NULL && found->confirmed &&
	    ucentry_alive(ht, found, now, false))
	{
		result = ISC_R_SUCCESS;
	}

	isc_tid_t tid = isc_tid();
	struct cds_list_head *lru = &uc->lru[tid];
	ucentry_purge(ht, lru, now);

	rcu_read_unlock();

	return result;
}

void
dns_unreachcache_remove(dns_unreachcache_t *uc, const isc_sockaddr_t *remote,
			const isc_sockaddr_t *local) {
	REQUIRE(VALID_UNREACHCACHE(uc));
	REQUIRE(remote != NULL);
	REQUIRE(local != NULL);

	isc_stdtime_t now = isc_stdtime_now();

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(uc->ht);
	INSIST(ht != NULL);

	dns__uckey_t key = {
		.remote = remote,
		.local = local,
	};
	uint32_t hashval = ucentry_hash(&key);

	dns_ucentry_t *found = ucentry_lookup(ht, hashval, &key);
	if (found != NULL) {
		ucentry_evict(ht, found);
	}

	isc_tid_t tid = isc_tid();
	struct cds_list_head *lru = &uc->lru[tid];
	ucentry_purge(ht, lru, now);

	rcu_read_unlock();
}

void
dns_unreachcache_flush(dns_unreachcache_t *uc) {
	REQUIRE(VALID_UNREACHCACHE(uc));

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(uc->ht);
	INSIST(ht != NULL);

	/* Flush the hash table */
	dns_ucentry_t *unreach;
	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(ht, &iter, unreach, ht_node) {
		ucentry_evict(ht, unreach);
	}

	rcu_read_unlock();
}
