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

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/hash.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/spinlock.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/badcache.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/types.h>

typedef struct dns_bcentry dns_bcentry_t;

struct dns_badcache {
	unsigned int magic;
	isc_mem_t *mctx;
	struct cds_lfht *ht;
	atomic_bool purge_in_progress;
};

#define BADCACHE_MAGIC	  ISC_MAGIC('B', 'd', 'C', 'a')
#define VALID_BADCACHE(m) ISC_MAGIC_VALID(m, BADCACHE_MAGIC)

#define BADCACHE_INIT_SIZE (1 << 10) /* Must be power of 2 */
#define BADCACHE_MIN_SIZE  (1 << 8)  /* Must be power of 2 */

struct dns_bcentry {
	isc_mem_t *mctx;
	dns_rdatatype_t type;
	_Atomic(isc_stdtime_t) expire;
	atomic_uint_fast32_t flags;
	dns_fixedname_t fname;
	dns_name_t *name;

	struct cds_lfht_node ht_node;
	struct rcu_head rcu_head;
};

static void
bcentry_print(dns_bcentry_t *bad, isc_stdtime_t now, FILE *fp);

static void
bcentry_destroy(struct rcu_head *rcu_head);

dns_badcache_t *
dns_badcache_new(isc_mem_t *mctx) {
	REQUIRE(mctx != NULL);

	dns_badcache_t *bc = isc_mem_get(mctx, sizeof(*bc));
	*bc = (dns_badcache_t){
		.magic = BADCACHE_MAGIC,
	};

	bc->ht = cds_lfht_new(BADCACHE_INIT_SIZE, BADCACHE_MIN_SIZE, 0,
			      CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	INSIST(bc->ht != NULL);

	isc_mem_attach(mctx, &bc->mctx);

	return (bc);
}

void
dns_badcache_destroy(dns_badcache_t **bcp) {
	REQUIRE(bcp != NULL && *bcp != NULL);
	REQUIRE(VALID_BADCACHE(*bcp));

	dns_badcache_t *bc = *bcp;
	*bcp = NULL;
	bc->magic = 0;

	dns_bcentry_t *bad = NULL;
	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(bc->ht, &iter, bad, ht_node) {
		INSIST(!cds_lfht_del(bc->ht, &bad->ht_node));
		bcentry_destroy(&bad->rcu_head);
	}
	RUNTIME_CHECK(!cds_lfht_destroy(bc->ht, NULL));

	isc_mem_putanddetach(&bc->mctx, bc, sizeof(dns_badcache_t));
}

static int
bcentry_match(struct cds_lfht_node *ht_node, const void *key) {
	const dns_name_t *name = key;
	dns_bcentry_t *bad = caa_container_of(ht_node, dns_bcentry_t, ht_node);

	return (dns_name_equal(bad->name, name));
}

static dns_bcentry_t *
bcentry_new(dns_badcache_t *bc, const dns_name_t *name,
	    const dns_rdatatype_t type, const uint32_t flags,
	    const isc_stdtime_t expire) {
	dns_bcentry_t *bad = isc_mem_get(bc->mctx, sizeof(*bad));
	*bad = (dns_bcentry_t){
		.type = type,
		.flags = flags,
		.expire = expire,
	};
	isc_mem_attach(bc->mctx, &bad->mctx);

	bad->name = dns_fixedname_initname(&bad->fname);
	dns_name_copy(name, bad->name);

	return (bad);
}

static void
bcentry_destroy(struct rcu_head *rcu_head) {
	dns_bcentry_t *bad = caa_container_of(rcu_head, dns_bcentry_t,
					      rcu_head);

	isc_mem_putanddetach(&bad->mctx, bad, sizeof(*bad));
}

static void
bcentry_evict(struct cds_lfht *ht, dns_bcentry_t *bad) {
	/*
	 * The hashtable isn't locked in a traditional sense, so multiple
	 * threads can lookup and evict the same record at the same time.
	 *
	 * This is amplified by the bcentry_purge_next() that walks a few more
	 * records in the hashtable and evicts them if they are expired.
	 *
	 * We need to destroy the bcentry only once - from the thread that has
	 * deleted the entry from the hashtable, all other calls to this
	 * function were redundant.
	 */
	if (!cds_lfht_del(ht, &bad->ht_node)) {
		call_rcu(&bad->rcu_head, bcentry_destroy);
	}
}

static bool
bcentry_alive(struct cds_lfht *ht, dns_bcentry_t *bad, isc_stdtime_t now) {
	if (cds_lfht_is_node_deleted(&bad->ht_node)) {
		return (false);
	} else if (atomic_load_relaxed(&bad->expire) < now) {
		bcentry_evict(ht, bad);
		return (false);
	}

	return (true);
}

#define cds_lfht_for_each_entry_next(ht, iter, pos, member)     \
	for (cds_lfht_next(ht, iter),                           \
	     pos = cds_lfht_entry(cds_lfht_iter_get_node(iter), \
				  __typeof__(*(pos)), member);  \
	     pos != NULL; /**/                                  \
	     cds_lfht_next(ht, iter),                           \
	     pos = cds_lfht_entry(cds_lfht_iter_get_node(iter), \
				  __typeof__(*(pos)), member))

static void
bcentry_purge_next(struct cds_lfht *ht, struct cds_lfht_iter *iter,
		   isc_stdtime_t now) {
	/* Lazy-purge the table */
	size_t count = 10;
	dns_bcentry_t *bad;
	cds_lfht_for_each_entry_next(ht, iter, bad, ht_node) {
		if (!bcentry_alive(ht, bad, now)) {
			break;
		}
		if (--count == 0) {
			break;
		}
	}
}

void
dns_badcache_add(dns_badcache_t *bc, const dns_name_t *name,
		 dns_rdatatype_t type, bool update, uint32_t flags,
		 isc_stdtime_t expire) {
	REQUIRE(VALID_BADCACHE(bc));
	REQUIRE(name != NULL);

	isc_stdtime_t now = isc_stdtime_now();
	if (expire < now) {
		expire = now;
	}

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(bc->ht);
	INSIST(ht != NULL);

	dns_bcentry_t *bad = NULL;
	uint32_t hashval = dns_name_hash(name);

	struct cds_lfht_iter iter;
	dns_bcentry_t *found = NULL;
	cds_lfht_for_each_entry_duplicate(ht, hashval, bcentry_match, name,
					  &iter, bad, ht_node) {
		if (bcentry_alive(ht, bad, now) && bad->type == type) {
			found = bad;
			/*
			 * We could bail-out on first match, but:
			 * 1. there could be duplicate .type entries
			 * 2. we want to check expire for all entries
			 */
		}
	}

	if (found == NULL) {
		/*
		 * In theory, this could result in multiple entries for the same
		 * type, but we don't care much, as they are going to be roughly
		 * the same, and the last will always trump and the former
		 * entries will expire (see above).
		 */
		bad = bcentry_new(bc, name, type, flags, expire);
		cds_lfht_add(ht, hashval, &bad->ht_node);
	} else if (update) {
		atomic_store_relaxed(&found->expire, expire);
		atomic_store_relaxed(&found->flags, flags);
	}

	rcu_read_unlock();
}

isc_result_t
dns_badcache_find(dns_badcache_t *bc, const dns_name_t *name,
		  dns_rdatatype_t type, uint32_t *flagp, isc_stdtime_t now) {
	REQUIRE(VALID_BADCACHE(bc));
	REQUIRE(name != NULL);

	isc_result_t result = ISC_R_NOTFOUND;

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(bc->ht);
	INSIST(ht != NULL);

	dns_bcentry_t *bad = NULL;
	uint32_t hashval = dns_name_hash(name);

	struct cds_lfht_iter iter;
	dns_bcentry_t *found = NULL;
	cds_lfht_for_each_entry_duplicate(ht, hashval, bcentry_match, name,
					  &iter, bad, ht_node) {
		if (bad->type == type && bcentry_alive(ht, bad, now)) {
			found = bad;
		}
	}

	if (found) {
		result = ISC_R_SUCCESS;
		if (flagp != NULL) {
			*flagp = atomic_load_relaxed(&found->flags);
		}

		bcentry_purge_next(ht, &iter, now);
	}

	rcu_read_unlock();

	return (result);
}

void
dns_badcache_flush(dns_badcache_t *bc) {
	REQUIRE(VALID_BADCACHE(bc));

	struct cds_lfht *ht =
		cds_lfht_new(BADCACHE_INIT_SIZE, BADCACHE_MIN_SIZE, 0,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	INSIST(ht != NULL);

	/* First swap the hashtables */
	rcu_read_lock();
	ht = rcu_xchg_pointer(&bc->ht, ht);
	rcu_read_unlock();

	/* Make sure nobody is using the old hash table */
	synchronize_rcu();

	/* Flush the old hash table */
	dns_bcentry_t *bad = NULL;
	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(ht, &iter, bad, ht_node) {
		INSIST(!cds_lfht_del(ht, &bad->ht_node));
		bcentry_destroy(&bad->rcu_head);
	}
	RUNTIME_CHECK(!cds_lfht_destroy(ht, NULL));
}

void
dns_badcache_flushname(dns_badcache_t *bc, const dns_name_t *name) {
	REQUIRE(VALID_BADCACHE(bc));
	REQUIRE(name != NULL);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(bc->ht);
	INSIST(ht != NULL);

	dns_bcentry_t *bad = NULL;
	uint32_t hashval = dns_name_hash(name);

	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry_duplicate(ht, hashval, bcentry_match, name,
					  &iter, bad, ht_node) {
		bcentry_evict(ht, bad);
	}

	rcu_read_unlock();
}

void
dns_badcache_flushtree(dns_badcache_t *bc, const dns_name_t *name) {
	dns_bcentry_t *bad;
	isc_stdtime_t now = isc_stdtime_now();

	REQUIRE(VALID_BADCACHE(bc));
	REQUIRE(name != NULL);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(bc->ht);
	INSIST(ht != NULL);

	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(ht, &iter, bad, ht_node) {
		if (dns_name_issubdomain(bad->name, name)) {
			bcentry_evict(ht, bad);
		} else if (!bcentry_alive(ht, bad, now)) {
			/* Flush all the expired entries */
		}
	}

	rcu_read_unlock();
}

static void
bcentry_print(dns_bcentry_t *bad, isc_stdtime_t now, FILE *fp) {
	char namebuf[DNS_NAME_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];

	dns_name_format(bad->name, namebuf, sizeof(namebuf));
	dns_rdatatype_format(bad->type, typebuf, sizeof(typebuf));
	fprintf(fp, "; %s/%s [ttl %" PRIu32 "]\n", namebuf, typebuf,
		atomic_load_relaxed(&bad->expire) - now);
}

void
dns_badcache_print(dns_badcache_t *bc, const char *cachename, FILE *fp) {
	dns_bcentry_t *bad;
	isc_stdtime_t now = isc_stdtime_now();

	REQUIRE(VALID_BADCACHE(bc));
	REQUIRE(fp != NULL);

	fprintf(fp, ";\n; %s\n;\n", cachename);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(bc->ht);
	INSIST(ht != NULL);

	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(ht, &iter, bad, ht_node) {
		if (bcentry_alive(ht, bad, now)) {
			bcentry_print(bad, now, fp);
		}
	}

	rcu_read_unlock();
}
