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

#pragma once

/*
 * A qp-trie is a kind of key -> value map, supporting lookups that are
 * aware of the lexicographic order of keys.
 *
 * Keys are `dns_qpkey_t`, which is a string-like thing, usually created
 * from a DNS name. You can use both relative and absolute DNS names as
 * keys.
 *
 * Leaf values are a pair of a `void *` pointer and a `uint32_t`
 * (because that is what fits inside an internal qp-trie leaf node).
 *
 * The trie does not store keys; instead keys are derived from leaf values
 * by calling a method provided by the user.
 *
 * There are a few flavours of qp-trie.
 *
 * The basic `dns_qp_t` supports single-threaded read/write access.
 *
 * A `dns_qpmulti_t` is a wrapper that supports multithreaded access.
 * There can be many concurrent readers and a single writer. Writes are
 * transactional, and support multi-version concurrency.
 *
 * The concurrency strategy uses copy-on-write. When making changes during
 * a transaction, the caller must not modify leaf values in place, but
 * instead delete the old leaf from the trie and insert a replacement. Leaf
 * values have reference counts, which will indicate when the old leaf
 * value can be freed after it is no longer needed by readers using an old
 * version of the trie.
 *
 * For fast concurrent reads, call `dns_qpmulti_query()` to get a
 * `dns_qpread_t`. Readers can access a single version of the trie between
 * write commits. Most write activity is not blocked by readers, but reads
 * must finish before a write can commit (a read-write lock blocks
 * commits).
 *
 * For long-running reads that need a stable view of the trie, while still
 * allow commits to proceed, call `dns_qpmulti_snapshot()` to get a
 * `dns_qpsnap_t`. It briefly gets the write mutex while creating the
 * snapshot, which requires allocating a copy of some of the trie's
 * metadata. A snapshot is for relatively heavy long-running read-only
 * operations such as zone transfers.
 *
 * While snapshots exist, a qp-trie cannot reclaim memory: it does not
 * retain detailed information about which memory is used by which
 * snapshots, so it pessimistically retains all memory that might be
 * used by old versions of the trie.
 *
 * You can start one read-write transaction at a time using
 * `dns_qpmulti_write()` or `dns_qpmulti_update()`. Either way, you
 * get a `dns_qp_t` that can be modified like a single-threaded trie,
 * without affecting other read-only query or snapshot users of the
 * `dns_qpmulti_t`. Committing a transaction only blocks readers
 * briefly when flipping the active readonly `dns_qp_t` pointer.
 *
 * "Update" transactions are heavyweight. They allocate working memory to
 * hold modifications to the trie, and compact the trie before committing.
 * For extra space savings, a partially-used allocation chunk is shrunk to
 * the smallest size possible. Unlike "write" transactions, an "update"
 * transaction can be rolled back instead of committed. (Update
 * transactions are intended for things like authoritative zones, where it
 * is important to keep the per-trie memory overhead low because there can
 * be a very large number of them.)
 *
 * "Write" transactions are more lightweight: they skip the allocation and
 * compaction at the start and end of the transaction. (Write transactions
 * are intended for frequent small changes, as in the DNS cache.)
 */

/***********************************************************************
 *
 *  types
 */

#include <isc/attributes.h>

#include <dns/types.h>

/*%
 * A `dns_qp_t` supports single-threaded read/write access.
 */
typedef struct dns_qp dns_qp_t;

/*%
 * A `dns_qpmulti_t` supports multi-version concurrent reads and transactional
 * modification.
 */
typedef struct dns_qpmulti dns_qpmulti_t;

/*%
 * A `dns_qpread_t` is a lightweight read-only handle on a `dns_qpmulti_t`.
 */
typedef struct dns_qpread dns_qpread_t;

/*%
 * A `dns_qpsnap_t` is a heavier read-only snapshot of a `dns_qpmulti_t`.
 */
typedef struct dns_qpsnap dns_qpsnap_t;

/*
 * The read-only qp-trie functions can work on either of the read-only
 * qp-trie types or the general-purpose read-write `dns_qp_t`. They
 * relies on the fact that all the `dns_qpreadable_t` structures start
 * with a `dns_qpread_t`.
 */
typedef union dns_qpreadable {
	dns_qpread_t *qpr;
	dns_qpsnap_t *qps;
	dns_qp_t     *qpt;
} dns_qpreadable_t __attribute__((__transparent_union__));

#define dns_qpreadable_cast(qp) ((qp).qpr)

/*%
 * A trie lookup key is a small array, allocated on the stack during trie
 * searches. Keys are usually created on demand from DNS names using
 * `dns_qpkey_fromname()`, but in principle you can define your own
 * functions to convert other types to trie lookup keys.
 *
 * A domain name can be up to 255 bytes. When converted to a key, each
 * character in the name corresponds to one byte in the key if it is a
 * common hostname character; otherwise unusual characters are escaped,
 * using two bytes in the key. So we allow keys to be up to 512 bytes.
 * (The actual max is (255 - 5) * 2 + 6 == 506)
 *
 * Every byte of a key must be greater than 0 and less than 48. Elements
 * after the end of the key are treated as having the value 1.
 */
typedef uint8_t dns_qpkey_t[512];

/*%
 * These leaf methods allow the qp-trie code to call back to the code
 * responsible for the leaf values that are stored in the trie. The
 * methods are provided for a whole trie when the trie is created.
 *
 * The qp-trie is also given a context pointer that is passed to the
 * methods, so the methods know about the trie's context as well as a
 * particular leaf value.
 *
 * The `attach` and `detach` methods adjust reference counts on value
 * objects. They support copy-on-write and safe memory reclamation
 * needed for multi-version concurrency.
 *
 * Note: When a value object reference count is greater than one, the
 * object is in use by concurrent readers so it must not be modified. A
 * refcount equal to one does not indicate whether or not the object is
 * mutable: its refcount can be 1 while it is only in use by readers (and
 * must be left unchanged), or newly created by a writer (and therefore
 * mutable).
 *
 * The `makekey` method fills in a `dns_qpkey_t` corresponding to a
 * value object stored in the qp-trie. It returns the length of the
 * key. This method will typically call dns_qpkey_fromname() with a
 * name stored in the value object.
 *
 * For logging and tracing, the `triename` method copies a human-
 * readable identifier into `buf` which has max length `size`.
 */
typedef struct dns_qpmethods {
	void (*attach)(void *ctx, void *pval, uint32_t ival);
	void (*detach)(void *ctx, void *pval, uint32_t ival);
	size_t (*makekey)(dns_qpkey_t key, void *ctx, void *pval,
			  uint32_t ival);
	void (*triename)(void *ctx, char *buf, size_t size);
} dns_qpmethods_t;

/*%
 * Buffers for use by the `triename()` method need to be large enough
 * to hold a zone name and a few descriptive words.
 */
#define DNS_QP_TRIENAME_MAX 300

/*%
 * A container for the counters returned by `dns_qp_memusage()`
 */
typedef struct dns_qp_memusage {
	void  *ctx;	    /*%< qp-trie method context */
	size_t leaves;	    /*%< values in the trie */
	size_t live;	    /*%< nodes in use */
	size_t used;	    /*%< allocated nodes */
	size_t hold;	    /*%< nodes retained for readers */
	size_t free;	    /*%< nodes to be reclaimed */
	size_t node_size;   /*%< in bytes */
	size_t chunk_size;  /*%< nodes per chunk */
	size_t chunk_count; /*%< allocated chunks */
	size_t bytes;	    /*%< total memory in chunks and metadata */
} dns_qp_memusage_t;

/***********************************************************************
 *
 *  functions - create, destory, enquire
 */

void
dns_qp_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *ctx,
	      dns_qp_t **qptp);
/*%<
 * Create a single-threaded qp-trie.
 *
 * Requires:
 * \li  `mctx` is a pointer to a valid memory context.
 * \li  all the methods are non-NULL
 * \li  `qptp != NULL && *qptp == NULL`
 *
 * Ensures:
 * \li  `*qptp` is a pointer to a valid single-threaded qp-trie
 */

void
dns_qp_destroy(dns_qp_t **qptp);
/*%<
 * Destroy a single-threaded qp-trie.
 *
 * Requires:
 * \li  `qptp != NULL`
 * \li  `*qptp` is a pointer to a valid single-threaded qp-trie
 *
 * Ensures:
 * \li  all memory allocated by the qp-trie has been released
 * \li  `*qptp` is NULL
 */

void
dns_qpmulti_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *ctx,
		   dns_qpmulti_t **qpmp);
/*%<
 * Create a multi-threaded qp-trie.
 *
 * Requires:
 * \li  `mctx` is a pointer to a valid memory context.
 * \li  all the methods are non-NULL
 * \li  `qpmp != NULL && *qpmp == NULL`
 *
 * Ensures:
 * \li  `*qpmp` is a pointer to a valid multi-threaded qp-trie
 */

void
dns_qpmulti_destroy(dns_qpmulti_t **qpmp);
/*%<
 * Destroy a multi-threaded qp-trie.
 *
 * Requires:
 * \li  `qptp != NULL`
 * \li  `*qptp` is a pointer to a valid multi-threaded qp-trie
 * \li  there are no write or update transactions in progress
 * \li  no snapshots exist
 *
 * Ensures:
 * \li  all memory allocated by the qp-trie has been released
 * \li  `*qpmp` is NULL
 */

void
dns_qp_compact(dns_qp_t *qp);
/*%<
 * Defragment the entire qp-trie and release unused memory.
 *
 * When modifications make a trie too fragmented, it is automatically
 * compacted. Automatic compaction avoids compacting chunks that are not
 * fragmented to save time, but this function compacts the entire trie to
 * defragment it as much as possible.
 *
 * This function can be used with a single-threaded qp-trie and during a
 * transaction on a multi-threaded trie.
 *
 * Requires:
 * \li  `qp` is a pointer to a valid qp-trie
 */

void
dns_qp_gctime(uint64_t *compact_us, uint64_t *recover_us,
	      uint64_t *rollback_us);
/*%<
 * Get the total times spent on garbage collection in microseconds.
 *
 * These counters are global, covering every qp-trie in the program.
 *
 * XXXFANF This is a placeholder until we can record times in histograms.
 */

dns_qp_memusage_t
dns_qp_memusage(dns_qp_t *qp);
/*%<
 * Get the memory counters from a qp-trie
 *
 * Requires:
 * \li  `qp` is a pointer to a valid qp-trie
 *
 * Returns:
 * \li  a `dns_qp_memusage_t` structure described above
 */

/***********************************************************************
 *
 *  functions - search, modify
 */

/*
 * XXXFANF todo, based on what we discover BIND needs
 *
 * fancy searches: longest match, lexicographic predecessor,
 * etc.
 *
 * do we need specific lookup functions to find out if the
 * returned value is readonly or mutable?
 *
 * richer modification such as dns_qp_replace{key,name}
 *
 * iteration - probably best to put an explicit stack in the iterator,
 * cf. rbtnodechain
 */

size_t
dns_qpkey_fromname(dns_qpkey_t key, const dns_name_t *name);
/*%<
 * Convert a DNS name into a trie lookup key.
 *
 * Requires:
 * \li  `name` is a pointer to a valid `dns_name_t`
 *
 * Returns:
 * \li  the length of the key
 */

isc_result_t
dns_qp_getkey(dns_qpreadable_t qpr, const dns_qpkey_t searchk, size_t searchl,
	      void **pval_r, uint32_t *ival_r);
/*%<
 * Find a leaf in a qp-trie that matches the given key
 *
 * The leaf values are assigned to `*pval_r` and `*ival_r`
 *
 * Requires:
 * \li  `qpr` is a pointer to a readable qp-trie
 * \li  `pval_r != NULL`
 * \li  `ival_r != NULL`
 *
 * Returns:
 * \li  ISC_R_NOTFOUND if the trie has no leaf with a matching key
 * \li  ISC_R_SUCCESS if the leaf was found
 */

isc_result_t
dns_qp_getname(dns_qpreadable_t qpr, const dns_name_t *name, void **pval_r,
	       uint32_t *ival_r);
/*%<
 * Find a leaf in a qp-trie that matches the given DNS name
 *
 * The leaf values are assigned to `*pval_r` and `*ival_r`
 *
 * Requires:
 * \li  `qpr` is a pointer to a readable qp-trie
 * \li  `name` is a pointer to a valid `dns_name_t`
 * \li  `pval_r != NULL`
 * \li  `ival_r != NULL`
 *
 * Returns:
 * \li  ISC_R_NOTFOUND if the trie has no leaf with a matching key
 * \li  ISC_R_SUCCESS if the leaf was found
 */

isc_result_t
dns_qp_insert(dns_qp_t *qp, void *pval, uint32_t ival);
/*%<
 * Insert a leaf into a qp-trie
 *
 * Requires:
 * \li  `qp` is a pointer to a valid qp-trie
 * \li  `pval != NULL`
 * \li  `alignof(pval) > 1`
 *
 * Returns:
 * \li  ISC_R_EXISTS if the trie already has a leaf with the same key
 * \li  ISC_R_SUCCESS if the leaf was added to the trie
 */

isc_result_t
dns_qp_deletekey(dns_qp_t *qp, const dns_qpkey_t key, size_t len);
/*%<
 * Delete a leaf from a qp-trie that matches the given key
 *
 * Requires:
 * \li  `qp` is a pointer to a valid qp-trie
 *
 * Returns:
 * \li  ISC_R_NOTFOUND if the trie has no leaf with a matching key
 * \li  ISC_R_SUCCESS if the leaf was deleted from the trie
 */

isc_result_t
dns_qp_deletename(dns_qp_t *qp, const dns_name_t *name);
/*%<
 * Delete a leaf from a qp-trie that matches the given DNS name
 *
 * Requires:
 * \li  `qp` is a pointer to a valid qp-trie
 * \li  `name` is a pointer to a valid qp-trie
 *
 * Returns:
 * \li  ISC_R_NOTFOUND if the trie has no leaf with a matching name
 * \li  ISC_R_SUCCESS if the leaf was deleted from the trie
 */

/***********************************************************************
 *
 *  functions - transactions
 */

void
dns_qpmulti_query(dns_qpmulti_t *multi, dns_qpread_t **qprp);
/*%<
 * Start a lightweight (brief) read-only transaction
 *
 * This takes a read lock on `multi`s rwlock that prevents
 * transactions from committing.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qprp != NULL`
 * \li  `*qprp == NULL`
 *
 * Returns:
 * \li  `*qprp` is a pointer to a valid read-only qp-trie handle
 */

void
dns_qpread_destroy(dns_qpmulti_t *multi, dns_qpread_t **qprp);
/*%<
 * End a lightweight read transaction, i.e. release read lock
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qprp != NULL`
 * \li  `*qprp` is a read-only qp-trie handle obtained from `multi`
 *
 * Returns:
 * \li  `*qprp == NULL`
 */

void
dns_qpmulti_snapshot(dns_qpmulti_t *multi, dns_qpsnap_t **qpsp);
/*%<
 * Start a heavyweight (long) read-only transaction
 *
 * This function briefly takes and releases the modification mutex
 * while allocating a copy of the trie's metadata. While the snapshot
 * exists it does not interfere with other read-only or read-write
 * transactions on the trie, except that memory cannot be reclaimed.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qpsp != NULL`
 * \li  `*qpsp == NULL`
 *
 * Returns:
 * \li  `*qpsp` is a pointer to a snapshot obtained from `multi`
 */

void
dns_qpsnap_destroy(dns_qpmulti_t *multi, dns_qpsnap_t **qpsp);
/*%<
 * End a heavyweight read transaction
 *
 * If this is the last remaining snapshot belonging to `multi` then
 * this function takes the modification mutex in order to free() any
 * memory that is no longer in use.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qpsp != NULL`
 * \li  `*qpsp` is a pointer to a snapshot obtained from `multi`
 *
 * Returns:
 * \li  `*qpsp == NULL`
 */

void
dns_qpmulti_update(dns_qpmulti_t *multi, dns_qp_t **qptp);
/*%<
 * Start a heavyweight write transaction
 *
 * This style of transaction allocates a copy of the trie's metadata to
 * support rollback, and it aims to minimize the memory usage of the
 * trie between transactions. The trie is compacted when the transaction
 * commits, and any partly-used chunk is shrunk to fit.
 *
 * During the transaction, the modification mutex is held.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qptp != NULL`
 * \li  `*qptp == NULL`
 *
 * Returns:
 * \li  `*qptp` is a pointer to the modifiable qp-trie inside `multi`
 */

void
dns_qpmulti_write(dns_qpmulti_t *multi, dns_qp_t **qptp);
/*%<
 * Start a lightweight write transaction
 *
 * This style of transaction does not need extra allocations in addition
 * to the ones required by insert and delete operations. It is intended
 * for a large trie that gets frequent small writes, such as a DNS
 * cache.
 *
 * During the transaction, the modification mutex is held.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qptp != NULL`
 * \li  `*qptp == NULL`
 *
 * Returns:
 * \li  `*qptp` is a pointer to the modifiable qp-trie inside `multi`
 */

void
dns_qpmulti_commit(dns_qpmulti_t *multi, dns_qp_t **qptp);
/*%<
 * Complete a modification transaction
 *
 * The commit itself only requires flipping the read pointer inside
 * `multi` from the old version of the trie to the new version. This
 * function takes a write lock on `multi`s rwlock just long enough to
 * flip the pointer. This briefly blocks `query` readers.
 *
 * This function releases the modification mutex after the post-commit
 * memory reclamation is completed.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qptp != NULL`
 * \li  `*qptp` is a pointer to the modifiable qp-trie inside `multi`
 *
 * Returns:
 * \li  `*qptp == NULL`
 */

void
dns_qpmulti_rollback(dns_qpmulti_t *multi, dns_qp_t **qptp);
/*%<
 * Abandon an update transaction
 *
 * This function reclaims the memory allocated during the transaction
 * and releases the modification mutex.
 *
 * Requires:
 * \li  `multi` is a pointer to a valid multi-threaded qp-trie
 * \li  `qptp != NULL`
 * \li  `*qptp` is a pointer to the modifiable qp-trie inside `multi`
 * \li  `*qptp` was obtained from `dns_qpmulti_update()`
 *
 * Returns:
 * \li  `*qptp == NULL`
 */

/**********************************************************************/
