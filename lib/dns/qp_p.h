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

/*
 * For an overview, see doc/design/qp-trie.md
 *
 * This private header defines the internal data structures,
 */

#pragma once

/***********************************************************************
 *
 *  interior node basics
 */

/*
 * A qp-trie node is normally either a branch or a leaf. It consists of
 * three 32-bit words into which the components are packed. They are used
 * as a 64-bit word and a 32-bit word, but they are not declared like that
 * to avoid unwanted padding, keeping the size down to 12 bytes. They are
 * in native endian order so getting the 64-bit part should compile down to
 * an unaligned load.
 *
 * The type of node is identified by the tag in the least significant bits
 * of the 64-bit word.
 *
 * In a branch the 64-bit word is described by the enum below. The 32-bit
 * word is a reference to the packed sparse vector of "twigs", i.e. child
 * nodes. A branch node has at least 2 and less than SHIFT_OFFSET twigs
 * (see the enum below). The qp-trie update functions ensure that branches
 * actually branch, i.e. branches cannot have only 1 child.
 *
 * The contents of each leaf are set by the trie's user. The 64-bit word
 * contains a pointer value (which must be word-aligned, so the tag bits
 * are zero), and the 32-bit word is an arbitrary integer value.
 *
 * There is a third kind of node, reader nodes, which anchor the root of a
 * trie. A pair of reader nodes together contain a packed `dns_qpreader_t`.
 * See the section on "packed reader nodes" below.
 */
typedef struct qp_node {
#if WORDS_BIGENDIAN
	uint32_t bighi, biglo, small;
#else
	uint32_t biglo, bighi, small;
#endif
} qp_node_t;

/*
 * The possible values of the node type tag. Type tags must fit in two bits
 * for compatibility with 4-byte pointer alignment on 32-bit systems.
 */
enum {
	LEAF_TAG = 0,	/* leaf node */
	BRANCH_TAG = 1, /* branch node */
	READER_TAG = 2, /* reader node */
	TAG_MASK = 3,	/* mask covering tag bits */
};

/*
 * This code does not work on CPUs with large pointers, e.g. CHERI capability
 * architectures. When porting to that kind of machine, a `dns_qpnode` should
 * be just a `uintptr_t`; a leaf node will contain a single pointer, and a
 * branch node will fit in the same space with room to spare.
 */
STATIC_ASSERT(sizeof(void *) <= sizeof(uint64_t),
	      "pointers must fit in 64 bits");

/*
 * A branch node contains a 64-bit word comprising the type tag, the
 * bitmap, and an offset into the key. It is called an "index word" because
 * it describes how to access the twigs vector (think "database index").
 * The following enum sets up the bit positions of these parts.
 *
 * In a leaf, the same 64-bit word contains a pointer. The pointer
 * must be word-aligned so that the branch/leaf tag bit is zero.
 * This requirement is checked by the newleaf() constructor.
 *
 * The bitmap is just above the type tag. The `bits_for_byte[]` table is
 * used to fill in a key so that bit tests can work directly against the
 * index word without superfluous masking or shifting; we don't need to
 * mask out the bitmap before testing a bit, but we do need to mask the
 * bitmap before calling popcount.
 *
 * The byte offset into the key is at the top of the word, so that it
 * can be extracted with just a shift, with no masking needed.
 *
 * The names are SHIFT_thing because they are qp_shift_t values. (See
 * below for the various `qp_*` type declarations.)
 *
 * These values are relatively fixed in practice: SHIFT_NOBYTE needs
 * to leave space for the type tag, and the implementation of
 * `dns_qpkey_fromname()` depends on the bitmap being large enough.
 * The symbolic names avoid mystery numbers in the code.
 */
enum {
	SHIFT_NOBYTE = 2,  /* label separator has no byte value */
	SHIFT_BITMAP,	   /* many bits here */
	SHIFT_OFFSET = 49, /* offset of byte in key */
};

/***********************************************************************
 *
 *  garbage collector tuning parameters
 */

/*
 * A "cell" is a location that can contain a `qp_node_t`, and a "chunk"
 * is a moderately large array of cells. A big trie can occupy
 * multiple chunks. (Unlike other nodes, a trie's root node lives in
 * its `struct dns_qp` instead of being allocated in a cell.)
 *
 * The qp-trie allocator hands out space for twigs vectors. Allocations are
 * made sequentially from one of the chunks; this kind of "sequential
 * allocator" is also known as a "bump allocator", so in `struct dns_qp`
 * (see below) the allocation chunk is called `bump`.
 */

/*
 * Number of cells in a chunk is a power of 2, which must have space for
 * a full twigs vector (48 wide). When testing, use a much smaller chunk
 * size to make the allocator work harder.
 */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define QP_CHUNK_LOG 7
#else
#define QP_CHUNK_LOG 10
#endif

STATIC_ASSERT(6 <= QP_CHUNK_LOG && QP_CHUNK_LOG <= 20,
	      "qp-trie chunk size is unreasonable");

#define QP_CHUNK_SIZE  (1U << QP_CHUNK_LOG)
#define QP_CHUNK_BYTES (QP_CHUNK_SIZE * sizeof(qp_node_t))

/*
 * We need a bitfield this big to count how much of a chunk is in use:
 * it needs to count from 0 up to and including `1 << QP_CHUNK_LOG`.
 */
#define QP_USAGE_BITS (QP_CHUNK_LOG + 1)

/*
 * A chunk needs to be compacted if it is less full than this threshold.
 * (12% overhead seems reasonable)
 */
#define QP_MAX_FREE (QP_CHUNK_SIZE / 8)
#define QP_MIN_USED (QP_CHUNK_SIZE - QP_MAX_FREE)

/*
 * Compact automatically when we pass this threshold: when there is a lot
 * of free space in absolute terms, and when we have freed more than half
 * of the space we allocated.
 *
 * The current compaction algorithm scans the whole trie, so it is important
 * to scale the threshold based on the size of the trie to avoid quadratic
 * behaviour. XXXFANF find an algorithm that scans less of the trie!
 *
 * During a modification transaction, when we copy-on-write some twigs we
 * count the old copy as "free", because they will be when the transaction
 * commits. But they cannot be recovered immediately so they are also
 * counted as on hold, and discounted when we decide whether to compact.
 */
#define QP_GC_HEURISTIC(qp, free) \
	((free) > QP_CHUNK_SIZE * 4 && (free) > (qp)->used_count / 2)

#define QP_NEEDGC(qp) QP_GC_HEURISTIC(qp, (qp)->free_count)
#define QP_AUTOGC(qp) QP_GC_HEURISTIC(qp, (qp)->free_count - (qp)->hold_count)

/*
 * The chunk base and usage arrays are resized geometically and start off
 * with two entries.
 */
#define GROWTH_FACTOR(size) ((size) + (size) / 2 + 2)

/***********************************************************************
 *
 *  helper types
 */

/*
 * C is not strict enough with its integer types for these typedefs to
 * improve type safety, but it helps to have annotations saying what
 * particular kind of number we are dealing with.
 */

/*
 * The number or position of a bit inside a word. (0..63)
 *
 * Note: A dns_qpkey_t is logically an array of qp_shift_t values, but it
 * isn't declared that way because dns_qpkey_t is a public type whereas
 * qp_shift_t is private.
 *
 * A dns_qpkey element key[off] must satisfy
 *
 *	SHIFT_NOBYTE <= key[off] && key[off] < SHIFT_OFFSET
 */
typedef uint8_t qp_shift_t;

/*
 * The number of bits set in a word (as in Hamming weight or popcount)
 * which is used for the position of a node in the packed sparse
 * vector of twigs. (0..47) because our bitmap does not fill the word.
 */
typedef uint8_t qp_weight_t;

/*
 * A chunk number, i.e. an index into the chunk arrays.
 */
typedef uint32_t qp_chunk_t;

/*
 * Cell offset within a chunk, or a count of cells. Each cell in a
 * chunk can contain a node.
 */
typedef uint32_t qp_cell_t;

/*
 * A twig reference is used to refer to a twigs vector, which occupies a
 * contiguous group of cells.
 */
typedef uint32_t qp_ref_t;

/*
 * Constructors and accessors for qp_ref_t values, defined here to show
 * how the qp_ref_t, qp_chunk_t, qp_cell_t types relate to each other
 */

static inline qp_ref_t
make_ref(qp_chunk_t chunk, qp_cell_t cell) {
	return (QP_CHUNK_SIZE * chunk + cell);
}

static inline qp_chunk_t
ref_chunk(qp_ref_t ref) {
	return (ref / QP_CHUNK_SIZE);
}

static inline qp_cell_t
ref_cell(qp_ref_t ref) {
	return (ref % QP_CHUNK_SIZE);
}

/*
 * We should not use the `root_ref` in an empty trie, so we set it
 * to a value that should trigger an obvious bug. See qp_init()
 * and get_root() below.
 */
#define INVALID_REF ((qp_ref_t)~0UL)

/***********************************************************************
 *
 *  chunk arrays
 */

/*
 * A `dns_qp_t` contains two arrays holding information about each chunk.
 *
 * The `base` array holds pointers to the base of each chunk.
 * The `usage` array hold the allocator's state for each chunk.
 *
 * The `base` array is used by the hot qp-trie traversal paths. It can
 * be shared by multiple versions of a trie, which are tracked with a
 * refcount. Old versions of the trie can retain old versions of the
 * `base` array.
 *
 * In multithreaded code, the `usage` array is only used when the
 * `dns_qpmulti_t` mutex is held, and there is only one version of
 * it in active use (maybe with a snapshot for rollback support).
 *
 * The two arrays are separate because they have rather different
 * access patterns, different lifetimes, and different element sizes.
 */

/*
 * For most purposes we don't need to know exactly which cells are
 * in use in a chunk, we only need to know how many of them there are.
 *
 * After we have finished allocating from a chunk, the `used` counter
 * is the size we need to know for shrinking the chunk and for
 * scanning it to detach leaf values before the chunk is free()d. The
 * `free` counter tells us when the chunk needs compacting and when it
 * has become empty.
 *
 * The `exists` flag allows the chunk scanning loops to look at the
 * usage array only.
 *
 * In multithreaded code, we mark chunks as `immutable` when a modify
 * transaction is opened. (We don't mark them immutable on commit,
 * because the old bump chunk must remain mutable between write
 * transactions, but it must become immutable when an update
 * transaction is opened.)
 *
 * There are a few flags used to mark which chunks are still needed by
 * snapshots after the chunks have passed their normal reclamation
 * phase.
 */
typedef struct qp_usage {
	/*% the allocation point, increases monotonically */
	qp_cell_t used : QP_USAGE_BITS;
	/*% count of nodes no longer needed, also monotonic */
	qp_cell_t free : QP_USAGE_BITS;
	/*% qp->base->ptr[chunk] != NULL */
	bool exists : 1;
	/*% is this chunk shared? [MT] */
	bool immutable : 1;
	/*% already subtracted from multi->*_count [MT] */
	bool discounted : 1;
	/*% is a snapshot using this chunk? [MT] */
	bool snapshot : 1;
	/*% tried to free it but a snapshot needs it [MT] */
	bool snapfree : 1;
	/*% for mark/sweep snapshot flag updates [MT] */
	bool snapmark : 1;
} qp_usage_t;

/*
 * The chunks are owned by the current version of the `base` array.
 * When the array is resized, the old version might still be in use by
 * concurrent readers, in which case it is free()d later when its
 * refcount drops to zero.
 *
 * A `dns_qpbase_t` counts references from `dns_qp_t` objects and
 * from packed readers, but not from `dns_qpread_t` nor from
 * `dns_qpsnap_t` objects. Refcount adjustments for `dns_qpread_t`
 * would wreck multicore scalability; instead we rely on RCU.
 *
 * The `usage` array determines when a chunk is no longer needed: old
 * chunk pointers in old `base` arrays are ignored. (They can become
 * dangling pointers to free memory, but they will never be
 * dereferenced.)
 *
 * We ensure that individual chunk base pointers remain immutable
 * after assignment, and they are not cleared until the chunk is
 * free()d, after all readers have departed. Slots can be reused, and
 * we allow transactions to fill or re-fill empty slots adjacent to
 * busy slots that are in use by readers.
 */
struct dns_qpbase {
	unsigned int magic;
	isc_refcount_t refcount;
	qp_node_t *ptr[];
};

/*
 * Chunks that may be in use by readers are reclaimed asynchronously.
 * When a transaction commits, immutable chunks that are now empty are
 * listed in a `qp_rcuctx_t` structure and passed to `call_rcu()`.
 */
typedef struct qp_rcuctx {
	unsigned int magic;
	struct rcu_head rcu_head;
	isc_mem_t *mctx;
	dns_qpmulti_t *multi;
	qp_chunk_t count;
	qp_chunk_t chunk[];
} qp_rcuctx_t;

/*
 * Returns true when the base array can be free()d.
 */
static inline bool
qpbase_unref(dns_qpreadable_t qpr) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	return (qp->base != NULL &&
		isc_refcount_decrement(&qp->base->refcount) == 1);
}

/*
 * Now we know about `dns_qpreader_t` and `dns_qpbase_t`,
 * here's how we convert a twig reference into a pointer.
 */
static inline qp_node_t *
ref_ptr(dns_qpreadable_t qpr, qp_ref_t ref) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	return (qp->base->ptr[ref_chunk(ref)] + ref_cell(ref));
}

/***********************************************************************
 *
 *  main qp-trie structures
 */

#define QP_MAGIC       ISC_MAGIC('t', 'r', 'i', 'e')
#define QPITER_MAGIC   ISC_MAGIC('q', 'p', 'i', 't')
#define QPMULTI_MAGIC  ISC_MAGIC('q', 'p', 'm', 'v')
#define QPREADER_MAGIC ISC_MAGIC('q', 'p', 'r', 'x')
#define QPBASE_MAGIC   ISC_MAGIC('q', 'p', 'b', 'p')
#define QPRCU_MAGIC    ISC_MAGIC('q', 'p', 'c', 'b')

#define QP_VALID(qp)	  ISC_MAGIC_VALID(qp, QP_MAGIC)
#define QPITER_VALID(qp)  ISC_MAGIC_VALID(qp, QPITER_MAGIC)
#define QPMULTI_VALID(qp) ISC_MAGIC_VALID(qp, QPMULTI_MAGIC)
#define QPBASE_VALID(qp)  ISC_MAGIC_VALID(qp, QPBASE_MAGIC)
#define QPRCU_VALID(qp)	  ISC_MAGIC_VALID(qp, QPRCU_MAGIC)

/*
 * Polymorphic initialization of the `dns_qpreader_t` prefix.
 *
 * The location of the root node is actually a qp_ref_t, but is
 * declared in DNS_QPREADER_FIELDS as uint32_t to avoid leaking too
 * many internal details into the public API.
 *
 * The `uctx` and `methods` support callbacks into the user's code.
 * They are constant after initialization.
 */
#define QP_INIT(qp, m, x)                 \
	(*(qp) = (typeof(*(qp))){         \
		 .magic = QP_MAGIC,       \
		 .root_ref = INVALID_REF, \
		 .uctx = x,               \
		 .methods = m,            \
	 })

/*
 * Snapshots have some extra cleanup machinery.
 *
 * Originally, a snapshot was basically just a `dns_qpread_t`
 * allocated on the heap, with the extra behaviour that memory
 * reclamation is suppressed for a particular trie while it has any
 * snapshots. However that design gets into trouble for a zone with
 * frequent updates and many zone transfers.
 *
 * Instead, each snapshot records which chunks it needs. When a
 * snapshot is created, it makes a copy of the `base` array, except
 * for chunks that are empty and waiting to be reclaimed. When a
 * snapshot is destroyed, we can traverse the list of snapshots to
 * accurately mark which chunks are still needed.
 *
 * A snapshot's `whence` pointer helps ensure that a `dns_qpsnap_t`is
 * not muddled up with the wrong `dns_qpmulti_t`.
 *
 * A trie's `base` array might have grown after the snapshot was
 * created, so it records its own `chunk_max`.
 */
struct dns_qpsnap {
	DNS_QPREADER_FIELDS;
	dns_qpmulti_t *whence;
	uint32_t chunk_max;
	ISC_LINK(struct dns_qpsnap) link;
};

/*
 * Read-write access to a qp-trie requires extra fields to support the
 * allocator and garbage collector.
 *
 * Bare instances of a `struct dns_qp` are used for stand-alone
 * single-threaded tries. For multithreaded access, a `dns_qpmulti_t`
 * wraps a `dns_qp_t` with a mutex and other fields that are only needed
 * at the start or end of a transaction.
 *
 * Allocations are made sequentially in the `bump` chunk. A sequence
 * of lightweight write transactions can use the same `bump` chunk, so
 * its prefix before `fender` is immutable, and the rest is mutable.
 *
 * To decide when to compact and reclaim space, QP_MAX_GARBAGE() examines
 * the values of `used_count`, `free_count`, and `hold_count`. The
 * `hold_count` tracks nodes that need to be retained while readers are
 * using them; they are free but cannot be reclaimed until the transaction
 * has committed, so the `hold_count` is discounted from QP_MAX_GARBAGE()
 * during a transaction.
 *
 * There are some flags that alter the behaviour of write transactions.
 *
 *  - The `transaction_mode` indicates whether the current transaction is a
 *    light write or a heavy update, or (between transactions) the previous
 *    transaction's mode, because the setup for the next transaction
 *    depends on how the previous one committed. The mode is set at the
 *    start of each transaction. It is QP_NONE in a single-threaded qp-trie
 *    to detect if part of a `dns_qpmulti_t` is passed to dns_qp_destroy().
 *
 *  - The `compact_all` flag is used when every node in the trie should be
 *    copied. (Usually compation aims to avoid moving nodes out of
 *    unfragmented chunks.) It is used when compaction is explicitly
 *    requested via `dns_qp_compact()`, and as an emergency mechanism if
 *    normal compaction failed to clear the QP_MAX_GARBAGE() condition.
 *    (This emergency is a bug even tho we have a rescue mechanism.)
 *
 *  - When a qp-trie is destroyed while it has pending cleanup work, its
 *    `destroy` flag is set so that it is destroyed by the reclaim worker.
 *    (Because items cannot be removed from the middle of the cleanup list.)
 *
 *  - When built with fuzzing support, we can use mprotect() and munmap()
 *    to ensure that incorrect memory accesses cause fatal errors. The
 *    `write_protect` flag must be set straight after the `dns_qpmulti_t`
 *    is created, then left unchanged.
 *
 * Some of the dns_qp_t fields are only needed for multithreaded transactions
 * (marked [MT] below) but the same code paths are also used for single-
 * threaded writes.
 */
struct dns_qp {
	DNS_QPREADER_FIELDS;
	/*% memory context (const) */
	isc_mem_t *mctx;
	/*% array of per-chunk allocation counters */
	qp_usage_t *usage;
	/*% number of slots in `chunk` and `usage` arrays */
	qp_chunk_t chunk_max;
	/*% which chunk is used for allocations */
	qp_chunk_t bump;
	/*% nodes in the `bump` chunk below `fender` are read only [MT] */
	qp_cell_t fender;
	/*% number of leaf nodes */
	qp_cell_t leaf_count;
	/*% total of all usage[] counters */
	qp_cell_t used_count, free_count;
	/*% free cells that cannot be recovered right now */
	qp_cell_t hold_count;
	/*% what kind of transaction was most recently started [MT] */
	enum { QP_NONE, QP_WRITE, QP_UPDATE } transaction_mode : 2;
	/*% compact the entire trie [MT] */
	bool compact_all : 1;
	/*% optionally when compiled with fuzzing support [MT] */
	bool write_protect : 1;
};

/*
 * Concurrent access to a qp-trie.
 *
 * The `reader` pointer provides wait-free access to the current version
 * of the trie. See the "packed reader nodes" section below for a
 * description of what it points to.
 *
 * The main object under the protection of the mutex is the `writer`
 * containing all the allocator state. There can be a backup copy when
 * we want to be able to rollback an update transaction.
 *
 * There is a `reader_ref` which corresponds to the `reader` pointer
 * (`ref_ptr(multi->reader_ref) == multi->reader`). The `reader_ref` is
 * necessary when freeing the space used by the reader, because there
 * isn't a good way to recover a qp_ref_t from a qp_node_t pointer.
 *
 * There is a per-trie list of snapshots that is used for reclaiming
 * memory when a snapshot is destroyed.
 *
 * Finally, we maintain a global list of `dns_qpmulti_t` objects that
 * need asynchronous safe memory recovery.
 */
struct dns_qpmulti {
	uint32_t magic;
	/*% RCU-protected pointer to current packed reader */
	qp_node_t *reader;
	/*% the mutex protects the rest of this structure */
	isc_mutex_t mutex;
	/*% ref_ptr(writer, reader_ref) == reader */
	qp_ref_t reader_ref;
	/*% the main working structure */
	dns_qp_t writer;
	/*% saved allocator state to support rollback */
	dns_qp_t *rollback;
	/*% all snapshots of this trie */
	ISC_LIST(dns_qpsnap_t) snapshots;
};

/***********************************************************************
 *
 *  interior node constructors and accessors
 */

/*
 * See the comments under "interior node basics" above, which explain
 * the layout of nodes as implemented by the following functions.
 *
 * These functions are (mostly) constructors and getters. Imagine how
 * much less code there would be if C had sum types with control over
 * the layout...
 */

/*
 * Get the 64-bit word of a node.
 */
static inline uint64_t
node64(qp_node_t *n) {
	uint64_t lo = n->biglo;
	uint64_t hi = n->bighi;
	return (lo | (hi << 32));
}

/*
 * Get the 32-bit word of a node.
 */
static inline uint32_t
node32(qp_node_t *n) {
	return (n->small);
}

/*
 * Create a node from its parts
 */
static inline qp_node_t
make_node(uint64_t big, uint32_t small) {
	return ((qp_node_t){
		.biglo = (uint32_t)(big),
		.bighi = (uint32_t)(big >> 32),
		.small = small,
	});
}

/*
 * Extract a pointer from a node's 64 bit word. The double cast is to avoid
 * a warning about mismatched pointer/integer sizes on 32 bit systems.
 */
static inline void *
node_pointer(qp_node_t *n) {
	return ((void *)(uintptr_t)(node64(n) & ~TAG_MASK));
}

/*
 * Examine a node's tag bits
 */
static inline uint32_t
node_tag(qp_node_t *n) {
	return (n->biglo & TAG_MASK);
}

/*
 * simplified for the hot path
 */
static inline bool
is_branch(qp_node_t *n) {
	return (n->biglo & BRANCH_TAG);
}

/* leaf nodes *********************************************************/

/*
 * Get a leaf's pointer value.
 */
static inline void *
leaf_pval(qp_node_t *n) {
	return (node_pointer(n));
}

/*
 * Get a leaf's integer value
 */
static inline uint32_t
leaf_ival(qp_node_t *n) {
	return (node32(n));
}

/*
 * Create a leaf node from its parts
 */
static inline qp_node_t
make_leaf(const void *pval, uint32_t ival) {
	qp_node_t leaf = make_node((uintptr_t)pval, ival);
	REQUIRE(node_tag(&leaf) == LEAF_TAG);
	return (leaf);
}

/* branch nodes *******************************************************/

/*
 * The following function names use plural `twigs` when they work on a
 * branch's twigs vector as a whole, and singular `twig` when they work on
 * a particular twig.
 */

/*
 * Get a branch node's index word
 */
static inline uint64_t
branch_index(qp_node_t *n) {
	return (node64(n));
}

/*
 * Get a reference to a branch node's child twigs.
 */
static inline qp_ref_t
branch_twigs_ref(qp_node_t *n) {
	return (node32(n));
}

/*
 * Bit positions in the bitmap come directly from the key. DNS names are
 * converted to keys using the tables declared at the end of this file.
 */
static inline qp_shift_t
qpkey_bit(const dns_qpkey_t key, size_t len, size_t offset) {
	if (offset < len) {
		return (key[offset]);
	} else {
		return (SHIFT_NOBYTE);
	}
}

/*
 * Extract a branch node's offset field, used to index the key.
 */
static inline size_t
branch_key_offset(qp_node_t *n) {
	return ((size_t)(branch_index(n) >> SHIFT_OFFSET));
}

/*
 * Which bit identifies the twig of this node for this key?
 */
static inline qp_shift_t
branch_keybit(qp_node_t *n, const dns_qpkey_t key, size_t len) {
	return (qpkey_bit(key, len, branch_key_offset(n)));
}

/*
 * Get a pointer to a branch node's twigs vector.
 */
static inline qp_node_t *
branch_twigs_vector(dns_qpreadable_t qpr, qp_node_t *n) {
	return (ref_ptr(qpr, branch_twigs_ref(n)));
}

/*
 * Warm up the cache while calculating which twig we want.
 */
static inline void
prefetch_twigs(dns_qpreadable_t qpr, qp_node_t *n) {
	__builtin_prefetch(branch_twigs_vector(qpr, n));
}

/* root node **********************************************************/

/*
 * Get a pointer to the root node, checking if the trie is empty.
 */
static inline qp_node_t *
get_root(dns_qpreadable_t qpr) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	if (qp->root_ref == INVALID_REF) {
		return (NULL);
	} else {
		return (ref_ptr(qp, qp->root_ref));
	}
}

/*
 * When we need to move the root node, we avoid repeating allocation
 * logistics by making a temporary fake branch node that has
 *	`branch_twigs_size() == 1 && branch_twigs_ref() == root_ref`
 * just enough to treat the root node as a vector of one twig.
 */
#define MOVABLE_ROOT(qp)                                   \
	(&(qp_node_t){                                     \
		.biglo = BRANCH_TAG | (1 << SHIFT_NOBYTE), \
		.small = qp->root_ref,                     \
	})

/***********************************************************************
 *
 *  bitmap popcount shenanigans
 */

/*
 * How many twigs appear in the vector before the one corresponding to the
 * given bit? Calculated using popcount of part of the branch's bitmap.
 *
 * To calculate a mask that covers the lesser bits in the bitmap,
 * we subtract 1 to set all lesser bits, and subtract the tag mask
 * because the type tag is not part of the bitmap.
 */
static inline qp_weight_t
branch_count_bitmap_before(qp_node_t *n, qp_shift_t bit) {
	uint64_t mask = (1ULL << bit) - 1 - TAG_MASK;
	uint64_t bitmap = branch_index(n) & mask;
	return ((qp_weight_t)__builtin_popcountll(bitmap));
}

/*
 * How many twigs does this branch have?
 *
 * The offset is directly after the bitmap so the offset's lesser bits
 * covers the whole bitmap, and the bitmap's weight is the number of twigs.
 */
static inline qp_weight_t
branch_twigs_size(qp_node_t *n) {
	return (branch_count_bitmap_before(n, SHIFT_OFFSET));
}

/*
 * Position of a twig within the packed sparse vector.
 */
static inline qp_weight_t
branch_twig_pos(qp_node_t *n, qp_shift_t bit) {
	return (branch_count_bitmap_before(n, bit));
}

/*
 * Get a pointer to a particular twig.
 */
static inline qp_node_t *
branch_twig_ptr(dns_qpreadable_t qpr, qp_node_t *n, qp_shift_t bit) {
	return (branch_twigs_vector(qpr, n) + branch_twig_pos(n, bit));
}

/*
 * Is the twig identified by this bit present?
 */
static inline bool
branch_has_twig(qp_node_t *n, qp_shift_t bit) {
	return (branch_index(n) & (1ULL << bit));
}

/* twig logistics *****************************************************/

static inline void
move_twigs(qp_node_t *to, qp_node_t *from, qp_weight_t size) {
	memmove(to, from, size * sizeof(qp_node_t));
}

static inline void
zero_twigs(qp_node_t *twigs, qp_weight_t size) {
	memset(twigs, 0, size * sizeof(qp_node_t));
}

/***********************************************************************
 *
 *  packed reader nodes
 */

/*
 * The purpose of these packed reader nodes is to simplify safe memory
 * reclamation for a multithreaded qp-trie.
 *
 * After the `reader` pointer in a qpmulti is replaced, we need to wait
 * for a grace period before we can reclaim the memory that is no longer
 * needed by the trie. So we need some kind of structure to hold
 * pointers to the (logically) detached memory until it is safe to free.
 * This memory includes the chunks and the `base` arrays.
 *
 * Packed reader nodes save us from having to track `dns_qpread_t`
 * objects as distinct allocations: the packed reader nodes get
 * reclaimed when the the chunk containing their cells is reclaimed.
 * When a real `dns_qpread_t` object is needed, it is allocated on the
 * stack (it must not live longer than a isc_loop callback) and the
 * packed reader is unpacked into it.
 *
 * Chunks are owned by the current `base` array, so unused chunks are
 * held there until they are free()d. Old `base` arrays are attached
 * to packed reader nodes with a refcount. When a chunk is reclaimed,
 * it is scanned so that `chunk_free()` can call `detach_leaf()` on
 * any remaining references to leaf objects. Similarly, it calls
 * `qpbase_unref()` to reclaim old `base` arrays.
 */

/*
 * Two nodes is just enough space for the information needed by
 * readers and for deferred memory reclamation.
 */
#define READER_SIZE 2

/*
 * Create a packed reader; space for the reader should have been
 * allocated using `alloc_twigs(&multi->writer, READER_SIZE)`.
 */
static inline void
make_reader(qp_node_t *reader, dns_qpmulti_t *multi) {
	dns_qp_t *qp = &multi->writer;
	reader[0] = make_node(READER_TAG | (uintptr_t)multi, QPREADER_MAGIC);
	reader[1] = make_node(READER_TAG | (uintptr_t)qp->base, qp->root_ref);
}

static inline bool
reader_valid(qp_node_t *reader) {
	return (reader != NULL && //
		node_tag(&reader[0]) == READER_TAG &&
		node_tag(&reader[1]) == READER_TAG &&
		node32(&reader[0]) == QPREADER_MAGIC);
}

/*
 * Verify and unpack a reader. We return the `multi` pointer to use in
 * consistency checks.
 */
static inline dns_qpmulti_t *
unpack_reader(dns_qpreader_t *qp, qp_node_t *reader) {
	INSIST(reader_valid(reader));
	dns_qpmulti_t *multi = node_pointer(&reader[0]);
	dns_qpbase_t *base = node_pointer(&reader[1]);
	INSIST(QPMULTI_VALID(multi));
	INSIST(QPBASE_VALID(base));
	*qp = (dns_qpreader_t){
		.magic = QP_MAGIC,
		.uctx = multi->writer.uctx,
		.methods = multi->writer.methods,
		.root_ref = node32(&reader[1]),
		.base = base,
	};
	return (multi);
}

/***********************************************************************
 *
 *  method invocation helpers
 */

static inline void
attach_leaf(dns_qpreadable_t qpr, qp_node_t *n) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	qp->methods->attach(qp->uctx, leaf_pval(n), leaf_ival(n));
}

static inline void
detach_leaf(dns_qpreadable_t qpr, qp_node_t *n) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	qp->methods->detach(qp->uctx, leaf_pval(n), leaf_ival(n));
}

static inline size_t
leaf_qpkey(dns_qpreadable_t qpr, qp_node_t *n, dns_qpkey_t key) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	size_t len = qp->methods->makekey(key, qp->uctx, leaf_pval(n),
					  leaf_ival(n));
	INSIST(len < sizeof(dns_qpkey_t));
	return (len);
}

static inline char *
triename(dns_qpreadable_t qpr, char *buf, size_t size) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	qp->methods->triename(qp->uctx, buf, size);
	return (buf);
}

#define TRIENAME(qp) \
	triename(qp, (char[DNS_QP_TRIENAME_MAX]){}, DNS_QP_TRIENAME_MAX)

/***********************************************************************
 *
 *  converting DNS names to trie keys
 */

/*
 * This is a deliberate simplification of the hostname characters,
 * because it doesn't matter much if we treat a few extra characters
 * favourably: there is plenty of space in the index word for a
 * slightly larger bitmap.
 */
static inline bool
qp_common_character(uint8_t byte) {
	return (('-' <= byte && byte <= '9') || ('_' <= byte && byte <= 'z'));
}

/*
 * Lookup table mapping bytes in DNS names to bit positions, used
 * by dns_qpkey_fromname() to convert DNS names to qp-trie keys.
 */
extern uint16_t dns_qp_bits_for_byte[];

/*
 * And the reverse, mapping bit positions to characters, so the tests
 * can print diagnostics involving qp-trie keys.
 */
extern uint8_t dns_qp_byte_for_bit[];

/**********************************************************************/
