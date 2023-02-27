<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

A qp-trie for the DNS
=====================

A qp-trie is a data structure that supports lookups in a sorted
collection of keys. It is efficient both in terms of fast lookups and
using little memory. It is particularly well-suited for use in DNS
servers.

These notes outline how BIND's `dns_qp` implementation works, how it
is optimized for lookups keyed by DNS names, and how it supports
multi-version concurrency.


data structure zoo
------------------

Chasing a pointer indirection is very slow, up to 100ns, whereas a
sequential memory access takes less than 10ns. So, to make a data
structure fast, we need to minimize indirections.

There is a tradeoff between speed and flexibility in standard data
structures:

  * Arrays are very simple and fast (a lookup goes straight to the
    right address), but the key can only be a small integer.

  * Hash tables allow you to use arbitrary lookup keys (such as
    strings), but may require probing multiple addresses to find the
    right element.

  * Radix trees allow you to do lookups based on the sorting order of
    the keys, provided it is lexical like `memcmp()`; however, lookups
    require multiple indirections.

  * Comparison search trees (binary trees and B-trees) allow you to
    use an arbitrary ordering predicate, but each indirection during
    a lookup also requires a comparison.

In the DNS, we need to use some kind of tree to support the kinds of
lookup required for DNSSEC: find longest match, find nearest
predecessor or successor, and so forth. So what kind of tree is best?


in theory
---------

In a tree where the average length of a key is `k`, and the number of
elements in the tree is `n`, the theoretical performance bounds are,
for a comparison tree:

  * `Ω(k * log n)`
  * `Ο(k * n)`

And for a radix tree:

  * `Ω(k + log n)`
  * `Ο(k + k)`

Here, `Ω()` is the lower bound and `Ο()` is the upper bound; we
expect typical performance to be close to the lower bound.

The multiplications in the comparison tree expressions means that each
indirection requires a comparison `Ο(k)`, whereas they are additions
in the radix tree expressions because a radix tree traversal only
needs one key comparison.

The upper bounds say that (in the absence of balancing) a comparison
tree can devolve into a linked list of nodes, whereas the shape of a
radix tree is determined by the set of keys independent of the order
of insertion or the number of keys.

The logarithms hide some interesting constant factors. In a binary
tree, the log is base 2. In a radix tree, the radix is the base of the
logarithm. So, if we increase the radix, the constant factor gets
smaller. The rough equivalent for a binary tree would be to use a
B-tree instead, but although B-trees have fewer indirections they do
not reduce the number of comparisons.

In implementation terms, a larger radix means tree nodes get wider
and the tree becomes shallower. A shallower tree requires fewer
indirections, so it should be faster. The trick is to increase the
radix without blowing up the tree's memory usage, which can lose
more performance than we win.

This analysis suggests that a radix tree is better than a comparison
tree, provided keys can be compared lexically - which is true for DNS
names, with some rearrangement (described below). When using big-o
notation, we also need to be wary of the constant factors; but in this
case they also favour a radix tree, especially with the optimization
tricks used by BIND's qp-trie.

Note: "radix" comes from the latin for "root", so "radix tree" is a
pun, which is geekily amusing especially when talking about logs.


what is a trie?
---------------

A trie is another name for a radix tree (or "digital tree" according
to Knuth). It is short for information reTRIEval, and I pronounce it
exactly like "tree" (though Knuth pronounces it like "try").

In a trie, keys are divided into digits depending on some radix e.g.
base 2 for binary tries, base 256 for byte-indexed tries. When
searching the trie, successive digits in the key, from most to least
significant, are used to select branches from successive nodes in
the trie, roughly like:

        for (offset = 0; isbranch(node); offset++)
            node = node->child[key[offset]];

All of the keys in a subtrie have identical prefixes. Tries do not
need to store keys since they are implicit in the structure.


binary crit-bit trees
---------------------

A patricia trie is a binary trie which omits nodes that have only one
child. Dan Bernstein calls his tightly space-optimized version a
"crit-bit tree".
https://cr.yp.to/critbit.html
https://github.com/agl/critbit/

Unlike a basic trie, a crit-bit tree skips parts of the key when
every element in a subtree shares the same sequence of bits.
Each node is annotated with the offset of the bit that is used to
select the branch; offsets always increase as you go deeper into
the tree.

    while (isbranch(node))
        node = node->child[key[node->offset]];

In a crit-bit tree the keys are not implicit in the structure
because parts of them are skipped. Therefore, each leaf refers to a
copy of its key so that when you find a leaf you can verify that the
skipped bits match.


prefetching
-----------

Observe that in the loop above, the current node has only one child
pointer, and the child nodes are adjacent in memory. This means it
is possible to tell the CPU to prefetch the child nodes before
extracting the critical bit from the key and choosing which child is
next. A qp-trie has a similar layout, but it has more child nodes
(still adjacent in memory) and it does more computation to choose
which one is next.

When I originally invented the qp-trie code, I found that explicit
prefetch hints made the qp-trie substantially faster and the crit-bit
tree slightly faster. The hints help the CPU to do useful work at the
same time as the memory subsystem. (This is unusual for linked data
structures, which tend to alternate between CPU waiting for memory,
and memory waiting for CPU.)

Large modern CPUs (after about 2015) are better at prefetching
automatically, so the explicit hint is less important than it used to
be, but `lib/dns/qp.c` still has `__builtin_prefetch()` hints in its
inner traversal loops.


packed sparse vectors with popcount
-----------------------------------

The `popcount` instruction counts the number of bits that are set
in a word. It's also known as the Hamming weight; Knuth calls it
"sideways add". https://en.wikipedia.org/wiki/popcount

You can use `popcount` to implement a sparse vector of length `N`
containing `M <= N` members using bitmap of length `N` and a packed
vector of `M` elements. A member `b` is present in the vector if bit
`b` is set, so `M == popcount(bitmap)`. The index of member `b` in
the packed vector is the popcount of the bits preceding `b`.

    // size of vector
    size = popcount(bitmap);
    // bit position
    bit =  1 << b;
    // is element present?
    if (bitmap & bit) {
        // mask covers the preceding elements
        mask = bit - 1;
        // position of element in packed vector
        pos = popcount(bitmap & mask);
        // fetch element
        elem = vector[pos];
    }

See "Hacker's Delight" by Hank Warren, section 5-1 "Counting 1
bits", subsection "applications". http://www.hackersdelight.org

See under _"bitmap popcount shenanigans"_ in `lib/dns/qp.c` for how
this is implemented in BIND.


popcount for trie nodes
-----------------------

Phil Bagwell's hashed array-mapped tries (HAMT) use popcount for
compact trie nodes. In a HAMT, string keys are hashed, and the hash is
used as the index to the trie, with radix 2^32 or 2^64.
http://infoscience.epfl.ch/record/64394/files/triesearches.pdf
http://infoscience.epfl.ch/record/64398/files/idealhashtrees.pdf

As discussed above, increasing the radix makes the tree shallower, so
it should be faster. The downside is usually much greater memory
overhead. Child vectors are often sparsely populated, so we can
greatly reduce the overhead by packing them with popcount.

The HAMT relies on hashing, which keeps keys dense. This means it
can be laid out like a basic trie with implicit keys (i.e. hash
values). The disadvantage of hashing is that strings are stored
out of order.


qp-trie
-------

A qp-trie is a mash-up of Bernstein's crit-bit tree with Bagwell's
HAMT. Like a crit-bit tree, a qp-trie omits nodes with one child;
nodes include a key offset; and keys a referenced from leaves instead
of being implicit in the trie structure. Like a HAMT, nodes have a
popcount packed vector of children, but unlike a HAMT, keys are not
hashed.

A qp-trie is faster than a crit-bit tree and uses less memory, because
its wider fan-out requires fewer nodes and popcount packs them very
efficiently. Like a crit-bit tree but unlike a HAMT, a qp-trie stores
keys in lexical order.

As in a HAMT, the original layout of a qp-trie node is a pair of
words, which are used as key and value pointers in leaf nodes, and
index word and pointer in branch nodes. The index word contains the
popcount bitmap (as in a HAMT) and the offset into the key (as in a
crit-bit tree), as well as a leaf/branch tag bit. The pointer refers
to the branch node's "twigs", which is what we call the packed sparse
vector of child nodes.

The fan-out of a qp-trie is limited by the need to fit the bitmap and
the nybble offset into a 64-bit word; a radix of 16 or 32 works well,
and 32 is slightly faster (though 5-bit nybbles are fiddly). But radix
64 requires an extra word per node, and the extra memory overhead
makes it slower as well as bulkier.

Early qp-trie implementations used a node layout like the
following. However, in practice C bitfields have too many
portability gotchas to work well. It is better to use hand-written
shifting and masking to access the parts of the index word.

        #define NYBBLE 4 // or 5
        #define RADIX (1 << NYBBLE)

        union qp_node {
            struct {
                unsigned tag : 1;
                unsigned bitmap : RADIX;
                unsigned offset : (64 - 1 - RADIX);
                union qp_node *twigs;
            } branch;
            struct {
                void *value;
                const char *key;
            } leaf;
        };


DNS qp-trie
-----------

BIND uses a variant of a qp-trie optimized for DNS names. DNS names
almost always use the usual hostname alphabet of (case-insensitive)
letters, digits, hyphen, plus underscore (which is often used in the DNS
for non-hostname purposes), and finally the label separator (which is
written as '.' in presentation-format domain names, and is the label
length in wire format). This adds up to 39 common characters.

A bitmap for 39 common characters is small enough to fit into a
qp-trie index word, so we can (in principle) walk down the trie one
character at a time, as if the radix were 256, but without needing a
multi-word bitmap.

However, DNS names can contain arbitrary bytes. To support the 200-ish
unusual characters we use an escaping scheme, described in more detail
below. This requires a few more bits in the bitmap to represent the
escape characters, so our radix ends up being 47. This still fits into
the 64-bit index word, so we get the compactness of a qp-trie but with
faster byte-at-a-time lookups for DNS names that use common hostname
characters.

You can also use other kinds of keys with BIND's DNS qp-trie, provided
they are not too long. You must provide your own key preparation
function, e.g. for uniform binary keys you might extract 5-bit nybbles
to get a radix-32 trie.


preparing a lookup key
----------------------

A DNS name needs to be rearranged to use it as a qp-trie key, so that
the lexical order of rearranged keys matches the canonical DNS name
order specified in RFC 4034 section 6.1:

  * reverse the order of the labels so that they run from most
    significant to least significant, left to right (but the
    characters in each label remain in the same order)

  * convert uppercase ASCII letters to lowercase ASCII

  * change the label separators to a non-byte value that sorts before
    the zero byte

For qp-trie lookups there are a couple of extra steps:

  * There is an escaping mechanism to support DNS names that use
    unusual characters. Common characters use one byte in the lookup
    key, but unusual characters are expanded to two bytes. To preserve
    the correct lexical order, there are different escape bytes
    depending on how the unusual character sorts relative to the
    common hostname characters.

  * Characters in the DNS name need to be converted to bitmap
    positions. This is done at the same time as preparing the lookup
    key, to move work out of the inner trie traversal loop.

These 5 transformations can be done in a single pass over a DNS name
using a single lookup table. The transformed name is usually the
same length (up to 2x longer if it contains unusual characters).

You can use absolute or relative DNS names as keys, without ambiguity
(provided you have some way of knowing what names are relative to).
When converted to a lookup key, absolute names start with a non-byte
value representing the root, and relative names do not.

Lookup keys are ephemeral, allocated on the stack during a lookup.

See under _"converting DNS names to trie keys"_ in `lib/dns/qp.c`
for how this is implemented in BIND.


node layout
-----------

Earlier I said that the original qp-trie node layout consists of two
words: one 64 bit word for the branch index, and one pointer-sized
word. BIND's qp-trie uses a layout that is smaller on 64-bit systems:
one 64 bit word and one 32-bit word.

A branch node contains

  * two type tag bits

  * a 47-wide bitmap, with a bit for each common hostname character
    and each escape character

  * a 9-bit key offset, enough to count twice the length of a DNS
    name

  * a 32-bit "twigs" reference to the packed vector of child nodes;
    these references are described in more detail below

A leaf node contains a pointer value (which we assume to be 64 bits)
and a 32-bit integer value. The type tag is smuggled into the
low-order bits of the pointer value, so the pointer value must have
large enough alignment. (This requirement is checked when a leaf is
added to the trie.) Apart from that, the meaning of leaf values
is entirely under control of the qp-trie user.

When constructing a qp-trie the user provides a collection of method
pointers. The qp-trie code calls these methods when it needs to do
anything that needs to look into a leaf value, such as extracting the
key.

See under _"interior node basics"_ and _"interior node constructors
and accessors"_ in `lib/dns/qp_p.h` for the implementation.


example
-------

Consider a small zone:

        example.        ; apex
        mail.example.   ; IMAP server
        mx.example.     ; incoming mail
        www.example.    ; web load balancer
        www1.example.   ; back-end web servers
        www2.example.

It becomes a qp-trie as follows. I am writing bitmaps as lists of
characters representing the bits that are set, with `'.'` for label
separators. I have used arbitrary names for the addresses of the twigs
vectors.

    root = (qp_node){
        tag: BRANCH,
        offset: 9,
        bitmap: [ '.', 'm', 'w' ],
        twigs: &one,
    };

Note that the offset skips the root zone, the zone name, and the apex
label separator. If the offset is beyond the end of the key, the byte
value is the label separator.

    one = (qp_node[3]){
        {
            tag: LEAF,
            key: "example.",
        },
        {
            tag: BRANCH,
            offset: 10,
            bitmap: [ 'a', 'x' ],
            twigs: &two,
        },
        {
            tag: BRANCH,
            offset: 12,
            bitmap: [ '.', '1', '2' ],
            twigs: &three,
        },
    };

This twigs vector has an element for the zone apex, and the two
different initial characters of the subdomains.

The mail servers differ in the next character, so the offset bumps from
9 to 10 without skipping any characters. The web servers all start with
www, so the offset bumps from 9 to 12, skipping the common prefix.

    two = (qp_node[2]){
        {
            tag: LEAF,
            key: "mail.example.",
        },
        {
            tag: LEAF,
            key: "mx.example.",
        },
    };

The different lengths of `mail` and `mx` don't matter: we implicitly
skip to the end of the key when we reach a leaf node.

    three = (qp_node[3]){
        {
            tag: LEAF,
            key: "www.example.",
        },
        {
            tag: LEAF,
            key: "www1.example.",
        },
        {
            tag: LEAF,
            key: "www2.example.",
        },
    };

When the trie includes labels of differing lengths, we can have a node
that chooses between a label separator and characters from the longer
labels. This is slightly different from the root node, which tested the
first character of the label; here we are testing the last character.


concurrency and transactions
----------------------------

The following sections discuss how the qp-trie supports concurrency.

The requirement is to support many concurrent read threads, and
allow updates to occur without blocking readers (or blocking readers
as little as possible).

Concurrent access to a qp-trie uses a transactional API. There can be
at most one writer at a time. When a writer commits its transaction
(by atomically replacing the trie's root pointer) the changes become
visible to readers. Read transactions ensure that memory is not
reclaimed while readers are still using it.

If there are relatively long read transactions and brief write
transactions (though that is unlikely) there can be multiple versions
of a qp-trie in use at a time.


copy-on-write
-------------

The strategy is to use "copy-on-write", that is, when an update
needs to alter the trie it makes a copy of the parts that it needs
to change, so that concurrent readers can continue to use the
original. (It is analogous to multiversion concurrency in databases
such as PostgreSQL, where copy-on-write uses a write-ahead log.)

The qp-trie only uses copy-on-write when the nodes that need to be
altered can be shared with concurrent readers. After copying, the
nodes are exclusive to the writer and can be updated in place. This
reduces the pressure on the allocator a lot: pure copy-on-write
allocates and discards memory at a ferocious rate.

Software that uses copy-on-write needs some mechanism for clearing
away old versions that are no longer in use. (For example, VACUUM in
PostgreSQL.) The qp-trie code uses a custom allocator with a simple
garbage collector; as well as supporting concurrency, the qp-trie's
memory manager makes tries smaller and faster.


allocation
----------

A qp-trie is relatively demanding on its allocator. Twigs vectors
can be lots of different sizes, and every mutation of the trie
requires an alloc and/or a free.

Older versions of the qp-trie code used the system allocator. Many
allocators (such as `jemalloc`) segregate the heap into different
size classes, so that each chunk of memory is dedicated to
allocations of the same size. While this memory layout provides good
locality when objects of the same type have the same size, it tends
to scatter the interior nodes of a qp-trie all over the address space.

BIND's qp-trie code uses a "bump allocator" for its interior nodes,
which is one of the simplest and fastest possible: an allocation
usually only requires incrementing a pointer and checking if it has
reached a limit. (If the check fails the allocator goes into its
slow path.) Allocations have good locality because they write
sequentially into memory. (A bit like a write-ahead log.)

Bump allocators need reasonably large contiguous chunks of empty
memory to make the most of their efficiency, so they are often
coupled with some kind of compacting garbage collector, which
defragments the heap to recover free space.

See `alloc_twigs()` in `lib/dns/qp.c` for the bump allocator fast
path.


garbage collection
------------------

[The Garbage Collection Handbook](https://gchandbook.org/) says
there are four basic kinds of automatic memory management.

Reference counting is used by scripting languages such as Perl and
Python, and also for manual memory management such as in operating
system kernels and BIND.

To avoid writing a custom allocator, I previously tried adapting the
qp-trie code to use refcounting to support copy-on-write, but I was
not very happy with the complexity of the implementation, and I
thought it was ugly that I needed to modify refcounts in nodes that
were logically read-only.

(Two other kinds of GC are mark-sweep and mark-compact. Both of them
have a similar disadvantage to refcounting: a simple GC mark phase
modifies nodes that are logically read-only. And mark-sweep leaves
memory fragmented so it does not support a bump allocator.)

The fourth kind is copying garbage collection. It works well with a
bump allocator, because copying the data structure using a bump
allocator in the most obvious way naturally compacts the data. And
the copying phase of the GC can run concurrently with readers
without interference.

BIND's qp-trie code uses a copying garbage collector only for its
interior nodes. The value objects that are attached to the leaves of
the trie are allocated by `isc_mem` and use reference counting like
the rest of BIND.

See `compact()` in `lib/dns/qp.c` for the copying phase of the
garbage collector. Reference counting for value objects is handled
by the `attach()` and `detach()` qp-trie methods.


chunked memory layout
---------------------

BIND's qp-trie code organizes its memory as a collection of "chunks"
allocated by `malloc()`, each of which is a few pages in size and
large enough to hold a thousand nodes or so.

As noted above, we also use the chunk-based layout to reduce the size
of interior nodes. Instead of using a native pointer (typically 64
bits) to refer to a node, we use a 32 bit integer containing the chunk
number and the position of the node in the chunk. This reduces the
memory used for interior nodes by 25%. See the "helper types" section
in `lib/dns/qp_p.h` for the relevant definitions.

BIND stores each zone separately, and there can be a very large number
of zones in a server. To avoid wasting memory on small zones that only
have a few names, chunks can be "shrunk" using `realloc()` to fit just
the nodes that have been allocated.


chunk metadata
--------------

The chunked memory layout is supported by a `base` array of pointers
to the start of each chunk. A chunk number is just an index into this
array.

Alongside the `base` array is a `usage` array, indexed the same way.
Instead of keeping track of individual nodes, the allocator just keeps
a count of how many nodes have been allocated from a chunk, and how
many were subsequently freed. The `used` count of the newest chunk
also serves as the allocation point for the bump allocator, and the
size of the chunk when it has been shrunk. This is why we increment
the `free` count when a node is discarded, instead of decrementing the
`used` count. The `usage` array also contains some fields used for
chunk reclamation, about which more below.

The `base` and `usage` arrays are separate because the `usage` array
is only used by writers, and never shared with readers. The read-only
hot path only needs the `base` array, so keeping it separate is more
cache-friendly: less memory pressure on the read path and less
interference from false sharing with write ops.

Both arrays can have empty slots in which new chunks can be allocated;
when a chunk is reclaimed its slot becomes empty. Additions and
removals from the `base` array don't affect readers: they will not see
a reference to a new chunk until after the writer commits, and the
chunk reclamation machinery ensures that no readers depend on a chunk
before it is deleted.

When the arrays fill up they are reallocated. This is easy for the
`usage` array because it is only accessed by writers, but the `base`
array must be cloned, and the old version must be reclaimed later
after it is no longer used by readers. For this reason the `base`
array has a reference count.


lightweight write transactions
------------------------------

"Write" transactions are intended for use when there is a heavy write
load, such as a resolver cache. They minimize the amount of allocation
by re-using the same chunk for the bump allocator across multiple
transactions until it fills up.

When a write (or update) is committed, a new packed read-only trie
anchor is created. This contains a pointer to the `base` array and a
32-bit reference to the trie's root node. The packed reader is stored
in a pair of nodes in the current chunk, allocated by the bump
allocator, so it does not need to be `malloc()`ed separately, and so
the chunk reclamation machinery can also reclaim the `base` array when
it is no longer in use.


heavyweight update transactions
-------------------------------

By contrast, "update" transactions are intended to keep memory usage
as low as possible between writes. On commit, the trie is compacted,
and the bump allocator's chunk is shrunk to fit. When a transaction is
opened, a fresh chunk must be allocated.

Update transactions also support rollback, which requires making a
copy of all the chunk metadata.


lightweight query transactions
------------------------------

A "query" transaction dereferences a pointer to the current trie
anchor and unpacks it into a `dns_qpread_t` object on the stack. There
is no explicit interlocking with writers. Instead, query transactions
must only be used inside an `isc_loop` callback function; the qp-trie
memory reclamation machinery knows that the reader has completed when
the callback returns to the loop. See `include/isc/qsbr.h` for more
about how this works.


heavyweight read-only snapshots
-------------------------------

A "snapshot" is for things like zone transfers that need a long-lived
consistent view of a zone. When a snapshot is created, it includes a
copy of the necessary parts of the `base` array. A qp-trie keeps a
list of its snapshots, and there are flags in the `usage` array to
mark which chunks are in use by snapshots and therefore cannot be
reclaimed.



lifecycle of value objects
--------------------------

A leaf node contains a pointer to a value object that is not managed
by the qp-trie garbage collector. Instead, the user provides
`attach` and `detach` methods that the qp-trie code calls to update
the reference counts in the value objects.

Value object reference counts do not indicate whether the object is
mutable: its refcount can be 1 while it is only in use by readers
(and must be left unchanged), or newly created by a writer (and
therefore mutable).

So, callers must keep track themselves whether leaf objects are newly
inserted (and therefore mutable) or not. XXXFANF this might change, by
adding special lookup functions that return whether leaf objects are
mutable - see the "todo" in `include/dns/qp.h`.


chunk cleanup
-------------

After a "write" or "update" transaction has committed, there can be a
number of chunks that are no longer needed by the latest version of
the trie, but still in use by readers accessing an older version.
The qp-trie uses a QSBR callback to clean up chunks when they are no
longer used at all.

When reclaiming a chunk, we have to scan it for any remaining leaf
nodes. When nodes are accessibly only to the writer, they are zeroed
out when they are freed. If they are shared with readers, they must be
left in place (though the `free` count in the usage array is still
adjucted), and finally `detach()`ed when the chunk is reclaimed.

This chunk scan also cleans up old `base` arrays referred to by packed
reader nodes.


testing strategies
------------------

The main qp-trie test is in `tests/dns/qpmulti_test.c`. This uses
randomized testing of the transactional API, with a lot of consistency
checking to detect bugs.

There are also a couple of fuzzers, which aim to benefit from
coverage-guided exploration of the test space and test minimization.
In `fuzz/dns_qp.c` we treat the fuzzer input as a bytecode to exercise
the single-threaded API, and `fuzz/dns_qpkey_name.c` checks conversion
from DNS names to lookup keys.

In `tests/bench` there are a few benchmarks. `load-names` does a very
basic comparison between BIND's hash table, red-black tree, and
qp-trie. `qpmulti` checks multicore performance of the transactional
API (similar to `qpmulti_test` but without the consistency checking).
And `qp-dump` is a utility for printing out the contents of a qp-trie.

John Regehr has some nice essays about testing data structures:

  * Levels of fuzzing: https://blog.regehr.org/archives/1039

    (how much semantic knowledge does your fuzzer have?)

  * Testing with small capacities: https://blog.regehr.org/archives/1138

    (I need to be able to change the chunk size)

  * Write fuzzable code: https://blog.regehr.org/archives/1687

  * Oracles for random testing: https://blog.regehr.org/archives/856


warning: generational collection
--------------------------------

The "generational hypothesis" is that most allocations have a short
lifetime, so it is profitable for a garbage collector to split its
heap into a number of generations. The youngest generation is where
allocations happen; it typically uses a bump allocator, and when the
allocation pointer reaches its limit, the youngest generation's
contents are copied to the second generation. The hypothesis is that
only a small fraction of the youngest generation will still be live
when the GC runs, so this copy will not take much time or space.

For a qp-trie the truth of this hypothesis depends on the order in
which keys are added or removed. It may be true if there is good
locality, for example, adding keys in lexicographic order, but not in
general.

When a qp-trie is mutated, only one node needs to be altered, near the
leaf that is added or removed. Nodes near the root of the trie tend to
be more stable and long-lived. However, during a copy-on-write
transaction, the path from the root to an altered leaf must be copied,
so nodes near the root are no longer stable and long-lived. They may
become stable in a long transaction, but that isn't guaranteed.

So the idea of generational garbage collection seems to be unhelpful
for a qp-trie.
