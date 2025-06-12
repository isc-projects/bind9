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

/*! \file isc/sieve.h */

/*
 * Zhang, Yazhuo, Juncheng Yang, Yao Yue, Ymir Vigfusson, and K V Rashmi.
 * “SIEVE Is Simpler than LRU: An Efficient Turn-Key Eviction Algorithm for
 * Web Caches,” n.d.
 *
 * Algorithm 1 SIEVE
 *
 * Input: The request x, doubly-linked queue T , cache size C, hand p
 *  1: if x is in T then			▷ Cache Hit
 *  2:     x.visited ←1
 *  3: else					▷ Cache Miss
 *  4:     if |T |= C then			▷ Cache Full
 *  5:         o ←p
 *  6:         if o is NULL then
 *  7:             o ←tail of T
 *  8:         while o.visited = 1 do
 *  9:             o.visited ←0
 * 10:             o ←o.prev
 * 11:             if o is NULL then
 * 12:                 o ←tail of T
 * 13:         p ←o.prev
 * 14:         Discard o in T			▷ Eviction
 * 15:     Insert x in the head of T .
 * 16:     x.visited ←0				▷ Insertion
 *
 * Data structure.  SIEVE requires only one FIFO queue and one pointer
 * called “hand”.  The queue maintains the insertion order between objects.
 * Each object in the queue uses one bit to track the visited/non-visited
 * status.  The hand points to the next eviction candidate in the cache and
 * moves from the tail to the head.  Note that, unlike existing algorithms,
 * e.g., LRU, FIFO, and CLOCK, in which the eviction candidate is always
 * the tail object, the eviction candidate in SIEVE is an object somewhere
 * in the queue.
 *
 * SIEVE operations.  A cache hit in SIEVE changes the visited bit of the
 * accessed object to 1.  For a popular object whose visited bit is already
 * 1, SIEVE does not need to perform any operation.  During a cache miss,
 * SIEVE examines the object pointed by the hand.  If it has been visited,
 * the visited bit is reset, and the hand moves to the next position (the
 * retained object stays in the original position of the queue).  It
 * continues this process until it encounters an object with the visited
 * bit being 0, and it evicts the object.  After the eviction, the hand
 * points to the next position (the previous object in the queue).  While
 * an evicted object is in the middle of the queue most of the time, a new
 * object is always inserted into the head of the queue.  In other words,
 * the new objects and the retained objects are not mixed together.
 *
 * At first glance, SIEVE is similar to CLOCK/Second Chance/FIFO-Reinsertion.
 * Each algorithm maintains a single queue in which each object is
 * associated with a visited bit to track its access status.  Visited
 * objects are retained (also called "survived") during an eviction.
 * Notably, new objects are inserted at the head of the queue in both SIEVE
 * and FIFO-Reinsertion.  However, the hand in SIEVE moves from the tail to
 * the head over time, whereas the hand in FIFO-Reinsertion stays at the
 * tail.  The key difference is where a retained object is kept.  SIEVE
 * keeps it in the old position, while FIFO-Reinsertion inserts it at the
 * head, together with newly inserted objects.
 *
 * We detail the algorithm in Alg. 1.  Line 1 checks whether there is a
 * hit, and if so, then line 2 sets the visited bit to one.  In the case of
 * a cache miss (Line 3), Lines 5-12 identify the object to be evicted.
 *
 * Lazy promotion and quick demotion.  Despite a simple design, SIEVE
 * effectively incorporates both lazy promotion and quick demotion.  An
 * object is only promoted at the eviction time in lazy promotion.  SIEVE
 * operates in a similar manner.  However, rather than promoting the object
 * to the head of the queue, SIEVE keeps the object at its original
 * location.  The "survived" objects are generally more popular than the
 * evicted ones, thus, they are likely to be accessed again in the future.
 * By gathering the "survived" objects, the hand in SIEVE can quickly move
 * from the tail to the area near the head, where most objects are newly
 * inserted.  These newly inserted objects are quickly examined by the hand
 * of SIEVE after they are admitted into the cache, thus achieving quick
 * demotion.  This eviction mechanism makes SIEVE achieve both lazy
 * promotion and quick demotion with- out adding too much overhead.
 *
 * The key ingredient of SIEVE is the moving hand, which functions like an
 * adaptive filter that removes unpopular objects from the cache.  This
 * mechanism enables SIEVE to strike a balance between finding new popular
 * objects and keeping old popular objects.
 */

#include <isc/list.h>

#define ISC_SIEVE(type)              \
	struct {                     \
		ISC_LIST(type) list; \
		type *hand;          \
	}
#define ISC_SIEVE_INIT(sieve)                \
	{                                    \
		ISC_LIST_INIT((sieve).list); \
		(sieve).hand = NULL;         \
	}
#define ISC_SIEVE_EMPTY(sieve) ISC_LIST_EMPTY((sieve).list)

#define ISC_SIEVE_MARKED(entry, visited) CMM_LOAD_SHARED((entry)->visited)
#define ISC_SIEVE_MARK(entry, visited)                    \
	if (!ISC_SIEVE_MARKED(entry, visited)) {          \
		CMM_STORE_SHARED((entry)->visited, true); \
	}
#define ISC_SIEVE_UNMARK(entry, visited) \
	CMM_STORE_SHARED((entry)->visited, false)

/*
 * Note: To match the original algorithm design, the
 * SIEVE queue is iterated from tail to head.
 */
#define ISC_SIEVE_NEXT(sieve, visited, link)                                  \
	({                                                                    \
		__typeof__((sieve).hand) __hand = ((sieve).hand);             \
		if (__hand == NULL && !ISC_LIST_EMPTY((sieve).list)) {        \
			__hand = ISC_LIST_TAIL((sieve).list);                 \
		}                                                             \
                                                                              \
		while (__hand != NULL && ISC_SIEVE_MARKED(__hand, visited)) { \
			ISC_SIEVE_UNMARK(__hand, visited);                    \
                                                                              \
			__hand = ISC_LIST_PREV(__hand, link);                 \
			if (__hand == NULL) {                                 \
				/* We know the queue is not empty */          \
				__hand = ISC_LIST_TAIL((sieve).list);         \
			}                                                     \
		}                                                             \
		(sieve).hand = __hand;                                        \
		__hand;                                                       \
	})

#define ISC_SIEVE_UNLINK(sieve, entry, link)                                 \
	({                                                                   \
		__typeof__((sieve).hand) __hand = (sieve).hand;              \
		/* 1. Go to the previous node (possibly head of the list) */ \
		if (entry == __hand) {                                       \
			__hand = ISC_LIST_PREV(entry, link);                 \
		}                                                            \
                                                                             \
		/* 2. Unlink the node from the list */                       \
		ISC_LIST_UNLINK((sieve).list, entry, link);                  \
                                                                             \
		/* 3. We reached head, continue with tail again */           \
		if (__hand == NULL && !ISC_LIST_EMPTY((sieve).list)) {       \
			__hand = ISC_LIST_TAIL((sieve).list);                \
		}                                                            \
                                                                             \
		(sieve).hand = __hand;                                       \
	})

#define ISC_SIEVE_INSERT(sieve, entry, link) \
	ISC_LIST_PREPEND((sieve).list, entry, link)

#define ISC_SIEVE_FOREACH(sieve, entry, link) \
	ISC_LIST_FOREACH((sieve).list, entry, link)
