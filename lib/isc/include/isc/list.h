/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef ISC_LIST_H
#define ISC_LIST_H 1

#include <stdbool.h>

#include <isc/assertions.h>
#include <isc/mutex.h>
#include <isc/types.h>

#ifdef ISC_LIST_CHECKINIT
#define ISC_LINK_INSIST(x) ISC_INSIST(x)
#else
#define ISC_LINK_INSIST(x)
#endif

#define ISC_LIST_INIT(list) \
	do { (list).head = NULL; (list).tail = NULL; } while (0)

#define ISC_LINK(type) struct { type *prev, *next; }
#define ISC_LINK_INIT_TYPE(elt, link, type) \
	do { \
		(elt)->link.prev = (type *)(-1); \
		(elt)->link.next = (type *)(-1); \
	} while (0)
#define ISC_LINK_INIT(elt, link) \
	ISC_LINK_INIT_TYPE(elt, link, void)
#define ISC_LINK_LINKED(elt, link) ((void *)((elt)->link.prev) != (void *)(-1))

#define ISC_LIST_HEAD(list) ((list).head)
#define ISC_LIST_TAIL(list) ((list).tail)
#define ISC_LIST_EMPTY(list) ((list).head == NULL)

#define __ISC_LIST_PREPENDUNSAFE(list, elt, link) \
	do { \
		if ((list).head != NULL) \
			(list).head->link.prev = (elt); \
		else \
			(list).tail = (elt); \
		(elt)->link.prev = NULL; \
		(elt)->link.next = (list).head; \
		(list).head = (elt); \
	} while (0)

#define ISC_LIST_PREPEND(list, elt, link) \
	do { \
		ISC_LINK_INSIST(!ISC_LINK_LINKED(elt, link)); \
		__ISC_LIST_PREPENDUNSAFE(list, elt, link); \
	} while (0)

#define ISC_LIST_INITANDPREPEND(list, elt, link) \
		__ISC_LIST_PREPENDUNSAFE(list, elt, link)

#define __ISC_LIST_APPENDUNSAFE(list, elt, link) \
	do { \
		if ((list).tail != NULL) \
			(list).tail->link.next = (elt); \
		else \
			(list).head = (elt); \
		(elt)->link.prev = (list).tail; \
		(elt)->link.next = NULL; \
		(list).tail = (elt); \
	} while (0)

#define ISC_LIST_APPEND(list, elt, link) \
	do { \
		ISC_LINK_INSIST(!ISC_LINK_LINKED(elt, link)); \
		__ISC_LIST_APPENDUNSAFE(list, elt, link); \
	} while (0)

#define ISC_LIST_INITANDAPPEND(list, elt, link) \
		__ISC_LIST_APPENDUNSAFE(list, elt, link)

#define __ISC_LIST_UNLINKUNSAFE_TYPE(list, elt, link, type) \
	do { \
		if ((elt)->link.next != NULL) \
			(elt)->link.next->link.prev = (elt)->link.prev; \
		else { \
			ISC_INSIST((list).tail == (elt)); \
			(list).tail = (elt)->link.prev; \
		} \
		if ((elt)->link.prev != NULL) \
			(elt)->link.prev->link.next = (elt)->link.next; \
		else { \
			ISC_INSIST((list).head == (elt)); \
			(list).head = (elt)->link.next; \
		} \
		(elt)->link.prev = (type *)(-1); \
		(elt)->link.next = (type *)(-1); \
		ISC_INSIST((list).head != (elt)); \
		ISC_INSIST((list).tail != (elt)); \
	} while (0)

#define __ISC_LIST_UNLINKUNSAFE(list, elt, link) \
	__ISC_LIST_UNLINKUNSAFE_TYPE(list, elt, link, void)

#define ISC_LIST_UNLINK_TYPE(list, elt, link, type) \
	do { \
		ISC_LINK_INSIST(ISC_LINK_LINKED(elt, link)); \
		__ISC_LIST_UNLINKUNSAFE_TYPE(list, elt, link, type); \
	} while (0)
#define ISC_LIST_UNLINK(list, elt, link) \
	ISC_LIST_UNLINK_TYPE(list, elt, link, void)

#define ISC_LIST_PREV(elt, link) ((elt)->link.prev)
#define ISC_LIST_NEXT(elt, link) ((elt)->link.next)

#define __ISC_LIST_INSERTBEFOREUNSAFE(list, before, elt, link) \
	do { \
		if ((before)->link.prev == NULL) \
			ISC_LIST_PREPEND(list, elt, link); \
		else { \
			(elt)->link.prev = (before)->link.prev; \
			(before)->link.prev = (elt); \
			(elt)->link.prev->link.next = (elt); \
			(elt)->link.next = (before); \
		} \
	} while (0)

#define ISC_LIST_INSERTBEFORE(list, before, elt, link) \
	do { \
		ISC_LINK_INSIST(ISC_LINK_LINKED(before, link)); \
		ISC_LINK_INSIST(!ISC_LINK_LINKED(elt, link)); \
		__ISC_LIST_INSERTBEFOREUNSAFE(list, before, elt, link); \
	} while (0)

#define __ISC_LIST_INSERTAFTERUNSAFE(list, after, elt, link) \
	do { \
		if ((after)->link.next == NULL) \
			ISC_LIST_APPEND(list, elt, link); \
		else { \
			(elt)->link.next = (after)->link.next; \
			(after)->link.next = (elt); \
			(elt)->link.next->link.prev = (elt); \
			(elt)->link.prev = (after); \
		} \
	} while (0)

#define ISC_LIST_INSERTAFTER(list, after, elt, link) \
	do { \
		ISC_LINK_INSIST(ISC_LINK_LINKED(after, link)); \
		ISC_LINK_INSIST(!ISC_LINK_LINKED(elt, link)); \
		__ISC_LIST_INSERTAFTERUNSAFE(list, after, elt, link); \
	} while (0)

#define ISC_LIST_APPENDLIST(list1, list2, link) \
	do { \
		if (ISC_LIST_EMPTY(list1)) \
			(list1) = (list2); \
		else if (!ISC_LIST_EMPTY(list2)) { \
			(list1).tail->link.next = (list2).head; \
			(list2).head->link.prev = (list1).tail; \
			(list1).tail = (list2).tail; \
		} \
		(list2).head = NULL; \
		(list2).tail = NULL; \
	} while (0)

#define ISC_LIST_PREPENDLIST(list1, list2, link) \
	do { \
		if (ISC_LIST_EMPTY(list1)) \
			(list1) = (list2); \
		else if (!ISC_LIST_EMPTY(list2)) { \
			(list2).tail->link.next = (list1).head; \
			(list1).head->link.prev = (list2).tail; \
			(list1).head = (list2).head; \
		} \
		(list2).head = NULL; \
		(list2).tail = NULL; \
	} while (0)

#define ISC_LIST_ENQUEUE(list, elt, link) ISC_LIST_APPEND(list, elt, link)
#define __ISC_LIST_ENQUEUEUNSAFE(list, elt, link) \
	__ISC_LIST_APPENDUNSAFE(list, elt, link)
#define ISC_LIST_DEQUEUE(list, elt, link) \
	 ISC_LIST_UNLINK_TYPE(list, elt, link, void)
#define ISC_LIST_DEQUEUE_TYPE(list, elt, link, type) \
	 ISC_LIST_UNLINK_TYPE(list, elt, link, type)
#define __ISC_LIST_DEQUEUEUNSAFE(list, elt, link) \
	__ISC_LIST_UNLINKUNSAFE_TYPE(list, elt, link, void)
#define __ISC_LIST_DEQUEUEUNSAFE_TYPE(list, elt, link, type) \
	__ISC_LIST_UNLINKUNSAFE_TYPE(list, elt, link, type)

/*
 * This is a generic implementation of a two-lock concurrent queue.
 * There are built-in mutex locks for the head and tail of the queue,
 * allowing elements to be safely added and removed at the same time.
 *
 * NULL is "end of list"
 * -1 is "not linked"
 */

#ifdef ISC_QUEUE_CHECKINIT
#define ISC_QLINK_INSIST(x) ISC_INSIST(x)
#else
#define ISC_QLINK_INSIST(x) (void)0
#endif

#define ISC_QLINK(type) struct { type *prev, *next; }

#define ISC_QLINK_INIT(elt, link) \
	do { \
		(elt)->link.next = (elt)->link.prev = (void *)(-1); \
	} while(0)

#define ISC_QLINK_LINKED(elt, link) ((void*)(elt)->link.next != (void*)(-1))

#define ISC_QUEUE(type) struct { \
	type *head, *tail; \
	isc_mutex_t headlock, taillock; \
}

#define ISC_QUEUE_INIT(queue, link) \
	do { \
		isc_mutex_init(&(queue).taillock); \
		isc_mutex_init(&(queue).headlock); \
		(queue).tail = (queue).head = NULL; \
	} while (0)

#define ISC_QUEUE_EMPTY(queue) ((queue).head == NULL)

#define ISC_QUEUE_DESTROY(queue) \
	do { \
		ISC_QLINK_INSIST(ISC_QUEUE_EMPTY(queue)); \
		isc_mutex_destroy(&(queue).taillock); \
		isc_mutex_destroy(&(queue).headlock); \
	} while (0)

/*
 * queues are meant to separate the locks at either end.  For best effect, that
 * means keeping the ends separate - i.e. non-empty queues work best.
 *
 * a push to an empty queue has to take the pop lock to update
 * the pop side of the queue.
 * Popping the last entry has to take the push lock to update
 * the push side of the queue.
 *
 * The order is (pop, push), because a pop is presumably in the
 * latency path and a push is when we're done.
 *
 * We do an MT hot test in push to see if we need both locks, so we can
 * acquire them in order.  Hopefully that makes the case where we get
 * the push lock and find we need the pop lock (and have to release it) rare.
 *
 * > 1 entry - no collision, push works on one end, pop on the other
 *   0 entry - headlock race
 *     pop wins - return(NULL), push adds new as both head/tail
 *     push wins - updates head/tail, becomes 1 entry case.
 *   1 entry - taillock race
 *     pop wins - return(pop) sets head/tail NULL, becomes 0 entry case
 *     push wins - updates {head,tail}->link.next, pop updates head
 *                 with new ->link.next and doesn't update tail
 *
 */
#define ISC_QUEUE_PUSH(queue, elt, link) \
	do { \
		bool headlocked = false; \
		ISC_QLINK_INSIST(!ISC_QLINK_LINKED(elt, link)); \
		if ((queue).head == NULL) { \
			LOCK(&(queue).headlock); \
			headlocked = true; \
		} \
		LOCK(&(queue).taillock); \
		if ((queue).tail == NULL && !headlocked) { \
			UNLOCK(&(queue).taillock); \
			LOCK(&(queue).headlock); \
			LOCK(&(queue).taillock); \
			headlocked = true; \
		} \
		(elt)->link.prev = (queue).tail; \
		(elt)->link.next = NULL; \
		if ((queue).tail != NULL) \
			(queue).tail->link.next = (elt); \
		(queue).tail = (elt); \
		UNLOCK(&(queue).taillock); \
		if (headlocked) { \
			if ((queue).head == NULL) \
				(queue).head = (elt); \
			UNLOCK(&(queue).headlock); \
		} \
	} while (0)

#define ISC_QUEUE_POP(queue, link, ret) \
	do { \
		LOCK(&(queue).headlock); \
		ret = (queue).head; \
		while (ret != NULL) { \
			if (ret->link.next == NULL) { \
				LOCK(&(queue).taillock); \
				if (ret->link.next == NULL) { \
					(queue).head = (queue).tail = NULL; \
					UNLOCK(&(queue).taillock); \
					break; \
				}\
				UNLOCK(&(queue).taillock); \
			} \
			(queue).head = ret->link.next; \
			(queue).head->link.prev = NULL; \
			break; \
		} \
		UNLOCK(&(queue).headlock); \
		if (ret != NULL) \
			(ret)->link.next = (ret)->link.prev = (void *)(-1); \
	} while(0)

#define ISC_QUEUE_UNLINK(queue, elt, link) \
	do { \
		ISC_QLINK_INSIST(ISC_QLINK_LINKED(elt, link)); \
		LOCK(&(queue).headlock); \
		LOCK(&(queue).taillock); \
		if ((elt)->link.prev == NULL) \
			(queue).head = (elt)->link.next; \
		else \
			(elt)->link.prev->link.next = (elt)->link.next; \
		if ((elt)->link.next == NULL) \
			(queue).tail = (elt)->link.prev; \
		else \
			(elt)->link.next->link.prev = (elt)->link.prev; \
		UNLOCK(&(queue).taillock); \
		UNLOCK(&(queue).headlock); \
		(elt)->link.next = (elt)->link.prev = (void *)(-1); \
	} while(0)

#endif /* ISC_LIST_H */
