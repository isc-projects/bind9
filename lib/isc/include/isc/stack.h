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

#include <isc/assertions.h>
#include <isc/atomic.h>
#include <isc/list.h>
#include <isc/pause.h>

/*
 * Single links, aka stack links
 */

#define ISC_SLINK(type)     \
	struct {            \
		type *next; \
	}
#define ISC_SLINK_INITIALIZER_TYPE(type)          \
	{                                         \
		.next = ISC_LINK_TOMBSTONE(type), \
	}
#define ISC_SLINK_INIT_TYPE(elt, link, type)                 \
	{                                                    \
		(elt)->link.next = ISC_LINK_TOMBSTONE(type); \
	}

#define ISC_SLINK_INITIALIZER	  ISC_SLINK_INITIALIZER_TYPE(void)
#define ISC_SLINK_INIT(elt, link) ISC_SLINK_INIT_TYPE(elt, link, void)

#define ISC_SLINK_LINKED_TYPE(elt, link, type) \
	((type *)((elt)->link.next) != ISC_LINK_TOMBSTONE(type))
#define ISC_SLINK_LINKED(elt, link) ISC_SLINK_LINKED_TYPE(elt, link, void)

#define ISC_SLINK_NEXT(elt, link) ((elt)->link.next)

/*
 * Simple singly-linked stack implementation
 */

#define ISC_STACK(type)    \
	struct {           \
		type *top; \
	}

#define ISC_STACK_INITIALIZER \
	{                     \
		.top = NULL,  \
	}
#define ISC_STACK_INIT(stack)       \
	{                           \
		(stack).top = NULL; \
	}

#define ISC_STACK_TOP(stack)   ((stack).top)
#define ISC_STACK_EMPTY(stack) ((stack).top == NULL)

#define ISC_STACK_PUSHUNSAFE(stack, elt, link)  \
	{                                       \
		(elt)->link.next = (stack).top; \
		(stack).top = (elt);            \
	}

#define ISC_STACK_PUSH(stack, elt, link)                \
	{                                               \
		INSIST(!ISC_SLINK_LINKED(elt, link));   \
		ISC_STACK_PUSHUNSAFE(stack, elt, link); \
	}

/*
 * This is slightly round about because when `type` is `void`
 * we can't directly access `__top->link.next`.
 */
#define ISC_STACK_POP_TYPE(stack, link, type)                             \
	({                                                                \
		type *__top = (stack).top;                                \
		if (__top != NULL) {                                      \
			type *__next = ISC_SLINK_NEXT((stack).top, link); \
			ISC_SLINK_INIT_TYPE((stack).top, link, type);     \
			(stack).top = __next;                             \
		}                                                         \
		__top;                                                    \
	})

#define ISC_STACK_POP(stack, link) ISC_STACK_POP_TYPE(stack, link, void)

/*
 * Helper to add element if not already on stack.
 */
#define ISC_STACK_ADD(stack, elt, link)                         \
	{                                                       \
		if (!ISC_STACK_LINKED(elt, link)) {             \
			ISC_STACK_PUSHUNSAFE(stack, elt, link); \
		}                                               \
	}

/*
 * This is a simplified implementation of the Treiber stack algorithm with
 * back-off.
 *
 * The original paper which describes the algorithm can be found here:
 * https://dominoweb.draco.res.ibm.com/58319a2ed2b1078985257003004617ef.html
 *
 * We sidestep the ABA problem when removing the elements by adding additional
 * constraint: once the element has been removed from the stack, it cannot be
 * re-added.
 *
 * This is actually not a problem for planned usage of the ISC_ASTACK where we
 * only use ISC_ASTACK_PUSH() to add individual elements and ISC_ASTACK_DRAIN()
 * to empty the stack in a single atomic operation.
 *
 * To make things simple, there's no implementation for ISC_ASTACK_POP() because
 * that's complex to implement and requires double-word CAS (for ABA counter).
 *
 * The pointers are wrapped in structs so that their types are
 * distinct, and to match the ISC_LIST macros.
 *
 * See doc/dev/dev.md for examples.
 */

#define ISC_ASTACK(type)               \
	struct {                       \
		atomic_ptr(type) atop; \
	}
#define ISC_ASTACK_INITIALIZER \
	{                      \
		.atop = NULL,  \
	}
#define ISC_ASTACK_INIT(stack)       \
	{                            \
		(stack).atop = NULL; \
	}

/*
 * ATOMIC: for performance, this kind of retry loop should use a weak
 * CAS with relaxed ordering in the failure case; on success, release
 * ordering ensures that writing the element contents happens before
 * reading them, following the acquire in ISC_ASTACK_TOP() and _DRAIN().
 */
#define ISC_ASTACK_PUSHUNSAFE(stack, elt, link)                         \
	{                                                               \
		(elt)->link.next = atomic_load_relaxed(&(stack).atop);  \
		while (!atomic_compare_exchange_weak_explicit(          \
			&(stack).atop, &ISC_SLINK_NEXT(elt, link), elt, \
			memory_order_release, memory_order_relaxed))    \
		{                                                       \
			isc_pause();                                    \
		}                                                       \
	}

#define ISC_ASTACK_PUSH(stack, elt, link)                \
	{                                                \
		INSIST(!ISC_SLINK_LINKED(elt, link));    \
		ISC_ASTACK_PUSHUNSAFE(stack, elt, link); \
	}

/*
 * Helper to add element if not already on stack.
 */
#define ISC_ASTACK_ADD(stack, elt, link)                         \
	{                                                        \
		if (!ISC_SLINK_LINKED(elt, link)) {              \
			ISC_ASTACK_PUSHUNSAFE(stack, elt, link); \
		}                                                \
	}

/*
 * ATOMIC: acquire ordering pairs with ISC_ASTACK_PUSHUNSAFEe()
 */
#define ISC_ASTACK_TOP(stack)	atomic_load_acquire(&(stack).atop)
#define ISC_ASTACK_EMPTY(stack) (ISC_ASTACK_TOP(stack) == NULL)

/*
 * ATOMIC: acquire ordering pairs with ISC_ASTACK_PUSHUNSAFE()
 */
#define ISC_ASTACK_TO_STACK(stack)                                   \
	{                                                            \
		.top = atomic_exchange_acquire(&(stack).atop, NULL), \
	}
