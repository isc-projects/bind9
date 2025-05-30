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

/***
 *** Attribute Compatibility Macros
 ***/

#ifndef __has_c_attribute
#define __has_c_attribute(x) 0
#endif /* __has_c_attribute */

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif /* __has_attribute */

#if __has_c_attribute(noreturn) && __STDC_VERSION__ >= 202311L
#define ISC_NORETURN [[noreturn]]
#else
#define ISC_NORETURN _Noreturn
#endif

#if HAVE_FUNC_ATTRIBUTE_RETURNS_NONNULL
#define ISC_ATTR_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define ISC_ATTR_RETURNS_NONNULL
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_MALLOC
/*
 * Indicates that a function is malloc-like, i.e., that the
 * pointer P returned by the function cannot alias any other
 * pointer valid when the function returns.
 */
#define ISC_ATTR_MALLOC __attribute__((malloc))
#if HAVE_MALLOC_EXT_ATTR
/*
 * Associates deallocator as a suitable deallocation function
 * for pointers returned from the function marked with the attribute.
 */
#define ISC_ATTR_DEALLOCATOR(deallocator) __attribute__((malloc(deallocator)))
/*
 * Similar to ISC_ATTR_DEALLOCATOR, but allows to speficy an index "idx",
 * which denotes the positional argument to which when the pointer is passed
 * in calls to deallocator has the effect of deallocating it.
 */
#define ISC_ATTR_DEALLOCATOR_IDX(deallocator, idx) \
	__attribute__((malloc(deallocator, idx)))
/*
 * Combines both ISC_ATTR_MALLOC and ISC_ATTR_DEALLOCATOR attributes.
 */
#define ISC_ATTR_MALLOC_DEALLOCATOR(deallocator) \
	__attribute__((malloc, malloc(deallocator)))
/*
 * Similar to ISC_ATTR_MALLOC_DEALLOCATOR, but allows to speficy an index "idx",
 * which denotes the positional argument to which when the pointer is passed
 * in calls to deallocator has the effect of deallocating it.
 */
#define ISC_ATTR_MALLOC_DEALLOCATOR_IDX(deallocator, idx) \
	__attribute__((malloc, malloc(deallocator, idx)))
#else /* #ifdef HAVE_MALLOC_EXT_ATTR */
/*
 * There is support for malloc attribute but not for
 * extended attributes, so macros that combine attribute malloc
 * with a deallocator will only expand to malloc attribute.
 */
#define ISC_ATTR_DEALLOCATOR(deallocator)
#define ISC_ATTR_DEALLOCATOR_IDX(deallocator, idx)
#define ISC_ATTR_MALLOC_DEALLOCATOR(deallocator)	  ISC_ATTR_MALLOC
#define ISC_ATTR_MALLOC_DEALLOCATOR_IDX(deallocator, idx) ISC_ATTR_MALLOC
#endif
#else /* #ifdef HAVE_FUNC_ATTRIBUTE_MALLOC */
/*
 * There is no support for malloc attribute.
 */
#define ISC_ATTR_MALLOC
#define ISC_ATTR_DEALLOCATOR(deallocator)
#define ISC_ATTR_DEALLOCATOR_IDX(deallocator, idx)
#define ISC_ATTR_MALLOC_DEALLOCATOR(deallocator)
#define ISC_ATTR_MALLOC_DEALLOCATOR_IDX(deallocator, idx)
#endif /* HAVE_FUNC_ATTRIBUTE_MALLOC */

#if __has_c_attribute(fallthrough)
#define FALLTHROUGH [[fallthrough]]
#elif __GNUC__ >= 7 && !defined(__clang__)
#define FALLTHROUGH __attribute__((fallthrough))
#else
/* clang-format off */
#define FALLTHROUGH do {} while (0) /* FALLTHROUGH */
/* clang-format on */
#endif

#if __has_c_attribute(maybe_unused)
#define ISC_ATTR_UNUSED [[maybe_unused]]
#else
#define ISC_ATTR_UNUSED __attribute__((__unused__))
#endif

#if __has_attribute(__counted_by__)
#define ISC_ATTR_COUNTED_BY(x) __attribute__((__counted_by__(x)))
#else
#define ISC_ATTR_COUNTED_BY(x)
#endif
