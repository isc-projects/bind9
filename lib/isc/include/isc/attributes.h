/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#ifdef _WIN32
#define __attribute__(attribute) /* do nothing */
#else
#define __declspec(modifier) /* do nothing */
#endif

#if HAVE_FUNC_ATTRIBUTE_NORETURN
#define ISC_NORETURN __attribute__((noreturn))
#elif _WIN32
#define ISC_NORETURN __declspec(noreturn)
#else
#define ISC_NORETURN
#endif
