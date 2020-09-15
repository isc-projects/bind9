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

#ifndef LWRES_STRING_H
#define LWRES_STRING_H 1

/*! \file lwres/string.h */

#include <stdlib.h>

#include <lwres/lang.h>
#include <lwres/platform.h>

#ifdef LWRES_PLATFORM_NEEDSTRLCPY
#define strlcpy lwres_strlcpy
#endif

LWRES_LANG_BEGINDECLS

size_t lwres_strlcpy(char *dst, const char *src, size_t size);

LWRES_LANG_ENDDECLS

#endif
