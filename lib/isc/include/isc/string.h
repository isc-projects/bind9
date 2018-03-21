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

/* $Id: string.h,v 1.23 2007/09/13 04:48:16 each Exp $ */

#ifndef ISC_STRING_H
#define ISC_STRING_H 1

/*! \file isc/string.h */

#include <isc/formatcheck.h>
#include <isc/int.h>
#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>

#include <string.h>

#ifdef ISC_PLATFORM_HAVESTRINGSH
#include <strings.h>
#endif

#define ISC_STRING_MAGIC 0x5e

ISC_LANG_BEGINDECLS

char *
isc_string_separate(char **stringp, const char *delim);

#ifdef ISC_PLATFORM_NEEDSTRSEP
#define strsep isc_string_separate
#endif

#ifdef ISC_PLATFORM_NEEDMEMMOVE
#define memmove(a,b,c) bcopy(b,a,c)
#endif

size_t
isc_string_strlcpy(char *dst, const char *src, size_t size);


#ifdef ISC_PLATFORM_NEEDSTRLCPY
#define strlcpy isc_string_strlcpy
#endif


size_t
isc_string_strlcat(char *dst, const char *src, size_t size);

#ifdef ISC_PLATFORM_NEEDSTRLCAT
#define strlcat isc_string_strlcat
#endif

char *
isc_string_strcasestr(const char *big, const char *little);

#ifdef ISC_PLATFORM_NEEDSTRCASESTR
#define strcasestr isc_string_strcasestr
#endif

ISC_LANG_ENDDECLS

#endif /* ISC_STRING_H */
