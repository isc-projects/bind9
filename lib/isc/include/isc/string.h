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

/*! \file isc/string.h */

#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

#if !defined(HAVE_STRLCPY)
size_t
strlcpy(char *dst, const char *src, size_t size);
#endif /* !defined(HAVE_STRLCPY) */

#if !defined(HAVE_STRLCAT)
size_t
strlcat(char *dst, const char *src, size_t size);
#endif /* if !defined(HAVE_STRLCAT) */

#if !defined(HAVE_STRNSTR)
char *
strnstr(const char *s, const char *find, size_t slen);
#endif /* if !defined(HAVE_STRNSTR) */

int
isc_string_strerror_r(int errnum, char *buf, size_t buflen);

/*
 * Return true when 'str' begins with 'prefix', compared case
 * sensitively.
 */
static inline bool
isc_string_hasprefix(const char *str, const char *prefix) {
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

/*
 * Return true when 'str' begins with 'prefix', compared case
 * insensitively.
 */
static inline bool
isc_string_casehasprefix(const char *str, const char *prefix) {
	return strncasecmp(str, prefix, strlen(prefix)) == 0;
}

/*
 * Match the beginning of 'str' against 'prefix' (case sensitively)
 * and strip the prefix: return the remainder of 'str' after 'prefix',
 * or NULL when 'str' does not begin with 'prefix'.
 */
static inline const char *
isc_string_stripprefix(const char *str, const char *prefix) {
	size_t len = strlen(prefix);
	return strncmp(str, prefix, len) == 0 ? str + len : NULL;
}

/*
 * Match the beginning of 'str' against 'prefix' (case insensitively)
 * and strip the prefix: return the remainder of 'str' after 'prefix',
 * or NULL when 'str' does not begin with 'prefix'.
 */
static inline const char *
isc_string_casestripprefix(const char *str, const char *prefix) {
	size_t len = strlen(prefix);
	return strncasecmp(str, prefix, len) == 0 ? str + len : NULL;
}

ISC_LANG_ENDDECLS
