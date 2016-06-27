/*
 * Copyright (C) 1998-2001, 2004-2007, 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: error.h,v 1.22 2009/09/29 23:48:04 tbox Exp $ */

#ifndef ISC_ERROR_H
#define ISC_ERROR_H 1

/*! \file isc/error.h */

#include <stdarg.h>

#include <isc/formatcheck.h>
#include <isc/lang.h>
#include <isc/platform.h>

ISC_LANG_BEGINDECLS

typedef void (*isc_errorcallback_t)(const char *, int, const char *, va_list);

/*% set unexpected error */
void
isc_error_setunexpected(isc_errorcallback_t);

/*% set fatal error */
void
isc_error_setfatal(isc_errorcallback_t);

/*% unexpected error */
void
isc_error_unexpected(const char *, int, const char *, ...)
     ISC_FORMAT_PRINTF(3, 4);

/*% fatal error */
ISC_PLATFORM_NORETURN_PRE void
isc_error_fatal(const char *, int, const char *, ...)
ISC_FORMAT_PRINTF(3, 4) ISC_PLATFORM_NORETURN_POST;

/*% runtimecheck error */
void
isc_error_runtimecheck(const char *, int, const char *);

#define ISC_ERROR_RUNTIMECHECK(cond) \
	((void) (ISC_LIKELY(cond) || \
		 ((isc_error_runtimecheck)(__FILE__, __LINE__, #cond), 0)))

ISC_LANG_ENDDECLS

#endif /* ISC_ERROR_H */
