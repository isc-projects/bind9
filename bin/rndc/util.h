/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: util.h,v 1.12 2009/09/29 23:48:03 tbox Exp $ */

#ifndef RNDC_UTIL_H
#define RNDC_UTIL_H 1

/*! \file */

#include <isc/lang.h>
#include <isc/platform.h>

#include <isc/formatcheck.h>

#define NS_CONTROL_PORT		953

#undef DO
#define DO(name, function) \
	do { \
		result = function; \
		if (result != ISC_R_SUCCESS) \
			fatal("%s: %s", name, isc_result_totext(result)); \
		else \
			notify("%s", name); \
	} while (0)

ISC_LANG_BEGINDECLS

void
notify(const char *fmt, ...) ISC_FORMAT_PRINTF(1, 2);

ISC_PLATFORM_NORETURN_PRE void
fatal(const char *format, ...)
ISC_FORMAT_PRINTF(1, 2) ISC_PLATFORM_NORETURN_POST;

ISC_LANG_ENDDECLS

#endif /* RNDC_UTIL_H */
