/*
 * Copyright (C) 2001, 2004, 2005, 2007, 2008, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: strerror.h,v 1.10 2008/12/01 23:47:45 tbox Exp $ */

#ifndef ISC_STRERROR_H
#define ISC_STRERROR_H

/*! \file */

#include <sys/types.h>

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

/*% String Error Size */
#define ISC_STRERRORSIZE 128

/*%
 * Provide a thread safe wrapper to strerror().
 *
 * Requires:
 * 	'buf' to be non NULL.
 */
void
isc__strerror(int num, char *buf, size_t bufsize);

ISC_LANG_ENDDECLS

#endif /* ISC_STRERROR_H */
