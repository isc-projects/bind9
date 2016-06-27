/*
 * Copyright (C) 2001, 2004, 2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: strerror.h,v 1.5 2007/06/19 23:47:20 tbox Exp $ */

#ifndef ISC_STRERROR_H
#define ISC_STRERROR_H

#include <sys/types.h>

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

#define ISC_STRERRORSIZE 128

/*
 * Provide a thread safe wrapper to strerrror().
 *
 * Requires:
 * 	'buf' to be non NULL.
 */
void
isc__strerror(int num, char *buf, size_t bufsize);

ISC_LANG_ENDDECLS

#endif /* ISC_STRERROR_H */
