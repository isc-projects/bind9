/*
 * Copyright (C) 2000, 2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: os.h,v 1.12 2007/06/19 23:47:18 tbox Exp $ */

#ifndef ISC_OS_H
#define ISC_OS_H 1

/*! \file isc/os.h */

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

unsigned int
isc_os_ncpus(void);
/*%<
 * Return the number of CPUs available on the system, or 1 if this cannot
 * be determined.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_OS_H */
