/*
 * Copyright (C) 1999-2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: lib.h,v 1.7 2007/06/19 23:47:17 tbox Exp $ */

#ifndef DST_LIB_H
#define DST_LIB_H 1

/*! \file dst/lib.h */

#include <isc/types.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

LIBDNS_EXTERNAL_DATA extern isc_msgcat_t *dst_msgcat;

void
dst_lib_initmsgcat(void);
/*
 * Initialize the DST library's message catalog, dst_msgcat, if it
 * has not already been initialized.
 */

ISC_LANG_ENDDECLS

#endif /* DST_LIB_H */
