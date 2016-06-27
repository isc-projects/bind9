/*
 * Copyright (C) 1999-2001, 2004-2007, 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: lib.h,v 1.18 2009/09/02 23:48:02 tbox Exp $ */

#ifndef DNS_LIB_H
#define DNS_LIB_H 1

/*! \file dns/lib.h */

#include <isc/types.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

/*%
 * Tuning: external query load in packets per seconds.
 */
LIBDNS_EXTERNAL_DATA extern unsigned int dns_pps;
LIBDNS_EXTERNAL_DATA extern isc_msgcat_t *dns_msgcat;

void
dns_lib_initmsgcat(void);
/*%<
 * Initialize the DNS library's message catalog, dns_msgcat, if it
 * has not already been initialized.
 */

isc_result_t
dns_lib_init(void);
/*%<
 * A set of initialization procedure used in the DNS library.  This function
 * is provided for an application that is not aware of the underlying ISC or
 * DNS libraries much.
 */

void
dns_lib_shutdown(void);
/*%<
 * Free temporary resources allocated in dns_lib_init().
 */

ISC_LANG_ENDDECLS

#endif /* DNS_LIB_H */
