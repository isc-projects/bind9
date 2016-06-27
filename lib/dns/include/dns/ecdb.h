/*
 * Copyright (C) 2009, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: ecdb.h,v 1.3 2009/09/02 23:48:02 tbox Exp $ */

#ifndef DNS_ECDB_H
#define DNS_ECDB_H 1

/*****
 ***** Module Info
 *****/

/* TBD */

/***
 *** Imports
 ***/

#include <dns/types.h>

/***
 *** Types
 ***/

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

/* TBD: describe those */

isc_result_t
dns_ecdb_register(isc_mem_t *mctx, dns_dbimplementation_t **dbimp);

void
dns_ecdb_unregister(dns_dbimplementation_t **dbimp);

ISC_LANG_ENDDECLS

#endif /* DNS_ECDB_H */
