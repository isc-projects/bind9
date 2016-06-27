/*
 * Copyright (C) 1999-2001, 2004, 2005, 2007, 2011, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id$ */

#ifndef DNS_RBTDB_H
#define DNS_RBTDB_H 1

#include <isc/lang.h>
#include <dns/types.h>

/*****
 ***** Module Info
 *****/

/*! \file
 * \brief
 * DNS Red-Black Tree DB Implementation
 */

ISC_LANG_BEGINDECLS

isc_result_t
dns_rbtdb_create(isc_mem_t *mctx, dns_name_t *base, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp);

/*%<
 * Create a new database of type "rbt" (or "rbt64").  Called via
 * dns_db_create(); see documentation for that function for more details.
 *
 * If argv[0] is set, it points to a valid memory context to be used for
 * allocation of heap memory.  Generally this is used for cache databases
 * only.
 *
 * Requires:
 *
 * \li argc == 0 or argv[0] is a valid memory context.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_RBTDB_H */
