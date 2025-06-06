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

/*****
***** Module Info
*****/

/*! \file dns/rdatasetiter.h
 * \brief
 * The DNS Rdataset Iterator interface allows iteration of all of the
 * rdatasets at a node.
 *
 * The dns_rdatasetiter_t type is like a "virtual class".  To actually use
 * it, an implementation of the class is required.  This implementation is
 * supplied by the database.
 *
 * It is the client's responsibility to call dns_rdataset_disassociate()
 * on all rdatasets returned.
 *
 * XXX more XXX
 *
 * MP:
 *\li	The iterator itself is not locked.  The caller must ensure
 *	synchronization.
 *
 *\li	The iterator methods ensure appropriate database locking.
 *
 * Reliability:
 *\li	No anticipated impact.
 *
 * Resources:
 *\li	TBS
 *
 * Security:
 *\li	No anticipated impact.
 *
 * Standards:
 *\li	None.
 */

/*****
***** Imports
*****/

#include <isc/magic.h>
#include <isc/stdtime.h>

#include <dns/types.h>

/*****
***** Types
*****/

typedef struct dns_rdatasetitermethods {
	void (*destroy)(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);
	isc_result_t (*first)(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
	isc_result_t (*next)(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
	void (*current)(dns_rdatasetiter_t	*iterator,
			dns_rdataset_t *rdataset DNS__DB_FLARG);
} dns_rdatasetitermethods_t;

#define DNS_RDATASETITER_MAGIC	  ISC_MAGIC('D', 'N', 'S', 'i')
#define DNS_RDATASETITER_VALID(i) ISC_MAGIC_VALID(i, DNS_RDATASETITER_MAGIC)

/*%
 * This structure is actually just the common prefix of a DNS db
 * implementation's version of a dns_rdatasetiter_t.
 * \brief
 * Direct use of this structure by clients is forbidden.  DB implementations
 * may change the structure.  'magic' must be #DNS_RDATASETITER_MAGIC for
 * any of the dns_rdatasetiter routines to work.  DB implementations must
 * maintain all DB rdataset iterator invariants.
 */
struct dns_rdatasetiter {
	/* Unlocked. */
	unsigned int		   magic;
	dns_rdatasetitermethods_t *methods;
	dns_db_t		  *db;
	dns_dbnode_t		  *node;
	dns_dbversion_t		  *version;
	isc_stdtime_t		   now;
	unsigned int		   options;
};

/* clang-format off */
/*
 * This is a hack to build a unique variable name to
 * replace 'res' below. (Two layers of macro indirection are
 * needed to make the line number be part of the variable
 * name; otherwise it would just be "x__LINE__".)
 */
#define DNS__RDATASETITER_CONNECT(x,y) x##y
#define DNS__RDATASETITER_CONCAT(x,y) DNS__RDATASETITER_CONNECT(x,y)
#define DNS_RDATASETITER_FOREACH_RES(rds, res)                         \
	for (isc_result_t res = dns_rdatasetiter_first((rds));       \
	     res == ISC_R_SUCCESS; res = dns_rdatasetiter_next((rds)))
#define DNS_RDATASETITER_FOREACH(rds)               \
	DNS_RDATASETITER_FOREACH_RES(rds, DNS__RDATASETITER_CONCAT(x, __LINE__))
/* clang-format on */

#define dns_rdatasetiter_destroy(iteratorp) \
	dns__rdatasetiter_destroy(iteratorp DNS__DB_FILELINE)
void
dns__rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);
/*%<
 * Destroy '*iteratorp'.
 *
 * Requires:
 *
 *\li	'*iteratorp' is a valid iterator.
 *
 * Ensures:
 *
 *\li	All resources used by the iterator are freed.
 *
 *\li	*iteratorp == NULL.
 */

#define dns_rdatasetiter_first(iterator) \
	dns__rdatasetiter_first(iterator DNS__DB_FILELINE)
isc_result_t
dns__rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
/*%<
 * Move the rdataset cursor to the first rdataset at the node (if any).
 *
 * Requires:
 *\li	'iterator' is a valid iterator.
 *
 * Returns:
 *\li	ISC_R_SUCCESS
 *\li	ISC_R_NOMORE			There are no rdatasets at the node.
 *
 *\li	Other results are possible, depending on the DB implementation.
 */

#define dns_rdatasetiter_next(iterator) \
	dns__rdatasetiter_next(iterator DNS__DB_FILELINE)
isc_result_t
dns__rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
/*%<
 * Move the rdataset cursor to the next rdataset at the node (if any).
 *
 * Requires:
 *\li	'iterator' is a valid iterator.
 *
 * Returns:
 *\li	ISC_R_SUCCESS
 *\li	ISC_R_NOMORE			There are no more rdatasets at the
 *					node.
 *
 *\li	Other results are possible, depending on the DB implementation.
 */

#define dns_rdatasetiter_current(iterator, rdataset) \
	dns__rdatasetiter_current(iterator, rdataset DNS__DB_FILELINE)
void
dns__rdatasetiter_current(dns_rdatasetiter_t	  *iterator,
			  dns_rdataset_t *rdataset DNS__DB_FLARG);
/*%<
 * Return the current rdataset.
 *
 * Requires:
 *\li	'iterator' is a valid iterator.
 *
 *\li	'rdataset' is a valid, disassociated rdataset.
 *
 *\li	The rdataset cursor of 'iterator' is at a valid location (i.e. the
 *	result of last call to a cursor movement command was #ISC_R_SUCCESS).
 */
