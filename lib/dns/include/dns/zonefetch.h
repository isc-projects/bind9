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

/*! \file dns/zonefetch.h */

#include <isc/mem.h>
#include <isc/result.h>

#include <dns/db.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/zone.h>

/*%
 * Fetch type; various features can initiate fetching and this enum value
 * allows common code paths to differentiate between them.
 *
 * ZONEFETCHTYPE_COUNT is not actually a zonefetch type and needs to be in
 * the last position of the enum.
 */
typedef enum {
	ZONEFETCHTYPE_DSYNC,
	ZONEFETCHTYPE_KEY,
	ZONEFETCHTYPE_NS,
	ZONEFETCHTYPE_COUNT,
} dns_zonefetch_type_t;

typedef struct dns_dsyncfetch dns_dsyncfetch_t;
typedef struct dns_keyfetch   dns_keyfetch_t;
typedef struct dns_nsfetch    dns_nsfetch_t;
typedef struct dns_zonefetch  dns_zonefetch_t;

/*
 * Fetch methods.
 */
typedef struct dns_zonefetch_methods {
	isc_result_t (*start_fetch)(dns_zonefetch_t *fetch);
	void (*continue_fetch)(dns_zonefetch_t *fetch);
	void (*cleanup_fetch)(dns_zonefetch_t *fetch);
	isc_result_t (*done_fetch)(dns_zonefetch_t *fetch,
				   isc_result_t	    eresult);
} dns_zonefetch_methods_t;

/*
 * Fetch contexts.
 */
struct dns_dsyncfetch {
	dns_fixedname_t dsyncname;
	dns_name_t	pname;
};

struct dns_keyfetch {
	dns_rdataset_t keydataset;
	dns_db_t      *db;
};

struct dns_nsfetch {
	dns_name_t pname;
};

typedef union dns_fetchdata {
	dns_dsyncfetch_t dsyncfetch;
	dns_keyfetch_t	 keyfetch;
	dns_nsfetch_t	 nsfetch;
} dns_zonefetch_data_t;

struct dns_zonefetch {
	/* Fetch context */
	dns_fetch_t    *fetch;
	isc_mem_t      *mctx;
	dns_zone_t     *zone;
	dns_fixedname_t name;

	/* Status */
	bool canceled;

	/* Query */
	dns_name_t     *qname;
	dns_rdatatype_t qtype;
	unsigned int	options;

	/* Response */
	dns_rdataset_t rrset;
	dns_rdataset_t sigset;

	/* Type specific */
	dns_zonefetch_type_t	fetchtype;
	dns_zonefetch_data_t	fetchdata;
	dns_zonefetch_methods_t fetchmethods;
};

void
dns_zonefetch_run(void *arg);
/*%<
 *      Start a zone fetch. This starts a query for a given qname and qtype, and
 *	recurses to answer a question. The type of fetch depends on the
 *	fetchtype.
 */

void
dns_zonefetch_done(void *arg);
/*%<
 *	Complete a zone fetch. This may trigger follow-up actions that depend on
 *	the fetch type.
 */

void
dns_zonefetch_schedule(dns_zonefetch_t *fetch, dns_name_t *name);
/*%<
 *	Schedule a zone fetch, starting at 'name'.  Initializes the rdata sets,
 *	and sets the starting name to 'name'. Note that the query type is
 *	determined by the type of zone fetch. This function also increments the
 *	corresponding zone's ireferences (to be decremented in
 *	dns_zonefetch_done()).
 *
 *	Requires:
 *		'fetch' is not NULL.
 *		'name' is not NULL.
 */

void
dns_zonefetch_reschedule(dns_zonefetch_t *fetch);
/*%<
 *	Reschedule a zone fetch.  Initializes the rdata sets and increments the
 *	corresponding zone's ireferences (to be decremented in
 *	dns_zonefetch_done()).
 *
 *	Requires:
 *		'fetch' is not NULL.
 *		'name' is not NULL.
 */

isc_result_t
dns_zonefetch_verify(dns_zonefetch_t *fetch, isc_result_t eresult,
		     dns_trust_t trust);
/*%<
 *      Check a completed zone fetch. This checks the response result,
 *	if there are records and signatures available, and the	level of trust.
 *
 *	Requires:
 *		'fetch' is not NULL.
 *
 *	Returns:
 *		ISC_R_SUCCESS    - if the completed zone fetch is verified.
 *		ISC_R_NOTFOUND	 - if no records are found.
 *		DNS_R_NOVALIDSIG - if no signatures are available, or the trust
 *				   level is below 'trust'.
 *	 	eresult		 - error code in case the fetch failed.
 */
