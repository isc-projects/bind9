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

/*! \file dns/diff.h
 * \brief
 * A diff is a convenience type representing a list of changes to be
 * made to a database.
 */

/***
 *** Imports
 ***/

#include <stddef.h>

#include <isc/magic.h>

#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/types.h>

/***
 *** Types
 ***/

/*%
 * A dns_difftuple_t represents a single RR being added or deleted.
 * The RR type and class are in the 'rdata' member; the class is always
 * the real one, not a DynDNS meta-class, so that the rdatas can be
 * compared using dns_rdata_compare().  The TTL is significant
 * even for deletions, because a deletion/addition pair cannot
 * be canceled out if the TTL differs (it might be an explicit
 * TTL update).
 *
 * Tuples are also used to represent complete RRs with owner
 * names for a couple of other purposes, such as the
 * individual RRs of a "RRset exists (value dependent)"
 * prerequisite set.  In this case, op==DNS_DIFFOP_EXISTS,
 * and the TTL is ignored.
 *
 * DNS_DIFFOP_*RESIGN will cause the 'resign' attribute of the resulting
 * RRset to be recomputed to be 'resign' seconds before the earliest RRSIG
 * timeexpire.
 */

typedef enum {
	DNS_DIFFOP_ADD = 0,	  /*%< Add an RR. */
	DNS_DIFFOP_DEL = 1,	  /*%< Delete an RR. */
	DNS_DIFFOP_EXISTS = 2,	  /*%< Assert RR existence. */
	DNS_DIFFOP_ADDRESIGN = 4, /*%< ADD + RESIGN. */
	DNS_DIFFOP_DELRESIGN = 5  /*%< DEL + RESIGN. */
} dns_diffop_t;

typedef struct dns_difftuple dns_difftuple_t;
typedef ISC_LIST(dns_difftuple_t) dns_difftuplelist_t;

#define DNS_DIFFTUPLE_MAGIC    ISC_MAGIC('D', 'I', 'F', 'T')
#define DNS_DIFFTUPLE_VALID(t) ISC_MAGIC_VALID(t, DNS_DIFFTUPLE_MAGIC)

struct dns_difftuple {
	unsigned int magic;
	isc_mem_t   *mctx;
	dns_diffop_t op;
	dns_name_t   name;
	dns_ttl_t    ttl;
	dns_rdata_t  rdata;
	ISC_LINK(dns_difftuple_t) link;
	/* Variable-size name data and rdata follows. */
};

/*%
 * A dns_diff_t represents a set of changes being applied to
 * a zone.  Diffs are also used to represent "RRset exists
 * (value dependent)" prerequisites.
 */
typedef struct dns_diff dns_diff_t;

#define DNS_DIFF_MAGIC	  ISC_MAGIC('D', 'I', 'F', 'F')
#define DNS_DIFF_VALID(t) ISC_MAGIC_VALID(t, DNS_DIFF_MAGIC)

struct dns_diff {
	unsigned int	    magic;
	isc_mem_t	   *mctx;
	dns_difftuplelist_t tuples;
	size_t		    size;
};

/* Type of comparison function for sorting diffs. */
typedef int
dns_diff_compare_func(const void *, const void *);

/***
 *** Functions
 ***/

/**************************************************************************/
/*
 * Manipulation of diffs and tuples.
 */

void
dns_difftuple_create(isc_mem_t *mctx, dns_diffop_t op, const dns_name_t *name,
		     dns_ttl_t ttl, dns_rdata_t *rdata, dns_difftuple_t **tp);
/*%<
 * Create a tuple.  Deep copies are made of the name and rdata, so
 * they need not remain valid after the call.
 *
 * Requires:
 *\li	*tp != NULL && *tp == NULL.
 */

void
dns_difftuple_free(dns_difftuple_t **tp);
/*%<
 * Free a tuple.
 *
 * Requires:
 *    \li   **tp is a valid tuple.
 *
 * Ensures:
 *     \li  *tp == NULL
 *      \li All memory used by the tuple is freed.
 */

void
dns_difftuple_copy(dns_difftuple_t *orig, dns_difftuple_t **copyp);
/*%<
 * Copy a tuple.
 *
 * Requires:
 * \li	'orig' points to a valid tuple
 * \li	copyp != NULL && *copyp == NULL
 */

void
dns_diff_init(isc_mem_t *mctx, dns_diff_t *diff);
/*%<
 * Initialize a diff.
 *
 * Requires:
 * \li   'diff' points to an uninitialized dns_diff_t
 *  \li  allocated by the caller.
 *
 * Ensures:
 * \li   '*diff' is a valid, empty diff.
 */

void
dns_diff_clear(dns_diff_t *diff);
/*%<
 * Clear a diff, destroying all its tuples.
 *
 * Requires:
 * \li   'diff' points to a valid dns_diff_t.
 *
 * Ensures:
 * \li    Any tuples in the diff are destroyed.
 *     The diff now empty, but it is still valid
 *     and may be reused without calling dns_diff_init
 *     again.  The only memory used is that of the
 *     dns_diff_t structure itself.
 *
 * Notes:
 * \li    Managing the memory of the dns_diff_t structure itself
 *     is the caller's responsibility.
 */

void
dns_diff_append(dns_diff_t *diff, dns_difftuple_t **tuple);
/*%<
 * Append a single tuple to a diff.
 *
 * Requires:
 * \li	'diff' is a valid diff.
 * \li	'*tuple' is a valid tuple.
 *
 * Ensures:
 * \li	*tuple is NULL.
 * \li	The tuple has been freed, or will be freed when the diff is cleared.
 */

bool
dns_diff_is_boundary(const dns_diff_t *diff, dns_name_t *name);
/*%<
 * Checks if 'name' is equal, up to case, to the last name of the diff.
 *
 * Requires:
 * \li	'diff' is a valid diff.
 * \li	'name' is a valid dns name.
 */

size_t
dns_diff_size(const dns_diff_t *diff);
/*%<
 * Returns the number of elements in the diff.
 *
 * Requires:
 * \li	'diff' is a valid diff.
 */

void
dns_diff_appendminimal(dns_diff_t *diff, dns_difftuple_t **tuple);
/*%<
 * Append 'tuple' to 'diff', removing any duplicate
 * or conflicting updates as needed to create a minimal diff.
 *
 * Requires:
 *\li	'diff' is a minimal diff.
 *
 * Ensures:
 *\li	'diff' is still a minimal diff.
 *  \li 	*tuple is NULL.
 *   \li	The tuple has been freed, or will be freed when the diff is
 * cleared.
 *
 */

isc_result_t
dns_diff_sort(dns_diff_t *diff, dns_diff_compare_func *compare);
/*%<
 * Sort 'diff' in-place according to the comparison function 'compare'.
 */

isc_result_t
dns_diff_apply(const dns_diff_t *diff, dns_db_t *db, dns_dbversion_t *ver);
isc_result_t
dns_diff_applysilently(const dns_diff_t *diff, dns_db_t *db,
		       dns_dbversion_t *ver);
/*%<
 * Apply 'diff' to the database 'db'.
 *
 * dns_diff_apply() logs warnings about updates with no effect or
 * with inconsistent TTLs; dns_diff_applysilently() does not.
 *
 * For efficiency, the diff should be sorted by owner name.
 * If it is not sorted, operation will still be correct,
 * but less efficient.
 *
 * Requires:
 *\li	*diff is a valid diff (possibly empty), containing
 *	tuples of type #DNS_DIFFOP_ADD and/or
 *	For #DNS_DIFFOP_DEL tuples, the TTL is ignored.
 *
 */

isc_result_t
dns_diff_load(const dns_diff_t *diff, dns_rdatacallbacks_t *callbacks);
/*%<
 * Like dns_diff_apply, but for use when loading a new database
 * instead of modifying an existing one.  This bypasses the
 * database transaction mechanisms.
 *
 * Requires:
 *\li	'callbacks' points to a dns_rdatacallbacks_t structure obtained
 *	from dns_db_beginload()
 */

isc_result_t
dns_diff_print(dns_diff_t *diff, FILE *file);

/*%<
 * Print the differences to 'file' or if 'file' is NULL via the
 * logging system.
 *
 * Require:
 *\li	'diff' to be valid.
 *\li	'file' to refer to a open file or NULL.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	any error from dns_rdataset_totext()
 */
