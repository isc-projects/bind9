/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <isc/mem.h>

#include <dns/result.h>
#include <dns/name.h>

typedef struct dns_dbtable dns_dbtable_t;

dns_result_t
dns_dbtable_create(isc_mem_t *mctx, dns_dbtable_t **dbtablep);
/*
 * Make a new dbtable.
 *
 * Requires:
 *	mctx != NULL
 * 	dbtablep != NULL && *dptablep == NULL
 *
 * Ensures:
 *
 *
 * Returns:
 *	
 */

void
dns_dbtable_destroy(dns_dbtable_t **dbtablep);
/*
 * Free all resources in the dbtable.
 *
 * Requires: *dbtablep is a valid dbtable.
 *
 * Ensures: *dbtablep == NULL.
 */

dns_result_t
dns_dbtable_add(dns_dbtable_t *dbtable, dns_db_t *db);
/*
 * Add 'db' to 'dbtable'.
 */

void
dns_dbtable_remove(dns_dbtable_t *dbtable, dns_db_t *db);
/*
 * Remove 'db' from 'dbtable'.
 *
 * Requires:
 *	'db' was previously added to 'dbtable'.
 */

void
dns_dbtable_adddefault(dns_dbtable_t *dbtable, dns_db_t *db);
/*
 * Use 'db' as the result of a dns_dbtable_find() if no better match is
 * available.
 */

void
dns_dbtable_getdefault(dns_dbtable_t *dbtable, dns_db_t **db);
/*
 * Get the 'db' used as the result of a dns_dbtable_find()
 * if no better match is available.
 */

void
dns_dbtable_removedefault(dns_dbtable_t *dbtable);
/*
 * Remove the default db from 'dbtable'.
 */

dns_result_t
dns_dbtable_find(dns_dbtable_t *dbtable, dns_name_t *name, dns_db_t **dbp);
/*
 * Find the deepest match to 'name' in the dbtable, and return it
 *
 * Returns:  DNS_R_SUCCESS		on success
 *	     <something else>		no default and match
 */
