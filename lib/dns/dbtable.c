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

/*
 * $Id: dbtable.c,v 1.6 1999/04/20 22:26:49 halley Exp $
 */

/*
 * Principal Author: DCL
 */

#include <config.h>

#include <isc/assertions.h>
#include <isc/rwlock.h>
#include "../isc/util.h"

#include <dns/dbtable.h>
#include <dns/db.h>
#include <dns/rbt.h>

struct dns_dbtable {
	/* Unlocked. */
	unsigned int		magic;
	isc_mem_t *		mctx;
	dns_rdataclass_t	rdclass;
	isc_rwlock_t		tree_lock;
	/* Locked by tree_lock. */
	dns_rbt_t *		rbt;
	dns_db_t *		default_db;
};

#define DBTABLE_MAGIC		0x44422D2DU /* DB--. */
#define VALID_DBTABLE(dbtable)	((dbtable) != NULL && \
				 (dbtable)->magic == DBTABLE_MAGIC)

dns_result_t
dns_dbtable_create(isc_mem_t *mctx, dns_rdataclass_t rdclass,
		   dns_dbtable_t **dbtablep)
{
	dns_dbtable_t *dbtable;
	dns_result_t result;

	REQUIRE(mctx != NULL);
	REQUIRE(dbtablep != NULL && *dbtablep == NULL);

	dbtable = (dns_dbtable_t *)isc_mem_get(mctx, sizeof(*dbtable));
	if (dbtable == NULL)
		return (DNS_R_NOMEMORY);

	result = dns_rbt_create(mctx, NULL, NULL, &dbtable->rbt);
	if (result != DNS_R_SUCCESS) {
		isc_mem_put(mctx, dbtable, sizeof(*dbtable));
		return (result);
	}

	result = isc_rwlock_init(&dbtable->tree_lock, 0, 0);
	if (result != ISC_R_SUCCESS) {
		dns_rbt_destroy(&dbtable->rbt);
		isc_mem_put(mctx, dbtable, sizeof(*dbtable));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(result));
		return (DNS_R_UNEXPECTED);
	}

	dbtable->default_db = NULL;
	dbtable->mctx = mctx;
	dbtable->rdclass = rdclass;
	dbtable->magic = DBTABLE_MAGIC;

	*dbtablep = dbtable;

	return (DNS_R_SUCCESS);
}

void
dns_dbtable_destroy(dns_dbtable_t **dbtablep) {
	dns_dbtable_t *dbtable;

	REQUIRE(dbtablep != NULL);
	REQUIRE(VALID_DBTABLE(*dbtablep));

	dbtable = *dbtablep;

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_write);

	if (dbtable->default_db != NULL)
		dns_db_detach(&dbtable->default_db);

	/* XXXRTH Need to detach from all db entries. */
	dns_rbt_destroy(&dbtable->rbt);

	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_write);

	isc_rwlock_destroy(&dbtable->tree_lock);

	dbtable->magic = 0;

	isc_mem_put(dbtable->mctx, dbtable, sizeof(*dbtable));

	*dbtablep = NULL;
}

dns_result_t
dns_dbtable_add(dns_dbtable_t *dbtable, dns_db_t *db) {
	dns_result_t result;
	dns_db_t *clone;

	REQUIRE(VALID_DBTABLE(dbtable));
	REQUIRE(dns_db_class(db) == dbtable->rdclass);

	clone = NULL;
	dns_db_attach(db, &clone);

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_write);
	result = dns_rbt_addname(dbtable->rbt, dns_db_origin(clone), clone);
	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_write);

	return (result);
}

void
dns_dbtable_remove(dns_dbtable_t *dbtable, dns_db_t *db) {
	dns_db_t *stored_data = NULL;
	isc_result_t result;
	dns_name_t *name;

	REQUIRE(VALID_DBTABLE(dbtable));
	
	name = dns_db_origin(db);

	/*
	 * There is a requirement that the association of name with db
	 * be verified.  With the current rbt.c this is expensive to do,
	 * because effectively two find operations are being done, but
	 * deletion is relatively infrequent.
	 */

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_write);

	result = dns_rbt_findname(dbtable->rbt, name, NULL,
				  (void **)&stored_data);

	if (result == DNS_R_SUCCESS) {
		INSIST(stored_data == db);
		dns_db_detach(&stored_data);

		dns_rbt_deletename(dbtable->rbt, name, ISC_FALSE);
	}

	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_write);
}

void
dns_dbtable_adddefault(dns_dbtable_t *dbtable, dns_db_t *db) {
	REQUIRE(VALID_DBTABLE(dbtable));
	REQUIRE(dbtable->default_db == NULL);
	REQUIRE(dns_name_compare(dns_db_origin(db), dns_rootname) == 0);

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_write);

	dbtable->default_db = NULL;
	dns_db_attach(db, &dbtable->default_db);

	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_write);
}

void
dns_dbtable_getdefault(dns_dbtable_t *dbtable, dns_db_t **dbp) {
	REQUIRE(VALID_DBTABLE(dbtable));
	REQUIRE(dbp != NULL && *dbp == NULL);

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_read);

	dns_db_attach(dbtable->default_db, dbp);

	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_read);
}

void
dns_dbtable_removedefault(dns_dbtable_t *dbtable) {
	REQUIRE(VALID_DBTABLE(dbtable));

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_write);

	dns_db_detach(&dbtable->default_db);

	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_write);
}

dns_result_t
dns_dbtable_find(dns_dbtable_t *dbtable, dns_name_t *name, dns_db_t **dbp) {
	dns_db_t *stored_data = NULL;
	dns_result_t result;

	REQUIRE(dbp != NULL && *dbp == NULL);

	RWLOCK(&dbtable->tree_lock, isc_rwlocktype_read);

	result = dns_rbt_findname(dbtable->rbt, name, NULL,
				  (void **)&stored_data);

	if (result == DNS_R_SUCCESS || result == DNS_R_PARTIALMATCH)
		dns_db_attach(stored_data, dbp);
	else if (dbtable->default_db != NULL) {
		dns_db_attach(dbtable->default_db, dbp);
		result = DNS_R_PARTIALMATCH;
	} else
		result = DNS_R_NOTFOUND;

	RWUNLOCK(&dbtable->tree_lock, isc_rwlocktype_read);

	return (result);
}
