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

#include <config.h>

#include <isc/assertions.h>
#include <isc/rwlock.h>
#include "../isc/util.h"

#include <dns/dbtable.h>
#include <dns/rbt.h>

struct dns_dbtable {
	unsigned int		magic;
	isc_mem_t *		mctx;
	isc_rwlock_t		tree_lock;
	dns_db_t *		default_db;
	dns_rbt_t *		rbt;
};

#define DBTABLE_MAGIC		0x44422D2DU /* DB--. */
#define VALID_DBTABLE(dbtable)	((dbtable) != NULL && \
				 (dbtable)->magic == DBTABLE_MAGIC)

dns_result_t
dns_dbtable_create(isc_mem_t *mctx, dns_dbtable_t **dbtablep) {
	dns_dbtable_t *dbtable;
	dns_result_t dresult;
	dns_result_t iresult;

	REQUIRE(mctx != NULL);
	REQUIRE(dbtablep != NULL && *dbtablep == NULL);

	dbtable = (dns_dbtable_t *)isc_mem_get(mctx, sizeof(*dbtable));
	if (dbtable == NULL)
		return (DNS_R_NOMEMORY);

	dresult = dns_rbt_create(mctx, NULL, NULL, &dbtable->rbt);
	if (dresult != DNS_R_SUCCESS) {
		isc_mem_put(mctx, dbtable, sizeof(*dbtable));
		return (dresult);
	}

	iresult = isc_rwlock_init(&dbtable->tree_lock, 0, 0);
	if (iresult != ISC_R_SUCCESS) {
		dns_rbt_destroy(&dbtable->rbt);
		isc_mem_put(mctx, dbtable, sizeof(*dbtable));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_rwlock_init() failed: %s",
				 isc_result_totext(iresult));
		return (DNS_R_UNEXPECTED);
	}

	dbtable->mctx = mctx;
	dbtable->magic = DBTABLE_MAGIC;

	*dbtablep = dbtable;

	return (DNS_R_SUCCESS);
}

void
dns_dbtable_destroy(dns_dbtable_t **dbtablep) {
	dns_dbtable_t *dbtable;
	isc_rwlocktype_t locktype = isc_rwlocktype_write;

	REQUIRE(dbtablep != NULL);
	REQUIRE(VALID_DBTABLE(*dbtablep));

	dbtable = *dbtablep;

	RWLOCK(&dbtable->tree_lock, locktype);
	dns_rbt_destroy(&dbtable->rbt);
	RWUNLOCK(&dbtable->tree_lock, locktype);

	isc_rwlock_destroy(&dbtable->tree_lock);

	dbtable->magic = 0;

	isc_mem_put(dbtable->mctx, dbtable, sizeof(*dbtable));

	*dbtablep = NULL;
}

dns_result_t
dns_dbtable_add(dns_dbtable_t *dbtable, dns_name_t *name, dns_db_t *db) {
	dns_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_write;

	REQUIRE(VALID_DBTABLE(dbtable));

	RWLOCK(&dbtable->tree_lock, locktype);
	result = dns_rbt_addname(dbtable->rbt, name, db);
	RWUNLOCK(&dbtable->tree_lock, locktype);

	return (result);

}

void
dns_dbtable_remove(dns_dbtable_t *dbtable, dns_name_t *name, dns_db_t *db) {
	dns_db_t *stored_data;
	isc_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_write;

	REQUIRE(VALID_DBTABLE(dbtable));
	
	/*
	 * There is a requirement that the association of name with db
	 * be verified.  With the current rbt.c this is expensive to do,
	 * because effectively two find operations are being done, but
	 * deletion is relatively infrequent.
	 */

	result = dns_rbt_findname(dbtable->rbt, name, NULL,
				  (void *)&stored_data);
	if (result != DNS_R_SUCCESS)
		return;

        REQUIRE(stored_data == db);

	/*
	 * This test seems redundant, but is necessary to shup up a warning
	 * about a variable set but not used, if REQUIRE() is turned off.
	 */

	if (db == stored_data) {
		RWLOCK(&dbtable->tree_lock, locktype);
		dns_rbt_deletename(dbtable->rbt, name, ISC_FALSE);
		RWUNLOCK(&dbtable->tree_lock, locktype);
	}
}

void
dns_dbtable_adddefault(dns_dbtable_t *dbtable, dns_db_t *db) {
	REQUIRE(VALID_DBTABLE(dbtable));

	dbtable->default_db = db;
}

void
dns_dbtable_getdefault(dns_dbtable_t *dbtable, dns_db_t **db) {
	REQUIRE(VALID_DBTABLE(dbtable));
	REQUIRE(db != NULL && *db == NULL);

	*db = dbtable->default_db;
}

void
dns_dbtable_removedefault(dns_dbtable_t *dbtable, dns_db_t *db) {
	REQUIRE(VALID_DBTABLE(dbtable));
	REQUIRE(db == dbtable->default_db);

	dbtable->default_db = NULL;
}

dns_result_t
dns_dbtable_find(dns_dbtable_t *dbtable, dns_name_t *name, dns_db_t **dbp) {
	dns_db_t *stored_data;
	dns_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	REQUIRE(dbp != NULL && *dbp == NULL);

	RWLOCK(&dbtable->tree_lock, locktype);
	result = dns_rbt_findname(dbtable->rbt, name, NULL,
				  (void *)&stored_data);
	RWUNLOCK(&dbtable->tree_lock, locktype);

	if (result == DNS_R_SUCCESS || result == DNS_R_PARTIALMATCH)
		*dbp = stored_data;
	else
		*dbp = dbtable->default_db;

	return (result);
}

/* DCL */
