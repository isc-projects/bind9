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

#include <stddef.h>
#include <string.h>

#include <isc/assertions.h>

#include <dns/db.h>

#include "rbtdb.h"

dns_result_t
dns_db_create(isc_mem_t *mctx, char *db_type, isc_boolean_t cache,
	      dns_rdataclass_t class,
	      unsigned int argc, char *argv[], dns_db_t **dbp)
{
	/* find the create method for 'db_type', and call it. */

	/* Temporary minor hack... */
	if (strcasecmp(db_type, "rbt") == 0)
		return (dns_rbtdb_create(mctx, cache, class, argc, argv,
					 dbp));

	return (DNS_R_NOTIMPLEMENTED);
}

void
dns_db_attach(dns_db_t *source, dns_db_t **targetp) {

	REQUIRE(DNS_DB_VALID(source));
	REQUIRE(targetp != NULL);

	(source->methods->attach)(source, targetp);
}

void
dns_db_detach(dns_db_t **dbp) {

	REQUIRE(dbp != NULL);
	REQUIRE(DNS_DB_VALID(*dbp));

	((*dbp)->methods->detach)(dbp);
}

void
dns_db_shutdown(dns_db_t *db) {
	/*
	 * db will go away when there are no open versions, no direct external
	 * references, and no in-use nodes (i.e. indirect external references).
	 */

	REQUIRE(DNS_DB_VALID(db));

	(db->methods->shutdown)(db);
}

void
dns_db_destroy(dns_db_t **dbp) {

	REQUIRE(dbp != NULL);
	REQUIRE(DNS_DB_VALID(*dbp));

	((*dbp)->methods->shutdown)(*dbp);
	((*dbp)->methods->detach)(dbp);
}

isc_boolean_t
dns_db_iscache(dns_db_t *db) {
	
	REQUIRE(DNS_DB_VALID(db));

	return (db->cache);
}

isc_boolean_t
dns_db_iszone(dns_db_t *db) {
	
	REQUIRE(DNS_DB_VALID(db));

	return (!db->cache);
}

/*
 * Version Operations.
 */

void
dns_db_currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	
	REQUIRE(DNS_DB_VALID(db));

	(db->methods->currentversion)(db, versionp);
}

dns_result_t
dns_db_newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	
	REQUIRE(DNS_DB_VALID(db));

	return ((db->methods->newversion)(db, versionp));
}

void
dns_db_closeversion(dns_db_t *db, dns_dbversion_t **versionp) {
	
	REQUIRE(DNS_DB_VALID(db));

	(db->methods->closeversion)(db, versionp);
}

/*
 * Node Operations.
 */

dns_result_t
dns_db_findnode(dns_db_t *db, dns_name_t *name,
		isc_boolean_t create, dns_dbnode_t **nodep)
{
	REQUIRE(DNS_DB_VALID(db));

	return ((db->methods->findnode)(db, name, create, nodep));
}

void
dns_db_attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {

	REQUIRE(DNS_DB_VALID(db));

	(db->methods->attachnode)(db, source, targetp);
}

void
dns_db_detachnode(dns_db_t *db, dns_dbnode_t **nodep) {

	REQUIRE(DNS_DB_VALID(db));

	(db->methods->detachnode)(db, nodep);
}

dns_result_t
dns_db_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    dns_rdatatype_t type, dns_rdataset_t *rdataset)
{

	REQUIRE(DNS_DB_VALID(db));

	return ((db->methods->findrdataset)(db, node, version, type,
					    rdataset));
}

dns_result_t
dns_db_addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		   dns_rdataset_t *rdataset, dns_addmode_t mode)
{
	REQUIRE(DNS_DB_VALID(db));

	return ((db->methods->addrdataset)(db, node, version, rdataset, mode));
}

dns_result_t
dns_db_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
		      dns_dbversion_t *version, dns_rdatatype_t type)
{
	REQUIRE(DNS_DB_VALID(db));

	return ((db->methods->deleterdataset)(db, node, version, type));
}

/* Need a node rdataset list iterator. */
