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

#ifndef DNS_DB_H
#define DNS_DB_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS DB
 *
 * The DNS DB interface allows named rdatasets to be stored and retrieved.
 *
 * The dns_db_t type is like a "virtual class".  To actually use
 * DBs, an implementation of the class is required.
 *
 * XXX <more> XXX
 *
 * MP:
 *	The module ensures appropriate synchronization of data structures it
 *	creates and manipulates.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	<TBS>
 *
 * Security:
 *	No anticipated impact.
 *
 * Standards:
 *	None.
 */

/*****
 ***** Imports
 *****/

#include <isc/boolean.h>
#include <isc/mem.h>
#include <isc/lang.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>

ISC_LANG_BEGINDECLS

/*****
 ***** Types
 *****/

typedef struct dns_dbmethods {
	void		(*attach)(dns_db_t *source, dns_db_t **targetp);
	void		(*detach)(dns_db_t **dbp);
	dns_result_t	(*load)(dns_db_t *db, char *filename);
	void		(*currentversion)(dns_db_t *db,
					  dns_dbversion_t **versionp);
	dns_result_t	(*newversion)(dns_db_t *db,
				      dns_dbversion_t **versionp);
	void		(*closeversion)(dns_db_t *db,
					dns_dbversion_t **versionp,
					isc_boolean_t commit);
	dns_result_t	(*findnode)(dns_db_t *db, dns_name_t *name,
				    isc_boolean_t create,
				    dns_dbnode_t **nodep);
	void		(*attachnode)(dns_db_t *db,
				      dns_dbnode_t *source,
				      dns_dbnode_t **targetp);
	void		(*detachnode)(dns_db_t *db,
				      dns_dbnode_t **targetp);
	dns_result_t	(*findrdataset)(dns_db_t *db, dns_dbnode_t *node,
					dns_dbversion_t *version,
					dns_rdatatype_t type,
					dns_rdataset_t *rdataset);
	dns_result_t	(*addrdataset)(dns_db_t *db, dns_dbnode_t *node,
				       dns_dbversion_t *version,
				       dns_rdataset_t *rdataset);
	dns_result_t	(*deleterdataset)(dns_db_t *db, dns_dbnode_t *node,
					  dns_dbversion_t *version,
					  dns_rdatatype_t type);
} dns_dbmethods_t;

#define DNS_DB_MAGIC			0x444E5344U		/* DNSD. */
#define DNS_DB_VALID(db)		((db) != NULL && \
					 (db)->magic == DNS_DB_MAGIC)

/*
 * This structure is actually just the common prefix of a DNS db
 * implementation's version of a dns_db_t.
 *
 * Direct use of this structure by clients is forbidden.  DB implementations
 * may change the structure.  'magic' must be DNS_DB_MAGIC for any of the
 * dns_db_ routines to work.  DB implementations must maintain all DB
 * invariants.
 */
struct dns_db {
	unsigned int			magic;
	unsigned int			impmagic;
	dns_dbmethods_t *		methods;
	isc_uint16_t			attributes;
	dns_rdataclass_t		rdclass;
	dns_name_t			origin;
	isc_mem_t *			mctx;
};

#define DNS_DBATTR_CACHE		0x01

/*****
 ***** Methods
 *****/

/***
 *** Basic DB Methods
 ***/

dns_result_t
dns_db_create(isc_mem_t *mctx, char *db_type, dns_name_t *origin,
	      isc_boolean_t cache, dns_rdataclass_t rdclass,
	      unsigned int argc, char *argv[], dns_db_t **dbp);
/*
 * Create a new database using implementation 'db_type'.
 *
 * Notes:
 *	All names in the database must be subdomains of 'origin' and in class
 *	'rdclass'.  The database makes its own copy of the origin, so the caller
 *	may do whatever they like with 'origin' and its storage once the
 *	call returns.
 *
 *	If 'cache' is ISC_TRUE, then cache semantics will be used, otherwise
 *	zone semantics will apply.
 *
 *	DB implementation-specific parameters are passed using argc and argv.
 *
 * Requires:
 *
 *	dbp != NULL and *dbp == NULL
 *
 *	'origin' is a valid absolute domain name.
 *
 *	mctx is a valid memory context
 *
 * Ensures:
 *
 *	A copy of 'origin' has been made for the databases use, and the
 *	caller is free to do whatever they want with the name and storage
 *	associated with 'origin'.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 *	DNS_R_NOTFOUND				db_type not found
 *
 *	Many other errors are possible, depending on what db_type was
 *	specified.
 */

void
dns_db_attach(dns_db_t *source, dns_db_t **targetp);
/*
 * Attach *targetp to source.
 *
 * Requires:
 *
 *	'source' is a valid database.
 *
 *	'targetp' points to a NULL dns_db_t *.
 *
 * Ensures:
 *
 *	*targetp is attached to source.
 */

void
dns_db_detach(dns_db_t **dbp);
/*
 * Detach *dbp from its database.
 *
 * Requires:
 *
 *	'dbp' points to a valid database.
 *
 * Ensures:
 *
 *	*dbp is NULL.
 *
 *	If '*dbp' is the last reference to the database,
 *
 *		All resources used by the database will be freed
 */

isc_boolean_t
dns_db_iscache(dns_db_t *db);
/*
 * Does 'db' have cache semantics?
 *
 * Note: dns_db_iscache(db) == !dns_db_iszone(db)
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 * Returns:
 *	ISC_TRUE	'db' has cache semantics
 *	ISC_FALSE	otherwise
 */

isc_boolean_t
dns_db_iszone(dns_db_t *db);
/*
 * Does 'db' have zone semantics?
 *
 * Note: dns_db_iszone(db) == !dns_db_iscache(db)
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 * Returns:
 *	ISC_TRUE	'db' has zone semantics
 *	ISC_FALSE	otherwise
 */

dns_name_t *
dns_db_origin(dns_db_t *db);
/*
 * The origin of the database.
 *
 * Note: caller must not try to change this name.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 * Returns:
 *
 *	The origin of the database.
 */

dns_result_t
dns_db_load(dns_db_t *db, char *filename);
/*
 * Load master file 'filename' into 'db'.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	This is the first attempt to load 'db'.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 *
 *	Other results are possible, depending upon the database
 *	implementation used, syntax errors in the master file, etc.
 */

/***
 *** Version Methods
 ***/

void
dns_db_currentversion(dns_db_t *db, dns_dbversion_t **versionp);
/*
 * Open the current version for reading.
 *
 * Requires:
 *
 *	'db' is a valid database with zone semantics.
 *
 *	versionp != NULL && *verisonp == NULL
 *
 * Ensures:
 *
 *	On success, '*versionp' is attached to the current version.
 *
 */

dns_result_t
dns_db_newversion(dns_db_t *db, dns_dbversion_t **versionp);
/*
 * Open a new version for reading and writing.
 *
 * Requires:
 *
 *	'db' is a valid database with zone semantics.
 *
 *	versionp != NULL && *verisonp == NULL
 *
 * Ensures:
 *
 *	On success, '*versionp' is attached to the current version.
 * 
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 *
 *	Other results are possible, depending upon the database
 *	implementation used.
 */

void
dns_db_closeversion(dns_db_t *db, dns_dbversion_t **versionp,
		    isc_boolean_t commit);
/*
 * Close version '*versionp'.
 *
 * Note: if '*versionp' is a read-write version and 'commit' is ISC_TRUE,
 * then all changes made in the version will take effect, otherwise they
 * will be rolled back.  The value if 'commit' is ignored for read-only
 * versions.
 *
 * Requires:
 *
 *	'db' is a valid database with zone semantics.
 *
 *	'*versionp' refers to a valid version.
 *
 * Ensures:
 *
 *	*versionp == NULL
 *
 *	If *versionp is a read-write version, and commit is ISC_TRUE, then
 *	the version will become the current version.  If !commit, then all
 *	changes made in the version will be undone, and the version will
 *	not become the current version.
 */

/***
 *** Node Methods
 ***/

dns_result_t
dns_db_findnode(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
		dns_dbnode_t **nodep);
/*
 * Find the node with name 'name'.
 *
 * WARNING:  THIS API WILL BE CHANGING IN THE NEAR FUTURE.
 *
 * Note: if 'create' is ISC_TRUE and no node with name 'name' exists, then
 * such a node will be created.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	'name' is a valid, non-empty, absolute name that is a subdomain of
 *	the database's origin.  (It need not be a proper subdomain.)
 *
 *	nodep != NULL && *nodep == NULL
 *
 * Ensures:
 *
 *	On success, *nodep is attached to the node with name 'name'.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOTFOUND			If !create and name not found.
 *	DNS_R_NOMEMORY		        Can only happen if create is ISC_TRUE.
 *
 *	Other results are possible, depending upon the database
 *	implementation used.
 */

void
dns_db_attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp);
/*
 * Attach *targetp to source.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	'source' is a valid node.
 *
 *	'targetp' points to a NULL dns_node_t *.
 *
 * Ensures:
 *
 *	*targetp is attached to source.
 */

void
dns_db_detachnode(dns_db_t *db, dns_dbnode_t **nodep);
/*
 * Detach *nodep from its node.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	'nodep' points to a valid node.
 *
 * Ensures:
 *
 *	*nodep is NULL.
 */

/***
 *** Rdataset Methods
 ***/

dns_result_t
dns_db_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    dns_rdatatype_t type, dns_rdataset_t *rdataset);
/*
 * Search for an rdataset of type 'type' at 'node' that are in version
 * 'version' of 'db'.  If found, make 'rdataset' refer to it.
 *
 * Notes:
 *
 *	If 'version' is NULL, then the current version will be used.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	'node' is a valid node.
 *
 *	'rdataset' is a valid, disassociated rdataset.
 *
 *	'type' is not a meta-RR type such as 'ANY' or 'OPT'.
 *
 * Ensures:
 *
 *	On success, 'rdataset' is associated with the found rdataset.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOTFOUND
 *	
 *	Other results are possible, depending upon the database
 *	implementation used.
 */

dns_result_t
dns_db_addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		   dns_rdataset_t *rdataset);
/*
 * Add 'rdataset' to 'node' in version 'version' of 'db'.
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	'node' is a valid node.
 *
 *	'rdataset' is a valid, associated rdataset.
 *
 *	The database has zone semantics and 'version' is a valid
 *	read-write version, or the database has cache semantics
 *	and version is NULL.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 *	DNS_R_EXISTS			An rdataset with the specified
 *					rdataset's type and version's serial
 *					number already exists.
 *					XXX should non-existence in this
 *					version be a requirement instead?
 *	
 *	Other results are possible, depending upon the database
 *	implementation used.
 */

dns_result_t
dns_db_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
		      dns_dbversion_t *version, dns_rdatatype_t type);
/*
 * Make it so that no rdataset of type 'type' exists at 'node' in version
 * version 'version' of 'db'.
 *
 * Notes:
 *
 *	If 'type' is dns_rdatatype_any, then no rdatasets will exist in
 *	'version' (provided that the dns_db_deleterdataset() isn't followed
 *	by one or more dns_db_addrdataset() calls).
 *
 * Requires:
 *
 *	'db' is a valid database.
 *
 *	'node' is a valid node.
 *
 *	The database has zone semantics and 'version' is a valid
 *	read-write version, or the database has cache semantics
 *	and version is NULL.
 *
 *	'type' is not a meta-RR type, except for dns_rdatatype_any, which is
 *	allowed.
 *
 * Ensures:
 *
 *	On success, 'rdataset' is associated with the found rdataset.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *	DNS_R_NOTFOUND
 *	
 *	Other results are possible, depending upon the database
 *	implementation used.
 */

 /*
  * XXX Need rdataset iterator for ANY queries.
  */
 
ISC_LANG_ENDDECLS

#endif /* DNS_DB_H */
