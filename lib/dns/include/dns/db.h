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
 * XXX Summary <TBS> XXX
 *
 * The dns_db_t type is like a "virtual class".  To actually use
 * DBs, an implementation of the class is required.
 *
 * XXX <more> XXX
 *
 * MP:
 *	Clients of this module must impose any required synchronization.
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

#include <isc/boolean.h>
#include <isc/mem.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>

typedef struct dns_dbmethods {
	void		(*attach)(dns_db_t *source, dns_db_t **targetp);
	void		(*detach)(dns_db_t **dbp);
	void		(*shutdown)(dns_db_t *db);
	dns_result_t	(*load)(dns_db_t *db, char *filename);
	void		(*currentversion)(dns_db_t *db,
					  dns_dbversion_t **versionp);
	dns_result_t	(*newversion)(dns_db_t *db,
				      dns_dbversion_t **versionp);
	void		(*closeversion)(dns_db_t *db,
					dns_dbversion_t **versionp);
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
				       dns_rdataset_t *rdataset,
				       dns_addmode_t mode);
	dns_result_t	(*deleterdataset)(dns_db_t *db, dns_dbnode_t *node,
					  dns_dbversion_t *version,
					  dns_rdatatype_t type);
} dns_dbmethods_t;

#define DNS_DB_MAGIC			0x444E5344U		/* DNSD. */
#define DNS_DB_VALID(db)		((db) != NULL && \
					 (db)->magic == DNS_DB_MAGIC)

/*
 * This structure is actually just the common prefix of a DNS db
 * implementation's version of a dns_db_t...
 *
 * Direct use of this structure by clients is forbidden.  DB implementations
 * may change the structure.  'magic' must be DNS_DB_MAGIC for any of the
 * dns_db_ routines to work.
 */
struct dns_db {
	unsigned int			magic;
	unsigned int			impmagic;
	dns_dbmethods_t *		methods;
	isc_boolean_t			cache;
	dns_rdataclass_t		class;
	dns_name_t			base;
	isc_mem_t *			mctx;
};

dns_result_t
dns_db_create(isc_mem_t *mctx, char *db_type, dns_name_t *base,
	      isc_boolean_t cache, dns_rdataclass_t class,
	      unsigned int argc, char *argv[], dns_db_t **dbp);

void
dns_db_attach(dns_db_t *source, dns_db_t **targetp);

void
dns_db_detach(dns_db_t **dbp);

void
dns_db_shutdown(dns_db_t *db);

void
dns_db_destroy(dns_db_t **dbp);

isc_boolean_t
dns_db_iscache(dns_db_t *db);

isc_boolean_t
dns_db_iszone(dns_db_t *db);

dns_result_t
dns_db_load(dns_db_t *db, char *filename);

void
dns_db_currentversion(dns_db_t *db, dns_dbversion_t **versionp);

dns_result_t
dns_db_newversion(dns_db_t *db, dns_dbversion_t **versionp);

void
dns_db_closeversion(dns_db_t *db, dns_dbversion_t **versionp);

dns_result_t
dns_db_findnode(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
		dns_dbnode_t **nodep);

void
dns_db_attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp);

void
dns_db_detachnode(dns_db_t *db, dns_dbnode_t **nodep);

dns_result_t
dns_db_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    dns_rdatatype_t type, dns_rdataset_t *rdataset);

dns_result_t
dns_db_addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		   dns_rdataset_t *rdataset, dns_addmode_t mode);

dns_result_t
dns_db_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
		      dns_dbversion_t *version, dns_rdatatype_t type);

#endif /* DNS_DB_H */
