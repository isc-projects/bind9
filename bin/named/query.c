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
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/event.h>

#include <dns/db.h>
#include <dns/dbtable.h>
#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/view.h>

#include <named/client.h>
#include <named/globals.h>
#include <named/query.h>

#include "../../isc/util.h"		/* XXX */

#define PARTIALANSWER(c)	(((c)->query.attributes & \
				  NS_QUERYATTR_PARTIALANSWER) != 0)

static inline void
query_reset(ns_client_t *client, isc_boolean_t everything) {
	isc_dynbuffer_t *dbuf, *dbuf_next;
	ns_dbversion_t *dbversion, *dbversion_next;
	unsigned int i;


	/*
	 * Cleanup any active versions.
	 */
	for (dbversion = ISC_LIST_HEAD(client->query.activeversions);
	     dbversion != NULL;
	     dbversion = dbversion_next) {
		dbversion_next = ISC_LIST_NEXT(dbversion, link);
		dns_db_closeversion(dbversion->db, &dbversion->version,
				    ISC_FALSE);
		dns_db_detach(&dbversion->db);
		ISC_LIST_APPEND(client->query.freeversions, dbversion, link);
	}
	ISC_LIST_INIT(client->query.activeversions);

	/*
	 * Clean up free versions.
	 */
	for (dbversion = ISC_LIST_HEAD(client->query.freeversions), i = 0;
	     dbversion != NULL;
	     dbversion = dbversion_next, i++) {
		dbversion_next = ISC_LIST_NEXT(dbversion, link);
		/*
		 * If we're not freeing everything, we keep the first three
		 * dbversions structures around.
		 */
		if (i > 3 || everything) {
			ISC_LIST_UNLINK(client->query.freeversions, dbversion,
					link);
			isc_mem_put(client->mctx, dbversion,
				    sizeof *dbversion);
		}
	}

	for (dbuf = ISC_LIST_HEAD(client->query.namebufs);
	     dbuf != NULL;
	     dbuf = dbuf_next) {
		dbuf_next = ISC_LIST_NEXT(dbuf, link);
		if (dbuf_next != NULL || everything) {
			ISC_LIST_UNLINK(client->query.namebufs, dbuf, link);
			isc_dynbuffer_free(client->mctx, &dbuf);
		}
	}
	/*
	 * We don't need to free items from these two lists because they
	 * will be taken care of when the message is reset.
	 */
	ISC_LIST_INIT(client->query.tmpnames);
	ISC_LIST_INIT(client->query.tmprdatasets);
	client->query.attributes = (NS_QUERYATTR_RECURSIONOK|
				    NS_QUERYATTR_CACHEOK);
	client->query.qname = NULL;
	client->query.origqname = NULL;
	client->query.dboptions = 0;
}

static void
query_next(ns_client_t *client, isc_result_t result) {
	(void)result;
	query_reset(client, ISC_FALSE);
}

void
ns_query_free(ns_client_t *client) {
	query_reset(client, ISC_TRUE);
}

static inline isc_result_t
query_newnamebuf(ns_client_t *client) {
	isc_dynbuffer_t *dbuf;
	isc_result_t result;

	dbuf = NULL;
	result = isc_dynbuffer_allocate(client->mctx, &dbuf, 1024,
					ISC_BUFFERTYPE_BINARY);
	if (result != ISC_R_SUCCESS)
		return (result);
	ISC_LIST_APPEND(client->query.namebufs, dbuf, link);

	return (ISC_R_SUCCESS);
}

static inline isc_dynbuffer_t *
query_getnamebuf(ns_client_t *client) {
	isc_dynbuffer_t *dbuf;
	isc_result_t result;
	isc_region_t r;

	if (ISC_LIST_EMPTY(client->query.namebufs)) {
		result = query_newnamebuf(client);
		if (result != ISC_R_SUCCESS)
			return (NULL);
	}

	dbuf = ISC_LIST_TAIL(client->query.namebufs);
	INSIST(dbuf != NULL);
	isc_buffer_available(&dbuf->buffer, &r);
	if (r.length < 255) {
		result = query_newnamebuf(client);
		if (result != ISC_R_SUCCESS)
			return (NULL);
		dbuf = ISC_LIST_TAIL(client->query.namebufs);
		isc_buffer_available(&dbuf->buffer, &r);
		INSIST(r.length >= 255);
	}
	return (dbuf);
}

static inline void
query_keepname(ns_client_t *client, dns_name_t *name, isc_dynbuffer_t *dbuf) {
	isc_region_t r;

	/*
	 * 'name' is using space in 'dbuf', but 'dbuf' has not yet been
	 * adjusted to take account of that.  We do the adjustment.
	 */

	REQUIRE((client->query.attributes & NS_QUERYATTR_NAMEBUFUSED) != 0);

	dns_name_toregion(name, &r);
	isc_buffer_add(&dbuf->buffer, r.length);
	dns_name_setbuffer(name, NULL);
	client->query.attributes &= ~NS_QUERYATTR_NAMEBUFUSED;
}

static inline void
query_releasename(ns_client_t *client, dns_name_t **namep) {
	dns_name_t *name = *namep;

	ISC_LIST_APPEND(client->query.tmpnames, name, link);
	if (dns_name_hasbuffer(name)) {
		INSIST((client->query.attributes & NS_QUERYATTR_NAMEBUFUSED)
		       != 0);
		client->query.attributes &= ~NS_QUERYATTR_NAMEBUFUSED;
	}
	*namep = NULL;
}

static inline dns_name_t *
query_newname(ns_client_t *client, isc_dynbuffer_t *dbuf,
	      isc_buffer_t *nbuf)
{
	dns_name_t *name;
	isc_region_t r;
	isc_result_t result;

	REQUIRE((client->query.attributes & NS_QUERYATTR_NAMEBUFUSED) == 0);

	name = ISC_LIST_HEAD(client->query.tmpnames);
	if (name == NULL) {
		result = dns_message_gettempname(client->message, &name);
		if (result != ISC_R_SUCCESS)
			return (NULL);
	} else
		ISC_LIST_UNLINK(client->query.tmpnames, name, link);
	isc_buffer_available(&dbuf->buffer, &r);
	isc_buffer_init(nbuf, r.base, r.length, ISC_BUFFERTYPE_BINARY);
	dns_name_init(name, NULL);
	dns_name_setbuffer(name, nbuf);
	client->query.attributes |= NS_QUERYATTR_NAMEBUFUSED;

	return (name);
}

static inline dns_rdataset_t *
query_newrdataset(ns_client_t *client) {
	dns_rdataset_t *rdataset;
	isc_result_t result;
	
	rdataset = ISC_LIST_HEAD(client->query.tmprdatasets);
	if (rdataset == NULL) {
		result = dns_message_gettemprdataset(client->message,
						     &rdataset);
		if (result != ISC_R_SUCCESS)
			return (NULL);
	} else
		ISC_LIST_UNLINK(client->query.tmprdatasets, rdataset, link);
	dns_rdataset_init(rdataset);

	return (rdataset);
}

static inline isc_result_t
query_newdbversion(ns_client_t *client, unsigned int n) {
	unsigned int i;
	ns_dbversion_t *dbversion;

	for (i = 0; i < n; i++) {
		dbversion = isc_mem_get(client->mctx, sizeof *dbversion);
		if (dbversion != NULL) {
			dbversion->db = NULL;
			dbversion->version = NULL;
			ISC_LIST_APPEND(client->query.freeversions, dbversion,
					link);
		} else {
			/*
			 * We only return ISC_R_NOMEMORY if we couldn't
			 * allocate anything.
			 */
			if (i == 0)
				return (ISC_R_NOMEMORY);
			else
				return (ISC_R_SUCCESS);
		}
	}

	return (ISC_R_SUCCESS);
}

static inline ns_dbversion_t *
query_getdbversion(ns_client_t *client) {
	isc_result_t result;
	ns_dbversion_t *dbversion;

	if (ISC_LIST_EMPTY(client->query.freeversions)) {
		result = query_newdbversion(client, 1);
		if (result != ISC_R_SUCCESS)
			return (NULL);
	}
	dbversion = ISC_LIST_HEAD(client->query.freeversions);
	INSIST(dbversion != NULL);
	ISC_LIST_UNLINK(client->query.freeversions, dbversion, link);
	
	return (dbversion);
}

isc_result_t
ns_query_init(ns_client_t *client) {
	isc_result_t result;

	ISC_LIST_INIT(client->query.namebufs);
	ISC_LIST_INIT(client->query.activeversions);
	ISC_LIST_INIT(client->query.freeversions);
	query_reset(client, ISC_FALSE);
	result = query_newdbversion(client, 3);
	if (result != ISC_R_SUCCESS)
		return (result);
	return (query_newnamebuf(client));
}

static inline dns_dbversion_t *
query_findversion(ns_client_t *client, dns_db_t *db) {
	ns_dbversion_t *dbversion;

	/*
	 * We may already have done a query related to this
	 * database.  If so, we must be sure to make subsequent
	 * queries from the same version.
	 */
	for (dbversion = ISC_LIST_HEAD(client->query.activeversions);
	     dbversion != NULL;
	     dbversion = ISC_LIST_NEXT(dbversion, link)) {
		if (dbversion->db == db)
			break;
	}	
	if (dbversion == NULL) {
		/*
		 * This is a new zone for this query.  Add it to
		 * the active list.
		 */
		dbversion = query_getdbversion(client);
		if (dbversion == NULL)
			return (NULL);
		dns_db_attach(db, &dbversion->db);
		dns_db_currentversion(db, &dbversion->version);
		ISC_LIST_APPEND(client->query.activeversions,
				dbversion, link);
	}
	
	return (dbversion->version);
}

static isc_result_t
query_addadditional(void *arg, dns_name_t *name, dns_rdatatype_t type) {
	ns_client_t *client = arg;
	isc_result_t result, eresult;
	dns_dbnode_t *node;
	dns_db_t *db;
	dns_name_t *fname, *mname;
	dns_rdataset_t *rdataset;
	dns_section_t section;
	isc_dynbuffer_t *dbuf;
	isc_buffer_t b;
	dns_dbversion_t *version;

	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(type != dns_rdatatype_any);
	/* XXXRTH  Other requirements. */

	/*
	 * XXXRTH  Should special case 'A' type.  If type is 'A', we should
	 *	   look for A6 and AAAA too.
	 */

	/*
	 * Initialization.
	 */
	eresult = ISC_R_SUCCESS;
	fname = NULL;
	rdataset = NULL;
	db = NULL;
	version = NULL;
	node = NULL;

	/*
	 * Get some resources...
	 */
	dbuf = query_getnamebuf(client);
	if (dbuf == NULL)
		goto cleanup;
	fname = query_newname(client, dbuf, &b);
	rdataset = query_newrdataset(client);
	if (fname == NULL || rdataset == NULL)
		goto cleanup;

	/*
	 * Find a database to answer the query.
	 */
	result = dns_dbtable_find(client->view->dbtable, name, &db);
	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH)
		goto cleanup;

	/*
	 * Get the current version of this database.
	 */
	if (dns_db_iszone(db)) {
		version = query_findversion(client, db);
		if (version == NULL)
			goto cleanup;
	}

	/*
	 * Now look for an answer in the database.
	 */
	node = NULL;
	result = dns_db_find(db, name, version, type, client->query.dboptions,
			     client->requesttime, &node, fname, rdataset);
	switch (result) {
	case DNS_R_SUCCESS:
	case DNS_R_GLUE:
		break;
	default:
		goto cleanup;
	}

	query_keepname(client, fname, dbuf);

	/*
	 * Suppress duplicates.
	 */
	for (section = DNS_SECTION_ANSWER;
	     section <= DNS_SECTION_ADDITIONAL;
	     section++) {
		mname = NULL;
		result = dns_message_findname(client->message, section,
					      name, type, &mname, NULL);
		if (result == ISC_R_SUCCESS) {
			/*
			 * We've already got this RRset in the response.
			 */
			goto cleanup;
		}
	}
	ISC_LIST_APPEND(fname->list, rdataset, link);
	rdataset = NULL;

	dns_message_addname(client->message, fname, DNS_SECTION_ADDITIONAL);
	fname = NULL;

	/*
	 * In a few cases, we want to add additional data for additional
	 * data.  It's simpler to just deal with special cases here than
	 * to try to create a general purpose mechanism and allow the
	 * rdata implementations to do it themselves.
	 *
	 * This involves recursion, but the depth is limited.  The
	 * most complex case is adding a SRV rdataset, which involves
	 * recursing to add address records, which in turn can cause
	 * recursion to add KEYs.
	 */
	if (type == dns_rdatatype_a || type == dns_rdatatype_aaaa ||
	    type == dns_rdatatype_a6) {
		/*
		 * RFC 2535 section 3.5 says that when A or AAAA records are
		 * retrieved as additional data, any KEY RRs for the owner name
		 * should be added to the additional data section.  We include
		 * A6 in the list of types with such treatment.
		 *
		 * XXXRTH  We should lower the priority here.  Alternatively,
		 * we could raise the priority of glue records.
		 */
		eresult = query_addadditional(client, name, dns_rdatatype_key);
 	} else if (type == dns_rdatatype_srv) {
		/*
		 * If we're adding SRV records to the additional data
		 * section, it's helpful if we add the SRV additional data
		 * as well.
		 */
		eresult = dns_rdataset_additionaldata(rdataset,
						      query_addadditional,
						      client);
	}

 cleanup:
	if (rdataset != NULL) {
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		ISC_LIST_APPEND(client->query.tmprdatasets, rdataset, link);
	}
	if (fname != NULL)
		query_releasename(client, &fname);
	if (node != NULL)
		dns_db_detachnode(db, &node);
	if (db != NULL)
		dns_db_detach(&db);

	return (eresult);
}

static inline void
query_addrdataset(ns_client_t *client, dns_name_t *fname,
		  dns_rdataset_t *rdataset)
{
	dns_rdatatype_t type = rdataset->type;

	ISC_LIST_APPEND(fname->list, rdataset, link);
	/*
	 * We don't care if dns_rdataset_additionaldata() fails.
	 */
	(void)dns_rdataset_additionaldata(rdataset, query_addadditional,
					  client);
	/*
	 * RFC 2535 section 3.5 says that when NS, SOA, A, or AAAA records
	 * are retrieved, any KEY RRs for the owner name should be added
	 * to the additional data section.  We include A6 in the list of
	 * types with such treatment.
	 *
	 * We don't care if query_additional() fails.
	 */
	if (type == dns_rdatatype_ns || type == dns_rdatatype_soa ||
	    type == dns_rdatatype_a || type == dns_rdatatype_aaaa ||
	    type == dns_rdatatype_a6) {
		/*
		 * XXXRTH  We should lower the priority here.  Alternatively,
		 * we could raise the priority of glue records.
		 */
		(void)query_addadditional(client, fname, dns_rdatatype_key);
	}
}

#define ANSWERED(rds)	(((rds)->attributes & DNS_RDATASETATTR_ANSWERED) != 0)

static inline void
query_addrrset(ns_client_t *client, dns_name_t **namep,
	       dns_rdataset_t **rdatasetp, isc_dynbuffer_t *dbuf,
	       dns_section_t section)
{
	dns_name_t *name, *mname;
	dns_rdataset_t *rdataset, *mrdataset;
	isc_result_t result;

	name = *namep;
	rdataset = *rdatasetp;
	mname = NULL;
	mrdataset = NULL;
	result = dns_message_findname(client->message, section,
				      name, rdataset->type,
				      &mname, &mrdataset);
	if (result == ISC_R_SUCCESS) {
		/*
		 * We've already got an RRset of the given name and type.
		 * There's nothing else to do;
		 */
		return;
	} else if (result == DNS_R_NXDOMAIN) {
		/*
		 * The name doesn't exist.
		 */
		if (dbuf != NULL)
			query_keepname(client, name, dbuf);
		dns_message_addname(client->message, name, section);
		*namep = NULL;
		mname = name;
	} else
		RUNTIME_CHECK(result == DNS_R_NXRDATASET);

	query_addrdataset(client, mname, rdataset);
	*rdatasetp = NULL;
}

static inline isc_result_t
query_addsoa(ns_client_t *client, dns_db_t *db) {
	dns_name_t *name, *fname;
	dns_dbnode_t *node;
	isc_result_t result, eresult;
	dns_fixedname_t foundname;
	dns_rdataset_t *rdataset;

	/*
	 * Initialization.
	 */
	eresult = ISC_R_SUCCESS;
	name = NULL;
	rdataset = NULL;
	node = NULL;
	dns_fixedname_init(&foundname);
	fname = dns_fixedname_name(&foundname);

	/*
	 * Get resources and make 'name' be the database origin.
	 */
	result = dns_message_gettempname(client->message, &name);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_name_init(name, NULL);
	dns_name_clone(dns_db_origin(db), name);
	rdataset = query_newrdataset(client);
	if (rdataset == NULL) {
		eresult = DNS_R_SERVFAIL;
		goto cleanup;
	}

	/*
	 * Find the SOA.
	 */
	result = dns_db_find(db, name, NULL, dns_rdatatype_soa, 0, 0, &node,
			     fname, rdataset);
	if (result != ISC_R_SUCCESS) {
		/*
		 * This is bad.  We tried to get the SOA RR at the zone top
		 * and it didn't work!
		 *
		 * The note above about temporary leakage applies here too.
		 */
		eresult = DNS_R_SERVFAIL;
	} else
		query_addrrset(client, &name, &rdataset, NULL,
			       DNS_SECTION_AUTHORITY);

 cleanup:
	if (rdataset != NULL) {
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		ISC_LIST_APPEND(client->query.tmprdatasets, rdataset, link);
	}
	if (name != NULL)
		query_releasename(client, &name);
	if (node != NULL)
		dns_db_detachnode(db, &node);

	return (eresult);
}

static inline isc_result_t
query_checktype(dns_rdatatype_t type) {
	
	/*
	 * XXXRTH  SIG is here only temporarily.
	 *	   OPT still needs to be added.
	 *	   Should get help with this from rdata.c
	 */
	switch (type) {
	case dns_rdatatype_sig:
		return (DNS_R_NOTIMP);
	case dns_rdatatype_tkey:
		return (DNS_R_NOTIMP);
	case dns_rdatatype_tsig:
		return (DNS_R_FORMERR);
	case dns_rdatatype_ixfr:
	case dns_rdatatype_axfr:
	case dns_rdatatype_mailb:
	case dns_rdatatype_maila:
		return (DNS_R_REFUSED);
	default:
		break;
	}

	return (ISC_R_SUCCESS);
}

#define MAX_RESTARTS 16

#define QUERY_ERROR(r) \
do { \
	eresult = r; \
	want_restart = ISC_FALSE; \
} while (0)

static void
query_find(ns_client_t *client) {
	dns_db_t *db;
	dns_dbnode_t *node;
	dns_rdatatype_t qtype, type;
	dns_name_t *fname, *tname, *prefix;
	dns_rdataset_t *rdataset, *qrdataset, *trdataset;
	dns_rdata_t rdata;
	dns_rdatasetiter_t *rdsiter;
	isc_boolean_t use_cache, recursion_ok, want_restart;
	isc_boolean_t auth, is_zone;
	unsigned int restarts, qcount, n, nlabels, nbits;
	dns_namereln_t namereln;
	int order;
	isc_dynbuffer_t *dbuf;
	isc_region_t r;
	isc_buffer_t b;
	isc_result_t result, eresult;
	dns_fixedname_t fixed;
	dns_dbversion_t *version;

	/*	
	 * One-time initialization.
	 *
	 * It's especially important to initialize anything that the cleanup
	 * code might cleanup.
	 */

	eresult = ISC_R_SUCCESS;
	restarts = 0;
	use_cache = ISC_FALSE;
	recursion_ok = ISC_FALSE;
	fname = NULL;
	rdataset = NULL;
	node = NULL;
	db = NULL;
	version = NULL;

	if (client->view->cachedb == NULL ||
	    client->view->resolver == NULL) {
		use_cache = ISC_FALSE;
		recursion_ok = ISC_FALSE;
	}
	
 restart:
	want_restart = ISC_FALSE;
	auth = ISC_FALSE;

	/*
	 * First we must find the right database.
	 */
	result = dns_dbtable_find(client->view->dbtable,
				  client->query.qname, &db);
	if (result == ISC_R_NOTFOUND) {
		/*
		 * We're not directly authoritative for this query name, nor
		 * is it a subdomain of any zone for which we're
		 * authoritative.
		 */
		if (!use_cache) {
			/*
			 * If we can't use the cache, either because we
			 * don't have one or because its use has been
			 * disallowed, there's no more progress we can make
			 * on this query.
			 */
			QUERY_ERROR(DNS_R_REFUSED);
			goto cleanup;
		}
		INSIST(client->view->cachedb != NULL);
		dns_db_attach(client->view->cachedb, &db);
	} else if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		/*
		 * Something is broken.
		 */
		QUERY_ERROR(DNS_R_SERVFAIL);
		goto cleanup;
	}

	is_zone = dns_db_iszone(db);
	if (is_zone) {
		auth = ISC_TRUE;

		/*
		 * Get the current version of this database.
		 */
		version = query_findversion(client, db);
		if (version == NULL) {
			QUERY_ERROR(DNS_R_SERVFAIL);
			goto cleanup;
		}
	}

	/*
	 * Find the first unanswered type in the question section.
	 */
	qcount = 0;
	qrdataset = NULL;
	qtype = dns_rdatatype_null;
	for (trdataset = ISC_LIST_HEAD(client->query.origqname->list);
	     trdataset != NULL;
	     trdataset = ISC_LIST_NEXT(trdataset, link)) {
		if (!ANSWERED(trdataset)) {
			if (qrdataset == NULL) {
				qrdataset = trdataset;
				qtype = trdataset->type;
			}
			qcount++;
		}
	}
	/*
	 * We had better have found something!
	 */
	INSIST(qrdataset != NULL && qcount > 0);
	/*
	 * If there's more than one question, we'll retrieve the node and
	 * iterate it, trying to find answers.
	 */
	if (qcount == 1)
		type = qtype;
	else {
		type = dns_rdatatype_any;
		/* XXXRTH */
		QUERY_ERROR(DNS_R_NOTIMP);
		goto cleanup;
	}

	/*
	 * See if the type is OK.
	 */
	result = query_checktype(qtype);
	if (result != ISC_R_SUCCESS) {
		QUERY_ERROR(result);
		goto cleanup;
	}

	/*
	 * We'll need some resources...
	 */
	dbuf = query_getnamebuf(client);
	if (dbuf == NULL) {
		QUERY_ERROR(DNS_R_SERVFAIL);
		goto cleanup;
	}
	fname = query_newname(client, dbuf, &b);
	rdataset = query_newrdataset(client);
	if (fname == NULL || rdataset == NULL) {
		QUERY_ERROR(DNS_R_SERVFAIL);
		goto cleanup;
	}

 db_find:
	/*
	 * Now look for an answer in the database.
	 */
	result = dns_db_find(db, client->query.qname, version, type, 0,
			     client->requesttime, &node, fname, rdataset);
	switch (result) {
	case DNS_R_SUCCESS:
	case DNS_R_ZONECUT:
		/*
		 * These cases are handled in the main line below.
		 */
		break;
	case DNS_R_DELEGATION:
		if (is_zone) {
			/*
			 * We're authoritative for an ancestor of QNAME.
			 */
			if (!use_cache) {
				/*
				 * We don't have a cache, so this is the best
				 * answer.
				 */
				query_addrrset(client, &fname, &rdataset, dbuf,
					       DNS_SECTION_AUTHORITY);
			} else {
				/*
				 * We might have a better answer or delegation
				 * in the cache.  We'll remember the current
				 * values of fname and rdataset, and then
				 * go looking for QNAME in the cache.  If we
				 * find something better, we'll use it instead.
				 */
				QUERY_ERROR(DNS_R_NOTIMP);
				goto cleanup;
			}
		} else {
			INSIST(recursion_ok);

			/*
			 * Recurse using the best delegation.
			 */
			QUERY_ERROR(DNS_R_NOTIMP);
		}
		goto cleanup;
	case DNS_R_GLUE:
		auth = ISC_FALSE;
		break;
	case DNS_R_NXRDATASET:
		INSIST(is_zone);
		if (dns_rdataset_isassociated(rdataset)) {
			/*
			 * If we've got a NXT record, we need to save the
			 * name now because we're going call query_addsoa()
			 * below, and it needs to use the name buffer.
			 */
			query_keepname(client, fname, dbuf);
			/*
			 * We don't want the cleanup code to try to release
			 * fname if we fail below, so we set it to NULL.
			 */
			tname = fname;
			fname = NULL;
		} else {
			/*
			 * We're not going to use fname, and need to release
			 * our hold on the name buffer so query_addsoa()
			 * may use it.
			 */
			query_releasename(client, &fname);
		}
		/*
		 * Add SOA.
		 */
		result = query_addsoa(client, db);
		if (result != ISC_R_SUCCESS) {
			QUERY_ERROR(result);
			goto cleanup;
		}
		/*
		 * Add NXT record if we found one.
		 */
		if (dns_rdataset_isassociated(rdataset))
			query_addrrset(client, &tname, &rdataset, NULL,
				       DNS_SECTION_AUTHORITY);
		goto cleanup;
	case DNS_R_NXDOMAIN:
		if (restarts > 0) {
			/*
			 * We hit a dead end following a CNAME or DNAME.
			 */
			goto cleanup;
		}
		INSIST(is_zone);
		/*
		 * Set message rcode.
		 */
		client->message->rcode = dns_rcode_nxdomain;
		/*
		 * Add SOA.
		 */
		query_releasename(client, &fname);
		result = query_addsoa(client, db);
		if (result != ISC_R_SUCCESS) {
			QUERY_ERROR(result);
			goto cleanup;
		}
		/*
		 * XXXRTH  Add NXT chain here.
		 */
		goto cleanup;
	case DNS_R_NOTFOUND:
		QUERY_ERROR(DNS_R_NOTIMP);
		goto cleanup;
	case DNS_R_CNAME:
		/*
		 * Keep a copy of the rdataset.  We have to do this because
		 * query_addrrset may clear 'rdataset' (to prevent the
		 * cleanup code from cleaning it up).
		 */
		trdataset = rdataset;
		/*
		 * Add the CNAME to the answer section.
		 */
		query_addrrset(client, &fname, &rdataset, dbuf,
			       DNS_SECTION_ANSWER);
		/*
		 * We set the PARTIALANSWER attribute so that if anything goes
		 * wrong later on, we'll return what we've got so far.
		 */
		client->query.attributes |= NS_QUERYATTR_PARTIALANSWER;
		/*
		 * Reset qname to be the target name of the CNAME and restart
		 * the query.
		 */
		tname = NULL;
		result = dns_message_gettempname(client->message, &tname);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		result = dns_rdataset_first(trdataset);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		dns_rdataset_current(trdataset, &rdata);
		r.base = rdata.data;
		r.length = rdata.length;
		dns_name_init(tname, NULL);
		dns_name_fromregion(tname, &r);
		client->query.qname = tname;
		want_restart = ISC_TRUE;
		goto cleanup;
	case DNS_R_DNAME:
		/*
		 * Compare the current qname to the found name.  We need
		 * to know how many labels and bits are in common because
		 * we're going to have to split qname later on.
		 */
		namereln = dns_name_fullcompare(client->query.qname, fname,
						&order, &nlabels, &nbits);
		INSIST(namereln == dns_namereln_subdomain);
		/*
		 * Keep a copy of the rdataset.  We have to do this because
		 * query_addrrset may clear 'rdataset' (to prevent the
		 * cleanup code from cleaning it up).
		 */
		trdataset = rdataset;
		/*
		 * Add the DNAME to the answer section.
		 */
		query_addrrset(client, &fname, &rdataset, dbuf,
			       DNS_SECTION_ANSWER);
		/*
		 * We set the PARTIALANSWER attribute so that if anything goes
		 * wrong later on, we'll return what we've got so far.
		 */
		client->query.attributes |= NS_QUERYATTR_PARTIALANSWER;
		/*
		 * Get the target name of the DNAME.
		 */
		tname = NULL;
		result = dns_message_gettempname(client->message, &tname);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		result = dns_rdataset_first(trdataset);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		dns_rdataset_current(trdataset, &rdata);
		r.base = rdata.data;
		r.length = rdata.length;
		dns_name_init(tname, NULL);
		dns_name_fromregion(tname, &r);
		/*
		 * Construct the new qname and restart the query.
		 */
		dns_fixedname_init(&fixed);
		prefix = dns_fixedname_name(&fixed);
		result = dns_name_split(client->query.qname, nlabels, nbits,
					prefix, NULL);
		if (result != ISC_R_SUCCESS)
			goto cleanup;	
		if (fname != NULL)
			query_releasename(client, &fname);
		dbuf = query_getnamebuf(client);
		if (dbuf == NULL)
			goto cleanup;
		fname = query_newname(client, dbuf, &b);
		if (fname == NULL)
			goto cleanup;
		result = dns_name_concatenate(prefix, tname, fname, NULL);
		if (result != ISC_R_SUCCESS) {
			if (result == ISC_R_NOSPACE) {
				/*
				 * draft-ietf-dnsind-dname-03.txt, section
				 * 4.1, subsection 3c says we should
				 * return YXDOMAIN if the constructed
				 * name would be too long.
				 */
				client->message->rcode = dns_rcode_yxdomain;
			}
			goto cleanup;
		}
		query_keepname(client, fname, dbuf);
		client->query.qname = fname;
		fname = NULL;
		want_restart = ISC_TRUE;
		goto cleanup;
	default:
		/*
		 * Something has gone wrong.
		 */
		QUERY_ERROR(DNS_R_SERVFAIL);
		goto cleanup;
	}

	if (type == dns_rdatatype_any) {
		/*
		 * XXXRTH  Need to handle zonecuts with special case
		 * code.
		 */
		n = 0;
		rdsiter = NULL;
		result = dns_db_allrdatasets(db, node, NULL, 0, &rdsiter);
		if (result != ISC_R_SUCCESS) {
			QUERY_ERROR(DNS_R_SERVFAIL);
			goto cleanup;
		}
		result = dns_rdatasetiter_first(rdsiter);
		while (result == ISC_R_SUCCESS) {
			dns_rdatasetiter_current(rdsiter, rdataset);
			tname = fname;
			query_addrrset(client, &tname, &rdataset, dbuf,
				       DNS_SECTION_ANSWER);
			n++;
			/*
			 * We shouldn't ever fail to add 'rdataset' because
			 * it's already in the answer.
			 */
			INSIST(rdataset == NULL);
			/*
			 * We set dbuf to NULL because we only want the
			 * query_keepname() call in query_addrrset() to be
			 * called once.
			 */
			dbuf = NULL;
			result = dns_message_gettemprdataset(client->message,
							     &rdataset);
			if (result == ISC_R_SUCCESS) {
				dns_rdataset_init(rdataset);
				result = dns_rdatasetiter_next(rdsiter);
			}
		}
		/*
		 * If we added at least one RRset, then we must clear fname,
		 * otherwise the cleanup code might cause it to be reused.
		 */
		if (n > 0)
			fname = NULL;
		dns_rdatasetiter_destroy(&rdsiter);
		if (result != DNS_R_NOMORE) {
			QUERY_ERROR(DNS_R_SERVFAIL);
			goto cleanup;
		}
	} else {
		/*
		 * This is the "normal" case -- an ordinary question to which
		 * we know the answer.
		 */
		query_addrrset(client, &fname, &rdataset, dbuf,
			       DNS_SECTION_ANSWER);
		/*
		 * Remember that we've answered this question.
		 */
		qrdataset->attributes |= DNS_RDATASETATTR_ANSWERED;
	}

	/*
	 * XXXRTH  Handle additional questions above.  Find all the question
	 *         types we can from the node we found, and (if recursion is
	 *	   OK) launch queries for any types we don't have answers to.
	 *
	 *	   Special case:  they make an ANY query as well as some
	 *         other type.  Perhaps ANY should be disallowed in a
	 *         multiple question query?
	 */

 cleanup:
	if (rdataset != NULL) {
		if (rdataset->methods != NULL)
			dns_rdataset_disassociate(rdataset);
		ISC_LIST_APPEND(client->query.tmprdatasets, rdataset, link);
	}
	if (fname != NULL)
		query_releasename(client, &fname);
	if (node != NULL)
		dns_db_detachnode(db, &node);
	if (db != NULL)
		dns_db_detach(&db);

	if (restarts == 0 && !auth) {
		/*
		 * We're not authoritative, so we must ensure the AA bit
		 * isn't set.
		 */
		client->message->flags &= ~DNS_MESSAGEFLAG_AA;
	}

	if (want_restart && restarts < MAX_RESTARTS) {
		restarts++;
		goto restart;
	}

	if (eresult != ISC_R_SUCCESS && !PARTIALANSWER(client))
		ns_client_error(client, eresult);
	else
		ns_client_send(client);
}

/*
 * XXXRTH  Problem areas.
 *
 * If we're authoritative for both a parent and a child, the
 * child is non-secure, and we are asked for the KEY of the
 * nonsecure child, we need to get it from the parent.
 * If we're not auth for the parent, then we have to go
 * looking for it in the cache.  How do we even know who
 * the parent is?  We probably won't find this KEY when doing
 * additional data KEY retrievals, but that's probably OK,
 * since it's a SHOULD not a MUST.  We don't want to be doing
 * tons of work just to fill out additional data.
 *
 * Similar problems occur with NXT queries, since there can
 * be NXT records at a delegation point in both the parent
 * and the child.  RFC 2535 section 5.5 says that on explicit
 * query we should return both, if available.  That seems
 * to imply we shouldn't recurse to get the missing one
 * if only one is available.  Is that right?
 */

void
ns_query_start(ns_client_t *client) {
	isc_result_t result;
	dns_message_t *message = client->message;
	dns_rdataset_t *rdataset;

	/*
	 * Ensure that appropriate cleanups occur.
	 */
	client->next = query_next;

	/*
	 * XXXRTH  Deal with allow-query and allow-recursion here.
	 */

	/*
	 * If the client doesn't want recursion, turn it off.
	 */
	if ((message->flags & DNS_MESSAGEFLAG_RD) == 0)
		client->query.attributes &= ~NS_QUERYATTR_RECURSIONOK;

	/*
	 * Get the question name.
	 */
	result = dns_message_firstname(message, DNS_SECTION_QUESTION);
	if (result != ISC_R_SUCCESS) {
		ns_client_error(client, result);
		return;
	}
	dns_message_currentname(message, DNS_SECTION_QUESTION,
				&client->query.qname);
	client->query.origqname = client->query.qname;
	result = dns_message_nextname(message, DNS_SECTION_QUESTION);
	if (result != ISC_R_NOMORE) {
		if (result == ISC_R_SUCCESS) {
			/*
			 * There's more than one QNAME in the question
			 * section.
			 */
			ns_client_error(client, DNS_R_FORMERR);
		} else
			ns_client_error(client, result);
		return;
	}

	/*
	 * Check for illegal meta-classes and meta-types in
	 * multiple question queries (edns1 section 5.1).
	 */
	if (message->counts[DNS_SECTION_QUESTION] > 1) {
		if (dns_rdataclass_ismeta(message->rdclass)) {
			ns_client_error(client, DNS_R_FORMERR);
			return;
		}
		for (rdataset = ISC_LIST_HEAD(client->query.qname->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			if (dns_rdatatype_ismeta(rdataset->type)) {
				ns_client_error(client, DNS_R_FORMERR);
				return;
			}
		}
	}
	
	/*
	 * Check for meta-queries like IXFR and AXFR.
	 */
	if (message->counts[DNS_SECTION_QUESTION] == 1) {
		rdataset = ISC_LIST_HEAD(client->query.qname->list);
		INSIST(rdataset != NULL);
		if (dns_rdatatype_ismeta(rdataset->type)) {
			switch (rdataset->type) {
			case dns_rdatatype_any:
				break; /* Let query_find handle it. */
			case dns_rdatatype_ixfr:
			case dns_rdatatype_axfr:
#ifdef notyet
				ns_xfr_start(client, rdataset->type);
				return;
#endif
			case dns_rdatatype_maila:
			case dns_rdatatype_mailb:
				ns_client_error(client, DNS_R_NOTIMP);
				return;
			default: /* TSIG, etc. */
				ns_client_error(client, DNS_R_FORMERR);
				return;
			}
		}
	}

	/* This is an ordinary query. */

	result = dns_message_reply(message, ISC_TRUE);
	if (result != ISC_R_SUCCESS) {
		ns_client_next(client, result);
		return;
	}

	/*
	 * Assume authoritative response until it is known to be
	 * otherwise.
	 */
	message->flags |= DNS_MESSAGEFLAG_AA;

	query_find(client);
}
