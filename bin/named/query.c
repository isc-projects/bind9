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
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>

#include <named/client.h>
#include <named/globals.h>
#include <named/query.h>

#include "../../isc/util.h"		/* XXX */

#define PARTIALANSWER(c)	(((c)->query.attributes & \
				  NS_QUERYATTR_PARTIALANSWER) != 0)

static inline void
query_reset(ns_client_t *client, isc_boolean_t everything) {
	isc_dynbuffer_t *dbuf, *dbuf_next;

	for (dbuf = ISC_LIST_HEAD(client->query.namebufs);
	     dbuf != NULL;
	     dbuf = dbuf_next) {
		dbuf_next = ISC_LIST_NEXT(dbuf, link);
		if (dbuf_next != NULL || everything) {
			ISC_LIST_UNLINK(client->query.namebufs, dbuf, link);
			isc_dynbuffer_free(client->mctx, &dbuf);
		}
	}
	client->query.attributes = (NS_QUERYATTR_RECURSIONOK|
				    NS_QUERYATTR_CACHEOK);
	client->query.qname = NULL;
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

	REQUIRE(NS_CLIENT_VALID(client));

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

isc_result_t
ns_query_init(ns_client_t *client) {
	ISC_LIST_INIT(client->query.namebufs);
	query_reset(client, ISC_FALSE);
	return (query_newnamebuf(client));
}

static isc_result_t
query_addadditional(void *arg, dns_name_t *name, dns_rdatatype_t type) {
	ns_client_t *client = arg;
	isc_result_t result;
	dns_dbnode_t *node;
	dns_db_t *db;
	dns_name_t *fname, *mname;
	dns_rdataset_t *rdataset;
	dns_section_t section;
	isc_dynbuffer_t *dbuf;
	isc_region_t r;
	isc_buffer_t b;

	REQUIRE(NS_CLIENT_VALID(client));
	REQUIRE(type != dns_rdatatype_any);
	/* XXXRTH  Other requirements. */

	/*
	 * XXXRTH  Should special case 'A' type.  If type is 'A', we should
	 *	   look for A6 and AAAA too.
	 */

	/*
	 * Get the resources we'll need.
	 */
	dbuf = query_getnamebuf(client);
	if (dbuf == NULL)
		return (ISC_R_NOMEMORY);
	isc_buffer_available(&dbuf->buffer, &r);
	isc_buffer_init(&b, r.base, r.length, ISC_BUFFERTYPE_BINARY);
	fname = NULL;
	result = dns_message_gettempname(client->message, &fname);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_name_init(fname, NULL);
	dns_name_setbuffer(fname, &b);
	rdataset = NULL;
	result = dns_message_gettemprdataset(client->message,
						     &rdataset);
	if (result != ISC_R_SUCCESS)
		return (result);
	dns_rdataset_init(rdataset);

	/*
	 * Find a database to answer the query.
	 */
	db = NULL;
	result = dns_dbtable_find(ns_g_dbtable, name, &db);
	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH)
		return (ISC_R_SUCCESS);

	/*
	 * Now look for an answer in the database.
	 */
	node = NULL;
	result = dns_db_find(db, name, NULL, type, client->query.dboptions,
			     0, &node, fname, rdataset);
			     
	switch (result) {
	case DNS_R_SUCCESS:
	case DNS_R_GLUE:
		dns_db_detachnode(db, &node);
		dns_db_detach(&db);
		break;
	case DNS_R_NXRDATASET:
	case DNS_R_ZONECUT:
		dns_db_detachnode(db, &node);
		dns_db_detach(&db);
		return (ISC_R_SUCCESS);
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_DELEGATION:
		dns_rdataset_disassociate(rdataset);
		dns_db_detachnode(db, &node);
		dns_db_detach(&db);
		return (ISC_R_SUCCESS);
	default:
		dns_db_detach(&db);
		return (ISC_R_SUCCESS);
	}

	/*
	 * Record the space we consumed from the namebuf.
	 */
	dns_name_toregion(fname, &r);
	isc_buffer_add(&dbuf->buffer, r.length);

	/*
	 * This is not strictly necessary, but is done to emphasize
	 * that the name's dedicated buffer, which is on our stack,
	 * is no longer used.  It also prevents any later accidental
	 * use of the dedicated buffer.
	 */
	dns_name_setbuffer(fname, NULL);

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
			dns_rdataset_disassociate(rdataset);
			return (ISC_R_SUCCESS);
		}
	}
	ISC_LIST_APPEND(fname->list, rdataset, link);

	dns_message_addname(client->message, fname, DNS_SECTION_ADDITIONAL);

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
		return (query_addadditional(client, name, dns_rdatatype_key));
 	} else if (type == dns_rdatatype_srv) {
		/*
		 * If we're adding SRV records to the additional data
		 * section, it's helpful if we add the SRV additional data
		 * as well.
		 */
		return (dns_rdataset_additionaldata(rdataset,
						    query_addadditional,
						    client));
	}

	return (ISC_R_SUCCESS);
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

#if 0		  
static isc_result_t
newfind(ns_client_t *client) {
	isc_boolean_t cache_ok = ISC_FALSE;
	isc_boolean_t recursion_ok = ISC_FALSE;
	dns_db_t *db;

	/*
	 * First we must find the right database to search
	 */
	db = NULL;
	result = dns_dbtable_find(client->view->dbtable,
				  client->query.qname, &db);
	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		if (PARTIALANSWER(client)) {
			/*
			 * If we've already got an answer we can go with,
			 * use it.  Otherwise there's nothing we can do.
			 */
			return (ISC_R_SUCCESS);
		}
		return (DNS_R_SERVFAIL);
	}
}
#endif

static isc_result_t
find(ns_client_t *client, dns_rdatatype_t type) {
	isc_result_t result;
	dns_dbnode_t *node;
	dns_db_t *db;
	dns_name_t *fname, *tname;
	dns_rdataset_t *rdataset;
	dns_rdatasetiter_t *rdsiter;
	unsigned int section;
	isc_dynbuffer_t *dbuf;
	isc_region_t r;
	isc_buffer_t b;
	unsigned int cname_hops;
	unsigned int dname_hops;
	isc_boolean_t auth;
	isc_boolean_t again;
	isc_boolean_t first_time;
	dns_rdata_t rdata;

	/*
	 * XXXRTH
	 *
	 * This is still jury rigged.
	 */

	/*
	 * One-time initialization.
	 */
	cname_hops = 0;
	dname_hops = 0;
	auth = ISC_FALSE;
	first_time = ISC_TRUE;

	/*
	 * Find answers to questions.
	 */
	do {
		/*
		 * Per iteration initialization.
		 */
		section = DNS_SECTION_ANSWER;
		again = ISC_FALSE;

		/*
		 * Get the resources we'll need.
		 */
		dbuf = query_getnamebuf(client);
		if (dbuf == NULL) {
			if (first_time)
				return (DNS_R_SERVFAIL);
			else
				return (ISC_R_SUCCESS);
		}
		isc_buffer_available(&dbuf->buffer, &r);
		isc_buffer_init(&b, r.base, r.length, ISC_BUFFERTYPE_BINARY);
		fname = NULL;
		result = dns_message_gettempname(client->message, &fname);
		if (result != ISC_R_SUCCESS) {
			if (first_time)
				return (result);
			else
				return (ISC_R_SUCCESS);
		}
		dns_name_init(fname, NULL);
		dns_name_setbuffer(fname, &b);
		rdataset = NULL;
		result = dns_message_gettemprdataset(client->message,
						     &rdataset);
		if (result != ISC_R_SUCCESS) {
			if (first_time)
				return (result);
			else
				return (ISC_R_SUCCESS);
		}
		dns_rdataset_init(rdataset);

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
		
		/*
		 * Find a database to answer the query.
		 */
		db = NULL;
		result = dns_dbtable_find(ns_g_dbtable, client->query.qname,
					  &db);
		if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
			if (first_time)
				return (DNS_R_SERVFAIL);
			else
				return (ISC_R_SUCCESS);
		}

		/*
		 * Now look for an answer in the database.
		 */
		if (dns_db_iszone(db))
			auth = ISC_TRUE;
		node = NULL;
		result = dns_db_find(db, client->query.qname, NULL, type, 0, 0,
				     &node, fname, rdataset);
		switch (result) {
		case DNS_R_SUCCESS:
		case DNS_R_DNAME:
			break;
		case DNS_R_CNAME:
			again = ISC_TRUE;
			cname_hops++;
			tname = NULL;
			result = dns_message_gettempname(client->message,
							 &tname);
			if (result != ISC_R_SUCCESS)
				goto cleanup_rdataset;
			result = dns_rdataset_first(rdataset);
			if (result != ISC_R_SUCCESS)
				goto cleanup_rdataset;
			dns_rdataset_current(rdataset, &rdata);
			r.base = rdata.data;
			r.length = rdata.length;
			dns_name_init(tname, NULL);
			dns_name_fromregion(tname, &r);
			client->query.qname = tname;
			break;
		case DNS_R_GLUE:
		case DNS_R_ZONECUT:
		case DNS_R_DELEGATION:
			auth = ISC_FALSE;
			break;
		case DNS_R_NXRDATASET:
			result = ISC_R_SUCCESS;
			goto cleanup_node;
		case DNS_R_NXDOMAIN:
			if (first_time)
				client->message->rcode = dns_rcode_nxdomain;
			result = ISC_R_SUCCESS;
			goto cleanup_db;
		default:
			result = DNS_R_SERVFAIL;
			goto cleanup_db;
		}

		/*
		 * Record the space we consumed from the namebuf.
		 */
		dns_name_toregion(fname, &r);
		isc_buffer_add(&dbuf->buffer, r.length);

		/*
		 * This is not strictly necessary, but is done to emphasize
		 * that the name's dedicated buffer, which is on our stack,
		 * is no longer used.  It also prevents any later accidental
		 * use of the dedicated buffer.
		 */
		dns_name_setbuffer(fname, NULL);

		if (result == DNS_R_DELEGATION) {
			/*
			 * XXXRTH  This is where we'll set up a resolver
			 * 	   fetch if recursion is allowed.  We'll need
			 *	   to handle the glue case too.
			 *         Also, we'll probably need to split find()
			 *	   up into a series of event callbacks.
			 */
			/*
			 * The following is the "no recursion" case.
			 */
			section = DNS_SECTION_AUTHORITY;
			/*
			 * We don't have to set DNS_DBFIND_VALIDDATEGLUE
			 * because since we'll be processing the NS records
			 * we know the glue is good.
			 */
			client->query.dboptions |= DNS_DBFIND_GLUEOK;
			query_addrdataset(client, fname, rdataset);
		} else if (type == dns_rdatatype_any) {
			/*
			 * XXXRTH  Need to handle zonecuts with special case
			 * code.
			 */
			rdsiter = NULL;
			result = dns_db_allrdatasets(db, node, NULL, 0,
						     &rdsiter);
			if (result == ISC_R_SUCCESS)
				result = dns_rdatasetiter_first(rdsiter);
			while (result == ISC_R_SUCCESS) {
				dns_rdatasetiter_current(rdsiter, rdataset);
				query_addrdataset(client, fname, rdataset);
				rdataset = NULL;
				result = dns_message_gettemprdataset(
						client->message,
						&rdataset);
				if (result == ISC_R_SUCCESS) {
				    dns_rdataset_init(rdataset);
				    result = dns_rdatasetiter_next(rdsiter);
				}
			}
			if (result != DNS_R_NOMORE) {
				result = DNS_R_SERVFAIL;
				goto cleanup_node;
			}
		} else {
			query_addrdataset(client, fname, rdataset);
		}

		dns_message_addname(client->message, fname, section);

		if (!auth && first_time)
			client->message->flags &= ~DNS_MESSAGEFLAG_AA;

		first_time = ISC_FALSE;

		dns_db_detachnode(db, &node);
		dns_db_detach(&db);
	} while (again && cname_hops < 8 && dname_hops < 16);

	return (ISC_R_SUCCESS);

 cleanup_rdataset:
	dns_rdataset_disassociate(rdataset);

 cleanup_node:
	dns_db_detachnode(db, &node);

 cleanup_db:
	dns_db_detach(&db);

	return (result);
}

void
ns_query_start(ns_client_t *client) {
	isc_result_t result;
	dns_rdataset_t *rdataset;
	dns_message_t *message = client->message;

	/*
	 * Ensure that appropriate cleanups occur.
	 */
	client->next = query_next;

	/*
	 * XXXRTH  Deal with allow-query and allow-recursion here.  Also,
	 *         If the view doesn't have a cache or a resolver, then
	 *	   NS_QUERYATTR_RECURSIONOK and NS_QUERYATTR_CACHEOK should
	 *	   be turned off.
	 */

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
	 * XXXRTH  comment here
	 */

	for (rdataset = ISC_LIST_HEAD(client->query.qname->list);
	     rdataset != NULL;
	     rdataset = ISC_LIST_NEXT(rdataset, link)) {
		result = find(client, rdataset->type);
		if (result != ISC_R_SUCCESS) {
			ns_client_error(client, result);
			return;
		}
	}

	ns_client_send(client);
}
