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
		dbuf = ISC_LIST_TAIL(client->namebufs);
		isc_buffer_available(&dbuf->buffer, &r);
		if (r.length < 255) {
			result = ns_client_newnamebuf(client);
			if (result != ISC_R_SUCCESS)
				return (result);
			dbuf = ISC_LIST_TAIL(client->namebufs);
			isc_buffer_available(&dbuf->buffer, &r);
			INSIST(r.length >= 255);
		}
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
		result = dns_dbtable_find(ns_g_dbtable, client->qname, &db);
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
		result = dns_db_find(db, client->qname, NULL, type, 0, 0,
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
			client->qname = tname;
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
			section = DNS_SECTION_AUTHORITY;
			ISC_LIST_APPEND(fname->list, rdataset, link);
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
				ISC_LIST_APPEND(fname->list, rdataset, link);
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
		} else
			ISC_LIST_APPEND(fname->list, rdataset, link);

		dns_message_addname(client->message, fname, section);

		if (!auth && !first_time)
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
	unsigned int nquestions = 0;

	result = dns_message_reply(client->message, ISC_TRUE);
	if (result != ISC_R_SUCCESS) {
		ns_client_next(client, result);
		return;
	}

	/*
	 * Assume authoritative response until it is known to be
	 * otherwise.
	 */
	client->message->flags |= DNS_MESSAGEFLAG_AA;

	/*
	 * Answer each question.
	 */
	result = dns_message_firstname(client->message, DNS_SECTION_QUESTION);
	while (result == ISC_R_SUCCESS) {
		nquestions++;
		client->qname = NULL;
		dns_message_currentname(client->message, DNS_SECTION_QUESTION,
					&client->qname);
		for (rdataset = ISC_LIST_HEAD(client->qname->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			result = find(client, rdataset->type);
			if (result != ISC_R_SUCCESS) {
				ns_client_error(client, result);
				return;
			}
		}
		result = dns_message_nextname(client->message,
					      DNS_SECTION_QUESTION);
	}
	if (result != ISC_R_NOMORE) {
		ns_client_error(client, result);
		return;
	}

	if (nquestions == 0) {
		ns_client_error(client, DNS_R_FORMERR);
		return;
	}

	ns_client_send(client);
}
