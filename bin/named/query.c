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
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/timer.h>

#include <dns/dispatch.h>
#include <dns/events.h>

#include <named/client.h>

#include "../../isc/util.h"		/* XXX */

static dns_result_t
resolve_packet(isc_mem_t *mctx, dns_message_t *query, isc_buffer_t *target) {
	dns_message_t *message;
	dns_result_t result, dbresult;
	dns_name_t *qname, *fname, *rqname;
	dns_fixedname_t foundname, frqname;
	dns_rdataset_t *rds, *rdataset, rqrds, rdatasets[MAX_RDATASETS];
	unsigned int nrdatasets = 0;
	dns_dbnode_t *node;
	dns_db_t *db;
	dns_rdatasetiter_t *rdsiter;
	dns_rdatatype_t type;
	isc_boolean_t possibly_auth = ISC_FALSE;

	message = NULL;
	result = dns_message_create(mctx, &message, DNS_MESSAGE_INTENTRENDER);
	CHECKRESULT(result, "dns_message_create failed");

	message->id = query->id;
	message->rcode = dns_rcode_noerror;
	message->flags = query->flags;
	message->flags |= DNS_MESSAGEFLAG_QR;

	result = dns_message_firstname(query, DNS_SECTION_QUESTION);
	if (result != DNS_R_SUCCESS)
		return (result);
	qname = NULL;
	dns_fixedname_init(&frqname);
	rqname = dns_fixedname_name(&frqname);
	dns_message_currentname(query, DNS_SECTION_QUESTION, &qname);
	result = dns_name_concatenate(qname, NULL, rqname, NULL);
	if (result != DNS_R_SUCCESS)
		return (DNS_R_UNEXPECTED);
	rds = ISC_LIST_HEAD(qname->list);
	if (rds == NULL)
		return (DNS_R_UNEXPECTED);
	type = rds->type;
	dns_rdataset_init(&rqrds);
	dns_rdataset_makequestion(&rqrds, rds->rdclass, rds->type);
	ISC_LIST_APPEND(rqname->list, &rqrds, link);

	dns_message_addname(message, rqname, DNS_SECTION_QUESTION);

	result = printmessage(message);
	INSIST(result == DNS_R_SUCCESS);  /* XXX not in a real server */

	/*
	 * Find a database to answer the query from.
	 */
	db = NULL;
	result = dns_dbtable_find(dbtable, qname, &db);
	if (result != DNS_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		printf("could not find a dbtable: %s\n",
		       dns_result_totext(result));
		message->rcode = dns_rcode_servfail;
		goto render;
	}
	
	/*
	 * Now look for an answer in the database.
	 */
	dns_fixedname_init(&foundname);
	fname = dns_fixedname_name(&foundname);
	rdataset = &rdatasets[nrdatasets++];
	dns_rdataset_init(rdataset);
	node = NULL;
	dbresult = dns_db_find(db, qname, NULL, type, 0, 0, &node, fname,
			       rdataset);
	switch (dbresult) {
	case DNS_R_SUCCESS:
	case DNS_R_DNAME:
	case DNS_R_CNAME:
		possibly_auth = ISC_TRUE;
		break;
	case DNS_R_GLUE:
	case DNS_R_ZONECUT:
	case DNS_R_DELEGATION:
		break;
	case DNS_R_NXRDATASET:
		if (dns_db_iszone(db))
			message->flags |= DNS_MESSAGEFLAG_AA;
		dns_db_detachnode(db, &node);
		dns_db_detach(&db);
                goto render;
	case DNS_R_NXDOMAIN:
		if (dns_db_iszone(db))
			message->flags |= DNS_MESSAGEFLAG_AA;
		dns_db_detach(&db);
                message->rcode = dns_rcode_nxdomain;
                goto render;
	default:
		printf("%s\n", dns_result_totext(result));
		dns_db_detach(&db);
                message->rcode = dns_rcode_servfail;
                goto render;
	}

	if (dbresult == DNS_R_DELEGATION) {
		ISC_LIST_APPEND(fname->list, rdataset, link);
		dns_message_addname(message, fname, DNS_SECTION_AUTHORITY);
	} else if (type == dns_rdatatype_any) {
		rdsiter = NULL;
		result = dns_db_allrdatasets(db, node, NULL, 0, &rdsiter);
		if (result == DNS_R_SUCCESS)
			result = dns_rdatasetiter_first(rdsiter);
		while (result == DNS_R_SUCCESS) {
			dns_rdatasetiter_current(rdsiter, rdataset);
			ISC_LIST_APPEND(fname->list, rdataset, link);
			if (nrdatasets == MAX_RDATASETS) {
				result = DNS_R_NOSPACE;
			} else {
				rdataset = &rdatasets[nrdatasets++];
				dns_rdataset_init(rdataset);
				result = dns_rdatasetiter_next(rdsiter);
			}
		}
		if (result != DNS_R_NOMORE) {
			dns_db_detachnode(db, &node);
			dns_db_detach(&db);
			message->rcode = dns_rcode_servfail;
			goto render;
		}
		dns_message_addname(message, fname, DNS_SECTION_ANSWER);
	} else {
		ISC_LIST_APPEND(fname->list, rdataset, link);
		dns_message_addname(message, fname, DNS_SECTION_ANSWER);
	}

	if (dns_db_iszone(db) && possibly_auth)
		message->flags |= DNS_MESSAGEFLAG_AA;

	dns_db_detachnode(db, &node);
	dns_db_detach(&db);

 render:

	result = dns_message_renderbegin(message, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_QUESTION,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_ANSWER,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_AUTHORITY,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_ADDITIONAL,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_TSIG,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_renderend(message);

	dns_message_destroy(&message);

	return (DNS_R_SUCCESS);
}

void
ns_query_start(ns_client_t *client) {

}
