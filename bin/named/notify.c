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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/taskpool.h>

#include <dns/aml.h>
#include <dns/confip.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/dbtable.h>
#include <dns/dnssec.h>
#include <dns/events.h>
#include <dns/fixedname.h>
#include <dns/journal.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/nxt.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>
#include <dns/types.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zt.h>

#include <named/globals.h>
#include <named/client.h>
#include <named/log.h>
#include <named/notify.h>

/*
 * This module implements notify as in RFCXXXX.
 */
  
/**************************************************************************/

/*
 * Convenience macro of common isc_log_write() arguments
 * to use in reportings server errors.
 */
#define NOTIFY_ERROR_LOGARGS \
	ns_g_lctx, NS_LOGCATEGORY_NOTIFY, NS_LOGMODULE_NOTIFY, \
	ISC_LOG_ERROR

/*
 * Convenience macro of common isc_log_write() arguments
 * to use in tracing dynamic update protocol requests.
 */
#define NOTIFY_PROTOCOL_LOGARGS \
	ns_g_lctx, NS_LOGCATEGORY_NOTIFY, NS_LOGMODULE_NOTIFY, \
	ISC_LOG_INFO

/*
 * Convenience macro of common isc_log_write() arguments
 * to use in low-level debug tracing.
 */
#define NOTIFY_DEBUG_LOGARGS \
	ns_g_lctx, NS_LOGCATEGORY_NOTIFY, NS_LOGMODULE_NOTIFY, \
	ISC_LOG_DEBUG(8)

/*
 * Check an operation for failure.  These macros all assume that
 * the function using them has a 'result' variable and a 'failure'
 * label.
 */
#define CHECK(op) \
	do { result = (op); 				  	 \
	       if (result != DNS_R_SUCCESS) goto failure; 	 \
	} while (0)

/*
 * Fail unconditionally with result 'code', which must not
 * be DNS_R_SUCCESS.  The reason for failure presumably has
 * been logged already.
 */

#define FAIL(code) \
	do {							\
		result = (code);				\
		goto failure;					\
	} while (0)

/*
 * Fail unconditionally and log as a client error.
 */
#define FAILC(code, msg) \
	do {							\
		result = (code);				\
		isc_log_write(NOTIFY_PROTOCOL_LOGARGS,		\
			      "notify failed: %s (%s)",	\
		      	      msg, isc_result_totext(code));	\
		goto failure;					\
	} while (0)

/*
 * Fail unconditionally and log as a server error.
 */
#define FAILS(code, msg) \
	do {							\
		result = (code);				\
		isc_log_write(NOTIFY_PROTOCOL_LOGARGS,		\
			      "notify error: %s: %s", 	\
			      msg, isc_result_totext(code));	\
		goto failure;					\
	} while (0)

/**************************************************************************/

static void
respond(ns_client_t *client, dns_result_t result) {
        int msg_result;
        dns_message_t *response = NULL;
        msg_result = dns_message_create(client->mctx, DNS_MESSAGE_INTENTRENDER,
                                        &response);
        if (msg_result != DNS_R_SUCCESS)
                goto msg_failure;

        response->id = client->message->id;
        response->rcode = (result == DNS_R_SUCCESS ?
                dns_rcode_noerror : dns_result_torcode(result));
        response->flags = client->message->flags;
        response->flags |= DNS_MESSAGEFLAG_QR;
	response->opcode = client->message->opcode;

        dns_message_destroy(&client->message);
        client->message = response;
        ns_client_send(client);
        return;

 msg_failure:
        isc_log_write(ns_g_lctx, NS_LOGCATEGORY_NOTIFY, NS_LOGMODULE_NOTIFY,
                      ISC_LOG_ERROR,
                      "could not create update response message: %s",
                      isc_result_totext(msg_result));
        ns_client_next(client, msg_result);
}

void
ns_notify_start(ns_client_t *client)
{
	dns_message_t *request = client->message;
	dns_result_t result;
	dns_name_t *zonename;
	dns_rdataset_t *zone_rdataset;
	dns_zone_t *zone = NULL;
	dns_rdataclass_t zoneclass;
	
	/*
	 * Interpret the question section.
	 */
	result = dns_message_firstname(request, DNS_SECTION_QUESTION);
	if (result != DNS_R_SUCCESS)
		FAILC(DNS_R_FORMERR,
		      "notify question section empty");

	/*
	 * The question section must contain exactly one question.
	 */
	zonename = NULL;
	dns_message_currentname(request, DNS_SECTION_QUESTION, &zonename);
	zone_rdataset = ISC_LIST_HEAD(zonename->list);
	zoneclass = zone_rdataset->rdclass;
	if (ISC_LIST_NEXT(zone_rdataset, link) != NULL)
		FAILC(DNS_R_FORMERR,
		      "notify question section contains multiple RRs");

	/* The zone section must have exactly one name. */
	result = dns_message_nextname(request, DNS_SECTION_ZONE);
	if (result != DNS_R_NOMORE)
		FAILC(DNS_R_FORMERR,
		      "notify question section contains multiple RRs");

	result = dns_zt_find(client->view->zonetable, zonename, NULL, &zone);
	if (result != DNS_R_SUCCESS)
		FAILC(DNS_R_REFUSED,
		      "not authoritative for update zone");

	switch(dns_zone_gettype(zone)) {
	case dns_zone_master:
		FAILC(DNS_R_REFUSED,
		      "notify to master");
	case dns_zone_slave:
		respond(client, dns_zone_notifyreceive(zone,
			ns_client_getsockaddr(client), request));
		return;
	default:
		FAILC(DNS_R_REFUSED,
		      "not authoritative for update zone");
	}
	return;
	
 failure:
	/*
	 * We failed without having sent an update event to the zone.
	 * We are still in the client task context, so we can 
	 * simply give an error response without switching tasks.
	 */
	respond(client, result);
}
