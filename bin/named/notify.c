/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
 * This module implements notify as in RFC 1996.
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
 * to use in tracing notify protocol requests.
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
respond(ns_client_t *client, isc_result_t result) {
	dns_rcode_t rcode;
        dns_message_t *message;
        isc_result_t msg_result;

	message = client->message;
	rcode = dns_result_torcode(result);

	msg_result = dns_message_reply(message, ISC_TRUE);
	if (msg_result != ISC_R_SUCCESS)
		msg_result = dns_message_reply(message, ISC_FALSE);
	if (msg_result != ISC_R_SUCCESS) {
		ns_client_next(client, msg_result);
		return;
	}
	message->rcode = rcode;
	ns_client_send(client);
}

void
ns_notify_start(ns_client_t *client)
{
	dns_message_t *request = client->message;
	isc_result_t result;
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
		      "not authoritative for notify zone");

	switch(dns_zone_gettype(zone)) {
	case dns_zone_master:
	case dns_zone_slave:
		respond(client, dns_zone_notifyreceive(zone,
			ns_client_getsockaddr(client), request));
		break;
	default:
		FAILC(DNS_R_REFUSED,
		      "not authoritative for notify zone");
	}
	return;
	
 failure:
	respond(client, result);
}
