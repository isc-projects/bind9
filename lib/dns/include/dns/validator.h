/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#ifndef DNS_VALIDATOR_H
#define DNS_VALIDATOR_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Validator
 *
 * XXX <TBS> XXX
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
 *	RFCs:	1034, 1035, 2181, 2535, <TBS>
 *	Drafts:	<TBS>
 */

#include <isc/types.h>
#include <isc/lang.h>
#include <isc/event.h>

#include <dns/types.h>
#include <dns/result.h>

ISC_LANG_BEGINDECLS

/*
 * A dns_validatorevent_t is sent when a 'validation' completes.
 *
 * 'rdataset', 'sigrdataset', and 'message' are the values that were
 * supplied when dns_validator_create() was called.  They are returned to the
 * caller so that they may be freed.
 */
typedef struct dns_validatorevent {
	ISC_EVENT_COMMON(struct dns_validatorevent);
	dns_validator_t *		validator;
	isc_result_t			result;
	dns_name_t *			name;
	dns_rdataset_t *		rdataset;
	dns_rdataset_t *		sigrdataset;
	dns_message_t *			message;
} dns_validatorevent_t;

isc_result_t
dns_validator_create(dns_view_t *view, dns_name_t *name,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
		     dns_message_t *message, unsigned int options,
		     isc_task_t *task, isc_taskaction_t action, void *arg,
		     dns_validator_t **validatorp);

void
dns_validator_cancel(dns_validator_t *validator);

void
dns_validator_destroy(dns_validator_t **validatorp);

ISC_LANG_ENDDECLS

#endif /* DNS_VALIDATOR_H */
