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

#ifndef DNS_AML_H
#define DNS_AML_H 1

/*****
 ***** Module Info
 *****/

/*
 * Address match list handling.
 */

/***
 *** Imports
 ***/

#include <dns/types.h>
#include <isc/sockaddr.h>
#include <dns/confacl.h>
#include <dns/confip.h>

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_aml_checkrequest(dns_message_t *request, isc_sockaddr_t *reqaddr,
		     dns_c_ipmatchlist_t *aml,
		     dns_c_acltable_t *acltable, 
		     const char *opname, isc_boolean_t default_allow);
/*
 * Check a request against an address match list.
 * This is appropriate for checking allow-update, 
 * allow-query, allow-axfr, etc.  It is not appropriate
 * for checking the blackhole list because
 * we log positive matches as "allow" and negative
 * matches as "deny"; in the case of the blackhole list
 * this would all be backwards.
 */

isc_result_t
dns_aml_match(isc_sockaddr_t *reqaddr,
	      dns_name_t *reqsigner,
	      dns_c_ipmatchlist_t *aml,
	      dns_c_acltable_t *acltable,
	      int *match,
	      dns_c_ipmatchelement_t **matchelt);
/*
 * General, low-level address match list matching.  This is expected to
 * be useful even for weird stuff like the topology and sortlist statements.
 *
 * Match the address 'reqaddr', and optionally the key name 'reqsigner',
 * against the address match list 'aml'.  'reqsigner' may be NULL.
 *
 * If there is a positive match, '*match' will be set to a positive value
 * indicating the distance from the beginning of the list.
 *
 * If there is a negative match, '*match' will be set to a negative value
 * whose absoluate value indicates the distance from the beginning of
 * the list.
 *
 * If there is a match (either positive or negative) and 'matchelt' is  
 * non-NULL, *matchelt will be attached to the primitive
 * (non-indirect) address match list element that matched.
 *
 * If there is no match, *match will be set to zero.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_AML_H */
