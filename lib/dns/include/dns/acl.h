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

#ifndef DNS_ACL_H
#define DNS_ACL_H 1

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
#include <dns/name.h>
#include <isc/sockaddr.h>

/***
 *** Types
 ***/

typedef enum {
	dns_aclelementtype_ipprefix,
	dns_aclelementtype_keyname,
	dns_aclelementtype_nestedacl,
	dns_aclelementtype_localhost,
	dns_aclelementtype_localnets,
	dns_aclelementtype_any
} dns_aclelemettype_t;

struct dns_aclelement {
	dns_aclelemettype_t type;
	isc_boolean_t negative;
	union {
		struct {
			isc_sockaddr_t address; /* IP4/IP6 */
			unsigned int prefixlen;
		} ip_prefix;
		dns_name_t keyname;
		dns_acl_t *nestedacl;
	} u;
};

struct dns_acl {
	isc_uint32_t		magic;
	isc_mem_t		*mctx;
	unsigned int		refcount;
	dns_aclelement_t	*elements;
	unsigned int 		alloc;		/* Elements allocated */
	unsigned int 		length;		/* Elements initialized */
	char 			*name;		/* Temporary use only */
	ISC_LINK(dns_acl_t) 	nextincache;	/* Ditto */
};

#define DNS_ACL_MAGIC		0x4461636c	/* Dacl */
#define DNS_ACL_VALID(a)	((a) != NULL && \
				 (a)->magic == DNS_ACL_MAGIC)
/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t dns_acl_create(isc_mem_t *mctx, int n, dns_acl_t **target);
/*
 * Create a new ACL with place for 'n' elements.
 * The elements are uninitialized and the length is 0.
 */

isc_result_t dns_acl_any(isc_mem_t *mctx, dns_acl_t **target);
/*
 * Create a new ACL that matches everything.
 */

isc_result_t dns_acl_none(isc_mem_t *mctx, dns_acl_t **target);
/*
 * Create a new ACL that matches nothing.
 */

void dns_acl_attach(dns_acl_t *source, dns_acl_t **target);

void dns_acl_detach(dns_acl_t **aclp);

isc_boolean_t
dns_aclelement_equal(dns_aclelement_t *ea, dns_aclelement_t *eb);

isc_boolean_t dns_acl_equal(dns_acl_t *a, dns_acl_t *b);

isc_result_t
dns_acl_checkrequest(dns_name_t *signer, isc_sockaddr_t *reqaddr,
		     const char *opname,
		     dns_acl_t *main_acl,
		     dns_acl_t *fallback_acl,
		     isc_boolean_t default_allow);
/*
 * Convenience function for "typical" DNS request permission checking.
 *
 * Check the DNS request signed by the key whose name is 'signer',
 * from IP address 'reqaddr', against 'main_acl'.  If main_acl is NULL,
 * check against 'fallback_acl' instead.  If fallback_acl
 * is also NULL, allow the request iff 'default_allow' is ISC_TRUE.
 * Log the outcome of the check if deemed appropriate.
 * Log messages will refer to the request as an 'opname' request.
 *
 * Notes:
 *	This is appropriate for checking allow-update, 
 * 	allow-query, allow-transfer, etc.  It is not appropriate
 * 	for checking the blackhole list because we treat positive
 * 	matches as "allow" and negative matches as "deny"; in
 *	the case of the blackhole list this would be backwards.
 *
 * Requires:
 *	'signer' points to a valid name or is NULL.
 *	'reqaddr' points to a valid socket address.
 *	'opname' points to a null-terminated string.
 *	'main_acl' points to a valid address match list, or is NULL.
 *	'fallback_acl' points to a valid address match list, or is NULL.
 *
 * Returns:
 *	ISC_R_SUCCESS	if the request should be allowed
 * 	ISC_R_REFUSED	if the request should be denied
 *	No other return values are possible.
 */

isc_result_t
dns_acl_match(isc_sockaddr_t *reqaddr,
	      dns_name_t *reqsigner,
	      dns_acl_t *acl,
	      int *match,
	      dns_aclelement_t **matchelt);
/*
 * General, low-level ACL matching.  This is expected to
 * be useful even for weird stuff like the topology and sortlist statements.
 *
 * Match the address 'reqaddr', and optionally the key name 'reqsigner',
 * against 'acl'.  'reqsigner' may be NULL.
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
 *
 * Returns:
 *	DNS_R_SUCCESS		Always succeeds.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_ACL_H */
