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

/* $Id: acl.h,v 1.11 2000/06/22 21:55:05 tale Exp $ */

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

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/netaddr.h>

#include <dns/name.h>
#include <dns/types.h>

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
			isc_netaddr_t address; /* IP4/IP6 */
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

struct dns_aclenv {
	dns_acl_t *localhost;
	dns_acl_t *localnets;	
};

#define DNS_ACL_MAGIC		0x4461636c	/* Dacl */
#define DNS_ACL_VALID(a)	ISC_MAGIC_VALID(a, DNS_ACL_MAGIC)

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_acl_create(isc_mem_t *mctx, int n, dns_acl_t **target);
/*
 * Create a new ACL with room for 'n' elements.
 * The elements are uninitialized and the length is 0.
 */

isc_result_t
dns_acl_appendelement(dns_acl_t *acl, dns_aclelement_t *elt);
/*
 * Append an element to an existing ACL.
 */

isc_result_t
dns_acl_any(isc_mem_t *mctx, dns_acl_t **target);
/*
 * Create a new ACL that matches everything.
 */

isc_result_t
dns_acl_none(isc_mem_t *mctx, dns_acl_t **target);
/*
 * Create a new ACL that matches nothing.
 */

void
dns_acl_attach(dns_acl_t *source, dns_acl_t **target);

void
dns_acl_detach(dns_acl_t **aclp);

isc_boolean_t
dns_aclelement_equal(dns_aclelement_t *ea, dns_aclelement_t *eb);

isc_boolean_t
dns_acl_equal(dns_acl_t *a, dns_acl_t *b);

isc_result_t
dns_aclenv_init(isc_mem_t *mctx, dns_aclenv_t *env);

void
dns_aclenv_copy(dns_aclenv_t *t, dns_aclenv_t *s);
	
void
dns_aclenv_destroy(dns_aclenv_t *env);

isc_result_t
dns_acl_match(isc_netaddr_t *reqaddr,
	      dns_name_t *reqsigner,
	      dns_acl_t *acl,
	      dns_aclenv_t *env,
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
 *	ISC_R_SUCCESS		Always succeeds.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_ACL_H */
