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

/* $Id: confrrset.h,v 1.12 2000/06/22 21:55:29 tale Exp $ */

#ifndef DNS_CONFRRSET_H
#define DNS_CONFRRSET_H 1

/*****
 ***** Module Info
 *****/

/*
 * 
 * MP:
 *	
 *
 * Reliability:
 *	
 *
 * Resources:
 *	
 *
 * Security:
 *	
 *
 * Standards:
 *	
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/magic.h>

#include <dns/confcommon.h>


#define DNS_C_RRSOLIST_MAGIC		0x5252534c /* RRSL */
#define DNS_C_RRSO_MAGIC		0x7272736f /* rrso */

#define DNS_C_RRSOLIST_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_RRSOLIST_MAGIC)
#define DNS_C_RRSO_VALID(ptr)     ISC_MAGIC_VALID(ptr, DNS_C_RRSO_MAGIC)

/***
 *** Types
 ***/

typedef struct dns_c_rrso		dns_c_rrso_t;
typedef struct dns_c_rrso_list		dns_c_rrsolist_t;


struct dns_c_rrso {
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;
	
	dns_rdataclass_t	oclass;
	dns_rdatatype_t		otype;
	char		       *name;
	dns_c_ordering_t	ordering;

	ISC_LINK(dns_c_rrso_t)	next;
};

struct dns_c_rrso_list {
	isc_uint32_t		magic;

	isc_mem_t	       *mem;

	ISC_LIST(dns_c_rrso_t)	elements;

};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_c_rrsolist_new(isc_mem_t *mem, dns_c_rrsolist_t **rval);

isc_result_t
dns_c_rrsolist_delete(dns_c_rrsolist_t **list);

isc_result_t
dns_c_rrsolist_copy(isc_mem_t *mem, dns_c_rrsolist_t **dest,
		    dns_c_rrsolist_t *source);

isc_result_t
dns_c_rrsolist_clear(dns_c_rrsolist_t *olist);

isc_result_t
dns_c_rrsolist_append(dns_c_rrsolist_t *dest, dns_c_rrsolist_t *src);

isc_result_t
dns_c_rrso_new(isc_mem_t *mem, dns_c_rrso_t **res, dns_rdataclass_t oclass,
	       dns_rdatatype_t otype, const char *name,
	       dns_c_ordering_t ordering);

isc_result_t
dns_c_rrso_delete(dns_c_rrso_t **order);

isc_result_t
dns_c_rrso_copy(isc_mem_t *mem, dns_c_rrso_t **dest, dns_c_rrso_t *source);

void
dns_c_rrsolist_print(FILE *fp, int indent, dns_c_rrsolist_t *rrlist);

void
dns_c_rrso_print(FILE *fp, int indent, dns_c_rrso_t *rrlist);

ISC_LANG_ENDDECLS

#endif /* DNS_CONFRRSET_H */
