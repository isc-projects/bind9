/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: conflwres.h,v 1.3.4.1 2001/01/09 22:45:21 bwelling Exp $ */

#ifndef DNS_CONFLWRES_H
#define DNS_CONFLWRES_H 1

/*****
 ***** Module Info
 *****/

/*
 * The ADTs for the lwres statement in a named.conf config file.
 */

/*
 *
 * MP:
 *
 *	Caller must to all necessary locking.
 *
 * Reliability:
 *
 *	Not applicable.
 *
 * Resources:
 *
 *	Memory allocators supplied by caller
 *
 * Security:
 *
 *	Not applicable.
 *
 * Standards:
 *
 *	Not applicable.
 */

/***
 *** Imports
 ***/

#include <stdio.h>

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/types.h>

#include <dns/confip.h>

#define DNS_C_LWRES_MAGIC		0x4C575253 /* LWRS */
#define DNS_C_LWLIST_MAGIC		0x4C57524C /* LWRL */
#define DNS_C_SEARCH_MAGIC		0x53524348 /* SRCH */
#define DNS_C_SEARCHLIST_MAGIC		0x5352434C /* SRCL */

#define DNS_C_LWRES_VALID(ptr)		ISC_MAGIC_VALID(ptr, DNS_C_LWRES_MAGIC)
#define DNS_C_LWLIST_VALID(ptr)		ISC_MAGIC_VALID(ptr, DNS_C_LWLIST_MAGIC)
#define DNS_C_SEARCH_VALID(ptr)	   	ISC_MAGIC_VALID(ptr, DNS_C_SEARCH_MAGIC)
#define DNS_C_SEARCHLIST_VALID(ptr) 	ISC_MAGIC_VALID(ptr, DNS_C_SEARCHLIST_MAGIC)

/***
 *** Types
 ***/

typedef struct dns_c_lwres		dns_c_lwres_t;
typedef struct dns_c_lwres_list		dns_c_lwreslist_t;
typedef struct dns_c_search		dns_c_search_t;
typedef struct dns_c_search_list	dns_c_searchlist_t;

/*
 * The type for holding an lwres config structure
 */
struct dns_c_lwres {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	dns_c_iplist_t	       *listeners;
	char		       *view;
	dns_rdataclass_t	viewclass;
	dns_c_searchlist_t     *searchlist;
	unsigned int		ndots;
	isc_boolean_t		ndotsset;

	ISC_LINK(dns_c_lwres_t)	next;
};

/*
 * A list of lwres config structures
 */
struct dns_c_lwres_list {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_lwres_t)	lwreslist;
};


/*
 * A search list element.
 */
struct dns_c_search {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;
	char		       *search;

	ISC_LINK(dns_c_search_t)	next;
};


/*
 * A search list.
 */
struct dns_c_search_list {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_search_t)	searches;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t dns_c_lwreslist_new(isc_mem_t *mem,
				 dns_c_lwreslist_t **lwreslist);

isc_result_t dns_c_lwreslist_delete(dns_c_lwreslist_t **list);

isc_result_t dns_c_lwreslist_append(dns_c_lwreslist_t *list,
				    dns_c_lwres_t *lwres);

isc_result_t dns_c_lwreslist_copy(isc_mem_t *mem, dns_c_lwreslist_t **dest,
				  dns_c_lwreslist_t *src);

isc_result_t dns_c_lwreslist_addlwres(dns_c_lwreslist_t *list,
				      dns_c_lwres_t *lwres);

dns_c_lwres_t * dns_c_lwreslist_head (dns_c_lwreslist_t *list);

dns_c_lwres_t * dns_c_lwreslist_next(dns_c_lwres_t *lwres);

void dns_c_lwreslist_print(FILE *fp, int indent, dns_c_lwreslist_t *lwres);

isc_result_t dns_c_lwres_new(isc_mem_t *mem, dns_c_lwres_t **lwresp);

isc_result_t dns_c_lwres_delete(dns_c_lwres_t **lwresp);

isc_result_t dns_c_lwres_setlistenon(dns_c_lwres_t *lwres,
				     dns_c_iplist_t *listeners);

isc_result_t dns_c_lwres_setview(dns_c_lwres_t *lwres, char *view,
				 dns_rdataclass_t rdclass);

isc_result_t dns_c_lwres_setsearchlist(dns_c_lwres_t *lwres,
				       dns_c_searchlist_t *searchlist);

isc_result_t dns_c_lwres_setndots(dns_c_lwres_t *lwres, unsigned int ndots);

void dns_c_lwres_print(FILE *fp, int indent, dns_c_lwres_t *lwres);

isc_result_t dns_c_searchlist_new(isc_mem_t *mem, dns_c_searchlist_t **list);

isc_result_t dns_c_searchlist_delete(dns_c_searchlist_t **list);

void dns_c_searchlist_append(dns_c_searchlist_t *list, dns_c_search_t *search);

void dns_c_searchlist_print(FILE *fp, int indent, dns_c_searchlist_t *list);

isc_result_t dns_c_search_new(isc_mem_t *mem, const char *val,
			      dns_c_search_t **search);


ISC_LANG_ENDDECLS

#endif /* DNS_CONFLWRES_H */
