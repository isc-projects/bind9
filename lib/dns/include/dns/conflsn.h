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

#ifndef DNS_CONFLSN_H
#define DNS_CONFLSN_H 1

/*****
 ***** Module Info
 *****/

/*
 * Data structures to hold information related to ``listen-on'' statements
 * in the named.conf file.
 */
 
/*
 *
 * MP:
 *
 *	Caller must do necessary locking
 *
 * Reliability:
 *
 *	No issues.
 *
 * Resources:
 *
 *	Uses memory managers supplied by callers.
 *
 * Security:
 *
 *	N/A
 *
 * Standards:
 *
 *	N/A
 *	
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/magic.h>

#include <dns/confip.h>

#define DNS_C_LISTEN_MAGIC		0x4c49534eU /* LISN */
#define DNS_C_LLIST_MAGIC		0x4c6c6973U /* Llis */

#define DNS_C_LISTEN_VALID(l)	ISC_MAGIC_VALID(l, DNS_C_LISTEN_MAGIC)
#define DNS_C_LISTENLIST_VALID(l) ISC_MAGIC_VALID(l, DNS_C_LLIST_MAGIC)

/***
 *** Types
 ***/

typedef struct dns_c_lstn_on		dns_c_lstnon_t;
typedef struct dns_c_lstn_list		dns_c_lstnlist_t;

/*
 * Structure for holing value of a single listen-on statement.
 */
struct dns_c_lstn_on {
	isc_uint32_t			magic;
	isc_mem_t		       *mem;
	
	in_port_t			port;
	dns_c_ipmatchlist_t	       *iml;

	ISC_LINK(dns_c_lstnon_t)	next;
};


/*
 * A list of listen-on statements.
 */
struct dns_c_lstn_list {
	isc_uint32_t			magic;
	isc_mem_t		       *mem;

	ISC_LIST(dns_c_lstnon_t)	elements;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_c_lstnlist_new(isc_mem_t *mem, dns_c_lstnlist_t **llist);
/*
 * Creates a new dns_c_lstnlist_t structure from the allocator pointed to
 * by MEM, and stores the pointer to the new structure in *LLIST.
 *
 * Requires:
 *	mem be a pointer to a valid allocator.
 *	llist be a valid non-NULL pointer.
 *
 * Returns:
 *	ISC_R_SUCCESS		on success.
 *	ISC_R_NOMEMORY		on allocation failure.
 */

isc_result_t
dns_c_lstnlist_delete(dns_c_lstnlist_t **llist);
/*
 * Deletes the list pointed to by **LLIST, and all the elements in it.
 * Sets *LLIST to NULL when done.
 *
 * Requires:
 * 
 * Returns:
 *
 *	ISC_R_SUCCESS on success.
 */


isc_result_t
dns_c_lstnlist_print(FILE *fp, int indent, dns_c_lstnlist_t *ll);
/*
 * Prints the given the list LL to the stream FP. INDENT number of tabs
 * preceed each line of output.
 *
 * Requires:
 *
 *	fp be a pointer to a valid FILE.
 *
 */


isc_result_t
dns_c_lstnon_new(isc_mem_t *mem, dns_c_lstnon_t **listen);
/*
 * Creates a new dns_c_lstnon_t structure and stores the pointer
 * in *LISTEN.
 *
 * Requires:
 *	mem be pointer to a valid memory allocator.
 *	listen be a valid non-NULL pointer.
 *
 * Returns:
 *	ISC_R_SUCCESS on success.
 *	ISC_R_NOMEMORY on allocation failure.
 */

isc_result_t
dns_c_lstnon_delete(dns_c_lstnon_t **listen);
/*
 * Deletes the dns_c_lstnon_t structure pointed to by *LISTEN.
 *
 * Requires:
 *
 *	listen be a valid non-NULL pointer.
 *
 * Returns:
 */

isc_result_t
dns_c_lstnon_setiml(dns_c_lstnon_t *listen, dns_c_ipmatchlist_t *iml,
		    isc_boolean_t deepcopy);
/*
 * Sets the iml field of the structure to the value of the IML
 * parameter. If deepcopy paramater is true the structure field is
 * assigned a depp copy of the IML parameter.
 *
 * Requires:
 *
 * Returns:
 *
 *	ISC_R_SUCCESS on happiness
 *	ISC_R_NOMEMORY on allocation failure.
 */

isc_result_t
dns_c_lstnon_print(FILE *fp, int indent, dns_c_lstnon_t *lo);

ISC_LANG_ENDDECLS

#endif /* DNS_CONFLSN_H */
