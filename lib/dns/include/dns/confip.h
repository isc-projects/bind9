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

#ifndef DNS_CONFIG_CONFIP_H
#define DNS_CONFIG_CONFIP_H 1

/*****
 ***** Module Info
 *****/

/*
 * Data structures used by the config file parser for managing address
 * lists and address-match lists. These structures are reference counted,
 * so clients can call 'attach' to increment the reference count. The
 * normal destructors won't delete the data until the counter goes to zero.
 */

/*
 * MP:
 *      Caller must do necessary locking
 *
 * Reliability:
 *
 *	No problems known.
 *
 * Resources:
 *
 *	Uses memory managers supplied by caller.
 *
 * Security:
 *
 *	No issues.
 *
 */

/***
 *** Imports
 ***/

#include <config.h>

#include <sys/types.h>
#include <netinet/in.h>

#include <isc/region.h>
#include <isc/list.h>
#include <isc/mem.h>

#include <dns/confcommon.h>


/***
 *** Types
 ***/


typedef struct dns_c_iplist		dns_c_iplist_t;
typedef struct dns_c_ipmatch_direct	dns_c_ipmatch_direct_t ;
typedef struct dns_c_ipmatch_indirect	dns_c_ipmatch_indirect_t;
typedef struct dns_c_ipmatch_key	dns_c_ipmatch_key_t;
typedef struct dns_c_ipmatch_element	dns_c_ipmatch_element_t;
typedef struct dns_c_ipmatch_list	dns_c_ipmatch_list_t;


/* A list of IP addresses (IPv4 or IPv6) */
struct dns_c_iplist {
	isc_mem_t		*mem;

	int refcount;
	
	dns_c_addr_t		*ips;
	isc_uint32_t		size;
	isc_uint32_t		nextidx;
};



struct dns_c_ipmatch_direct
{
	dns_c_addr_t	address;		/* XXX IPv6??? */
	dns_c_addr_t	mask;
};



struct dns_c_ipmatch_indirect
{
	isc_textregion_t refname;	/* for acls, mostly. */
	dns_c_ipmatch_list_t *list;
};



struct dns_c_ipmatch_element
{
	dns_c_ipmatch_type_t type;
	u_int flags;
	union {
		dns_c_ipmatch_direct_t		direct;
		dns_c_ipmatch_indirect_t	indirect;
		char 		       	       *key;
		char		       	       *aclname;
	} u;

	ISC_LINK(dns_c_ipmatch_element_t) next;
};


struct dns_c_ipmatch_list
{
	isc_mem_t *mem;
	int refcount;

	ISC_LIST(dns_c_ipmatch_element_t) elements;
};


/***
 *** Functions
 ***/

/*
 * In all the functions below where an isc_mem_t is a parameter, that
 * paramater will be used for all memory allocation.
 */


isc_result_t	dns_c_ipmatch_element_new(isc_mem_t *mem,
					  dns_c_ipmatch_element_t
					  **result);
isc_result_t	dns_c_ipmatch_element_delete(isc_mem_t *mem,
					     dns_c_ipmatch_element_t **ipme);
isc_result_t	dns_c_ipmatch_element_copy(isc_mem_t *mem,
					   dns_c_ipmatch_element_t **dest,
					   dns_c_ipmatch_element_t *src);
isc_result_t	dns_c_ipmatch_element_print(FILE *fp, int indent,
					    dns_c_ipmatch_element_t *ime);
isc_boolean_t	dns_c_ipmatch_element_isneg(dns_c_ipmatch_element_t *elem);

isc_result_t	dns_c_ipmatch_negate(dns_c_ipmatch_element_t *ipe);
isc_result_t	dns_c_ipmatch_acl_new(isc_mem_t *mem,
				      dns_c_ipmatch_element_t **result,
				      const char *aclname);
isc_result_t	dns_c_ipmatch_key_new(isc_mem_t *mem,
				      dns_c_ipmatch_element_t **result,
				      const char *key);
isc_result_t	dns_c_ipmatch_localhost_new(isc_mem_t *mem,
					    dns_c_ipmatch_element_t **result); 
isc_result_t	dns_c_ipmatch_localnets_new(isc_mem_t *mem,
					    dns_c_ipmatch_element_t **result); 
isc_result_t	dns_c_ipmatch_pattern_new(isc_mem_t *mem,
					  dns_c_ipmatch_element_t **result,
					  dns_c_addr_t address,
					  isc_uint32_t maskbits);
isc_result_t	dns_c_ipmatch_indirect_new(isc_mem_t *mem,
					   dns_c_ipmatch_element_t **result,
					   dns_c_ipmatch_list_t *iml,
					   const char *name);

isc_result_t	dns_c_ipmatch_list_new(isc_mem_t *mem,
				       dns_c_ipmatch_list_t **ptr);
isc_result_t	dns_c_ipmatch_list_delete(dns_c_ipmatch_list_t **ml);
dns_c_ipmatch_list_t *dns_c_ipmatch_list_attach(dns_c_ipmatch_list_t *ipml);
isc_result_t	dns_c_ipmatch_list_copy(isc_mem_t *mem,
					dns_c_ipmatch_list_t **dest,
					dns_c_ipmatch_list_t *src);
isc_result_t	dns_c_ipmatch_list_empty(dns_c_ipmatch_list_t *ipml);
isc_result_t	dns_c_ipmatch_list_append(dns_c_ipmatch_list_t *dest,
					  dns_c_ipmatch_list_t *src,
					  isc_boolean_t negate);
isc_result_t	dns_c_ipmatch_list_print(FILE *fp, int indent,
					 dns_c_ipmatch_list_t *iml);



isc_result_t	dns_c_iplist_new(isc_mem_t *mem, int length,
				 dns_c_iplist_t **newlist);
isc_result_t	dns_c_iplist_delete(dns_c_iplist_t **list);
isc_result_t	dns_c_iplist_copy(isc_mem_t *mem, dns_c_iplist_t **dest,
				  dns_c_iplist_t *src);
dns_c_iplist_t *dns_c_iplist_attach(dns_c_iplist_t *list);
isc_result_t	dns_c_iplist_append(dns_c_iplist_t *list,
				    dns_c_addr_t newaddr);
isc_result_t	dns_c_iplist_remove(dns_c_iplist_t *list,
				    dns_c_addr_t newaddr);
void		dns_c_iplist_print(FILE *fp, int indent,
				   dns_c_iplist_t *list);


#endif /* DNS_CONFIG_CONFIP_H */
