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
 *	Caller must do necessary locking
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

#include <isc/region.h>
#include <isc/list.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/net.h>

#include <dns/confcommon.h>


#define DNS_C_IPLIST_MAGIC 0x49706c73	/* Ipls */ /* dns_c_iplist */
#define DNS_C_IPMDIRECT_MAGIC 0x49506d64 /* IPmd */ /* dns_c_ipmatch_direct */
#define DNS_C_IPMINDIRECT_MAGIC 0x69506d69 /* iPmi */ /* dns_c_ipmatch_indirect */
#define DNS_C_IPMELEM_MAGIC 0x49704d65	/* IpMe */ /* dns_c_ipmatch_element */
#define DNS_C_IPMLIST_MAGIC 0x69706d6c	/* ipml */ /* dns_c_ipmatchlist */

#define DNS_C_IPLIST_VALID(ptr)	ISC_MAGIC_VALID(ptr,DNS_C_IPLIST_MAGIC)
#define DNS_C_IPDIRECT_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_IPMDIRECT_MAGIC)
#define DNS_C_IPINDIRECT_VALID(ptr) \
	ISC_MAGIC_VALID(ptr, DNS_C_IPMINDIRECT_MAGIC)
#define DNS_C_IPMELEM_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_IPMELEM_MAGIC)
#define DNS_C_IPMLIST_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_IPMLIST_MAGIC)




/***
 *** Types
 ***/


typedef struct dns_c_iplist		dns_c_iplist_t;
typedef struct dns_c_ipmatch_direct	dns_c_ipmatch_direct_t ;
typedef struct dns_c_ipmatch_indirect	dns_c_ipmatch_indirect_t;
typedef struct dns_c_ipmatch_key	dns_c_ipmatch_key_t;
typedef struct dns_c_ipmatch_element	dns_c_ipmatchelement_t;
typedef struct dns_c_ipmatch_list	dns_c_ipmatchlist_t;


/* A list of IP addresses (IPv4 or IPv6) */
struct dns_c_iplist {
	isc_uint32_t		magic;
	
	isc_mem_t	       *mem;
	int			refcount;
	isc_sockaddr_t	       *ips;
	isc_uint32_t		size;
	isc_uint32_t		nextidx;
};



struct dns_c_ipmatch_direct
{
	isc_uint32_t	magic;
	
	isc_sockaddr_t	address;		/* XXX IPv6??? */
	isc_uint32_t	mask;
};



struct dns_c_ipmatch_indirect
{
	isc_uint32_t	magic;
	
	isc_textregion_t refname;	/* for acls, mostly. */
	dns_c_ipmatchlist_t *list;
};



struct dns_c_ipmatch_element
{
	isc_uint32_t	magic;
	
	dns_c_ipmatch_type_t type;
	u_int flags;
	union {
		dns_c_ipmatch_direct_t		direct;
		dns_c_ipmatch_indirect_t	indirect;
		char			       *key;
		char			       *aclname;
	} u;

	ISC_LINK(dns_c_ipmatchelement_t) next;
};


struct dns_c_ipmatch_list
{
	isc_uint32_t	magic;
	
	isc_mem_t *mem;
	int refcount;

	ISC_LIST(dns_c_ipmatchelement_t) elements;
};


/***
 *** Functions
 ***/

/*
 * In all the functions below where an isc_mem_t is a parameter, that
 * paramater will be used for all memory allocation.
 */


isc_result_t	dns_c_ipmatchelement_new(isc_mem_t *mem,
					 dns_c_ipmatchelement_t **result);
isc_result_t	dns_c_ipmatchelement_delete(isc_mem_t *mem,
					    dns_c_ipmatchelement_t **ipme);
isc_result_t	dns_c_ipmatchelement_copy(isc_mem_t *mem,
					  dns_c_ipmatchelement_t **dest,
					  dns_c_ipmatchelement_t *src);
isc_result_t	dns_c_ipmatchelement_print(FILE *fp, int indent,
					   dns_c_ipmatchelement_t *ime);
isc_boolean_t	dns_c_ipmatchelement_isneg(dns_c_ipmatchelement_t *elem);

isc_result_t	dns_c_ipmatch_negate(dns_c_ipmatchelement_t *ipe);
isc_result_t	dns_c_ipmatch_aclnew(isc_mem_t *mem,
				     dns_c_ipmatchelement_t **result,
				     const char *aclname);
isc_result_t	dns_c_ipmatchkey_new(isc_mem_t *mem,
				     dns_c_ipmatchelement_t **result,
				     const char *key);
isc_result_t	dns_c_ipmatchany_new(isc_mem_t *mem,
				     dns_c_ipmatchelement_t **result); 
isc_result_t	dns_c_ipmatchlocalhost_new(isc_mem_t *mem,
					   dns_c_ipmatchelement_t **result); 
isc_result_t	dns_c_ipmatchlocalnets_new(isc_mem_t *mem,
					   dns_c_ipmatchelement_t **result); 
isc_result_t	dns_c_ipmatchpattern_new(isc_mem_t *mem,
					 dns_c_ipmatchelement_t **result,
					 isc_sockaddr_t address,
					 isc_uint32_t maskbits);
isc_result_t	dns_c_ipmatchindirect_new(isc_mem_t *mem,
					  dns_c_ipmatchelement_t **result,
					  dns_c_ipmatchlist_t *iml,
					  const char *name);

isc_result_t	dns_c_ipmatchlist_new(isc_mem_t *mem,
				      dns_c_ipmatchlist_t **ptr);
isc_result_t	dns_c_ipmatchlist_detach(dns_c_ipmatchlist_t **ml);
void		dns_c_ipmatchlist_attach(dns_c_ipmatchlist_t *source,
					  dns_c_ipmatchlist_t **target);
isc_result_t	dns_c_ipmatchlist_copy(isc_mem_t *mem,
				       dns_c_ipmatchlist_t **dest,
				       dns_c_ipmatchlist_t *src);
isc_result_t	dns_c_ipmatchlist_empty(dns_c_ipmatchlist_t *ipml);
isc_result_t	dns_c_ipmatchlist_append(dns_c_ipmatchlist_t *dest,
					 dns_c_ipmatchlist_t *src,
					 isc_boolean_t negate);
isc_result_t	dns_c_ipmatchlist_print(FILE *fp, int indent,
					dns_c_ipmatchlist_t *iml);



isc_result_t	dns_c_iplist_new(isc_mem_t *mem, int length,
				 dns_c_iplist_t **newlist);
isc_result_t	dns_c_iplist_detach(dns_c_iplist_t **list);
isc_result_t	dns_c_iplist_copy(isc_mem_t *mem, dns_c_iplist_t **dest,
				  dns_c_iplist_t *src);
void	        dns_c_iplist_attach(dns_c_iplist_t *source,
				    dns_c_iplist_t **target);
isc_result_t	dns_c_iplist_append(dns_c_iplist_t *list,
				    isc_sockaddr_t newaddr);
isc_result_t	dns_c_iplist_remove(dns_c_iplist_t *list,
				    isc_sockaddr_t newaddr);
void		dns_c_iplist_print(FILE *fp, int indent,
				   dns_c_iplist_t *list);
isc_boolean_t	dns_c_iplist_equal(dns_c_iplist_t *list1,
				   dns_c_iplist_t *list2);

isc_boolean_t dns_c_ipmatchelement_equal(dns_c_ipmatchelement_t *e1,
					 dns_c_ipmatchelement_t *e2);

isc_boolean_t dns_c_ipmatchlist_equal(dns_c_ipmatchlist_t *l1,
				      dns_c_ipmatchlist_t *l2);

#endif /* DNS_CONFIG_CONFIP_H */
