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

#ifndef DNS_CONFIG_CONFKEYS_H
#define DNS_CONFIG_CONFKEYS_H 1

/*****
 ***** Module Info
 *****/

/*
 * The ADTs for the key values defined in a named.conf config file.
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

#include <config.h>

#include <isc/mem.h>
#include <isc/list.h>



/***
 *** Types
 ***/


typedef struct dns_c_pubkey		dns_c_pubkey_t;
typedef struct dns_c_tkey		dns_c_tkey_t;
typedef struct dns_c_tkey_list		dns_c_tkey_list_t;
typedef struct dns_c_kdef		dns_c_kdef_t;
typedef struct dns_c_kdef_list		dns_c_kdef_list_t;
typedef struct dns_c_kid		dns_c_kid_t;
typedef struct dns_c_kid_list		dns_c_kid_list_t;


/* The type for holding a trusted key value. */
struct dns_c_tkey
{
	isc_mem_t	       *mem;
	
	char		       *domain;
	dns_c_pubkey_t	       *pubkey;

	ISC_LINK(dns_c_tkey_t)	next;
};

/* A list of trusted keys. */
struct dns_c_tkey_list
{
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_tkey_t)	tkeylist;
};
	
	
/* A public key value */
struct dns_c_pubkey
{
	isc_mem_t      *mem;
	isc_int32_t	flags;
	isc_int32_t	protocol;
	isc_int32_t	algorithm;
	char 	       *key;
};


/* A private key definition from a 'key' statement */
struct dns_c_kdef 
{
	dns_c_kdef_list_t      *mylist;	

	char		       *keyid;
	char		       *algorithm;
	char		       *secret;

	ISC_LINK(dns_c_kdef_t)	next;
};


/* A list of private keys */
struct dns_c_kdef_list
{
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_kdef_t)	keydefs;
};


/* A key id for in a server statement 'keys' list */
struct dns_c_kid
{
	dns_c_kid_list_t       *mylist;
	char		       *keyid;

	ISC_LINK(dns_c_kid_t)	next;
};


/* List of key ids for a 'server' statement */
struct dns_c_kid_list
{
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_kid_t)	keyids;
};


/***
 *** Functions
 ***/

isc_result_t	dns_c_pubkey_new(isc_mem_t *mem, isc_int32_t flags,
				 isc_int32_t protocol,
				 isc_int32_t algorithm,
				 const char *key, dns_c_pubkey_t **pubkey);
isc_result_t	dns_c_pubkey_delete(dns_c_pubkey_t **pubkey);
isc_result_t	dns_c_pubkey_copy(isc_mem_t *mem, dns_c_pubkey_t **dest,
				  dns_c_pubkey_t *src);
void		dns_c_pubkey_print(FILE *fp, int indent,
				   dns_c_pubkey_t *pubkey);


isc_result_t	dns_c_kid_list_new(isc_mem_t *mem,
				   dns_c_kid_list_t **list);
isc_result_t	dns_c_kid_list_delete(dns_c_kid_list_t **list);
isc_result_t	dns_c_kid_list_undef(dns_c_kid_list_t *list,
				     const char *keyid);
isc_result_t	dns_c_kid_list_find(dns_c_kid_list_t *list,
				    const char *keyid,
				    dns_c_kid_t **retval);
void		dns_c_kid_list_print(FILE *fp, int indent,
				     dns_c_kid_list_t *list);
isc_result_t	dns_c_kid_new(dns_c_kid_list_t *list, const char *name,
			      dns_c_kid_t **keyid);

isc_result_t	dns_c_kdef_list_new(isc_mem_t *mem,
				    dns_c_kdef_list_t **list);
isc_result_t	dns_c_kdef_list_delete(dns_c_kdef_list_t **list);
isc_result_t	dns_c_kdef_list_undef(dns_c_kdef_list_t *list,
				      const char *keyid);
isc_result_t	dns_c_kdef_list_find(dns_c_kdef_list_t *list,
				     const char *keyid,
				     dns_c_kdef_t **retval);
void		dns_c_kdef_list_print(FILE *fp, int indent,
				      dns_c_kdef_list_t *list);
isc_result_t	dns_c_kdef_new(dns_c_kdef_list_t *list, const char *name,
			       dns_c_kdef_t **keyid);
void		dns_c_kdef_print(FILE *fp, int indent, dns_c_kdef_t *keydef);
isc_result_t	dns_c_kdef_set_algorithm(dns_c_kdef_t *elem,
					 const char *algorithm);
isc_result_t	dns_c_kdef_set_secret(dns_c_kdef_t *elem,
				      const char *secret);

isc_result_t	dns_c_tkey_list_new(isc_mem_t *mem,
				    dns_c_tkey_list_t **newlist);
isc_result_t	dns_c_tkey_list_delete(dns_c_tkey_list_t **list);
isc_result_t	dns_c_tkey_list_copy(isc_mem_t *mem,
				     dns_c_tkey_list_t **dest,
				     dns_c_tkey_list_t *src);
void		dns_c_tkey_list_print(FILE *fp, int indent,
				      dns_c_tkey_list_t *list);
isc_result_t	dns_c_tkey_list_append(dns_c_tkey_list_t *list,
				       dns_c_tkey_t *element,
				       isc_boolean_t copy);

isc_result_t	dns_c_tkey_new(isc_mem_t *mem, const char *domain,
			       isc_int32_t flags,
			       isc_int32_t protocol,
			       isc_int32_t algorithm,
			       const char *key, dns_c_tkey_t **newkey);
isc_result_t	dns_c_tkey_delete(dns_c_tkey_t **tkey);
isc_result_t	dns_c_tkey_copy(isc_mem_t *mem,
				dns_c_tkey_t **dest, dns_c_tkey_t *src);

isc_result_t	dns_c_tkey_get_flags(dns_c_tkey_t *tkey,
				     isc_int32_t *flags);
isc_result_t	dns_c_tkey_get_protocol(dns_c_tkey_t *tkey,
					isc_int32_t *protocol);
isc_result_t	dns_c_tkey_get_algorithm(dns_c_tkey_t *tkey,
					 isc_int32_t *algorithm);
isc_result_t	dns_c_tkey_get_key(dns_c_tkey_t *tkey,
				   const char **key);
void		dns_c_tkey_print(FILE *fp, int indent, dns_c_tkey_t *tkey);



#endif /* DNS_CONFIG_CONFKEYS_H */
