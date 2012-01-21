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

/* $Id: confkeys.h,v 1.17.2.1 2000/07/12 16:37:13 gson Exp $ */

#ifndef DNS_CONFKEYS_H
#define DNS_CONFKEYS_H 1

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

#include <stdio.h>

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/types.h>


#define DNS_C_TKEY_MAGIC		0x544b4559 /* TKEY */
#define DNS_C_TKEYLIST_MAGIC		0x544b4c53 /* TKLS */
#define DNS_C_PUBKEY_MAGIC		0x5055424b /* PUBK */
#define DNS_C_PKLIST_MAGIC		0x504b4c53 /* PKLS */
#define DNS_C_KDEF_MAGIC		0x4b444546 /* KDEF */
#define DNS_C_KDEFLIST_MAGIC		0x4b4c5354 /* KLST */
#define DNS_C_KEYID_MAGIC		0x4b455949 /* KEYI */
#define DNS_C_KEYIDLIST_MAGIC		0x4b494c53 /* KILS */

#define DNS_C_TKEY_VALID(ptr)	   ISC_MAGIC_VALID(ptr, DNS_C_TKEY_MAGIC)
#define DNS_C_TKEYLIST_VALID(ptr)  ISC_MAGIC_VALID(ptr, DNS_C_TKEYLIST_MAGIC)
#define DNS_C_PUBKEY_VALID(ptr)	   ISC_MAGIC_VALID(ptr, DNS_C_PUBKEY_MAGIC)
#define DNS_C_PKLIST_VALID(ptr)	   ISC_MAGIC_VALID(ptr, DNS_C_PKLIST_MAGIC)
#define DNS_C_KDEF_VALID(ptr)	   ISC_MAGIC_VALID(ptr, DNS_C_KDEF_MAGIC)
#define DNS_C_KDEFLIST_VALID(ptr)  ISC_MAGIC_VALID(ptr, DNS_C_KDEFLIST_MAGIC)
#define DNS_C_KEYID_VALID(ptr)	   ISC_MAGIC_VALID(ptr, DNS_C_KEYID_MAGIC)
#define DNS_C_KEYIDLIST_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_KEYIDLIST_MAGIC)

/***
 *** Types
 ***/

typedef struct dns_c_pubkey		dns_c_pubkey_t;
typedef struct dns_c_pklist		dns_c_pklist_t;
typedef struct dns_c_tkey		dns_c_tkey_t;
typedef struct dns_c_tkey_list		dns_c_tkeylist_t;
typedef struct dns_c_kdef		dns_c_kdef_t;
typedef struct dns_c_kdef_list		dns_c_kdeflist_t;
typedef struct dns_c_kid		dns_c_kid_t;
typedef struct dns_c_kid_list		dns_c_kidlist_t;

/*
 * The type for holding a trusted key value.
 */
struct dns_c_tkey {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;
	
	char		       *domain;
	dns_c_pubkey_t	       *pubkey;

	ISC_LINK(dns_c_tkey_t)	next;
};

/*
 * A list of trusted keys.
 */
struct dns_c_tkey_list {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_tkey_t)	tkeylist;
};
	
	
/*
 * A public key value.
 */
struct dns_c_pubkey {
	isc_uint32_t	magic;
	isc_mem_t      *mem;
	isc_uint32_t	flags;
	isc_uint32_t	protocol;
	isc_uint32_t	algorithm;
	char	       *key;

	ISC_LINK(dns_c_pubkey_t)	next;
};

/*
 * A list of pubkeys.
 */
struct dns_c_pklist {
	isc_uint32_t			magic;
	isc_mem_t		       *mem;

	ISC_LIST(dns_c_pubkey_t)	keylist;
};


/*
 * A private key definition from a 'key' statement.
 */
struct dns_c_kdef {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	char		       *keyid;
	char		       *algorithm;
	char		       *secret;

	ISC_LINK(dns_c_kdef_t)	next;
};

/*
 * A list of private keys.
 */
struct dns_c_kdef_list {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_kdef_t)	keydefs;
};


/*
 * A key id for in a server statement 'keys' list.
 */
struct dns_c_kid {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;
	char		       *keyid;

	ISC_LINK(dns_c_kid_t)	next;
};


/*
 * List of key ids for a 'server' statement.
 */
struct dns_c_kid_list {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;

	ISC_LIST(dns_c_kid_t)	keyids;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t dns_c_pklist_new(isc_mem_t *mem, dns_c_pklist_t **pklist);

isc_result_t dns_c_pklist_delete(dns_c_pklist_t **list);

isc_result_t dns_c_pklist_addpubkey(dns_c_pklist_t *list, dns_c_pubkey_t *pkey,
				    isc_boolean_t deepcopy);

isc_result_t dns_c_pklist_findpubkey(dns_c_pklist_t *list,
				     dns_c_pubkey_t **pubkey,
				     isc_uint32_t flags, isc_uint32_t protocol,
				     isc_uint32_t algorithm, const char *key);

isc_result_t dns_c_pklist_rmpubkey(dns_c_pklist_t *list, isc_uint32_t flags,
				   isc_uint32_t protocol,
				   isc_uint32_t algorithm, const char *key);

void dns_c_pklist_print(FILE *fp, int indent, dns_c_pklist_t *pubkey);

isc_result_t dns_c_pubkey_new(isc_mem_t *mem, isc_uint32_t flags,
			      isc_uint32_t protocol,
			      isc_uint32_t algorithm,
			      const char *key,
			      dns_c_pubkey_t **pubkey);

isc_result_t dns_c_pubkey_delete(dns_c_pubkey_t **pubkey);

isc_result_t dns_c_pubkey_copy(isc_mem_t *mem, dns_c_pubkey_t **dest,
			       dns_c_pubkey_t *src);

isc_boolean_t dns_c_pubkey_equal(dns_c_pubkey_t *k1, dns_c_pubkey_t *k2);

void dns_c_pubkey_print(FILE *fp, int indent, dns_c_pubkey_t *pubkey);

isc_result_t dns_c_kidlist_new(isc_mem_t *mem, dns_c_kidlist_t **list);

isc_result_t dns_c_kidlist_delete(dns_c_kidlist_t **list);

isc_uint32_t dns_c_kidlist_keycount(dns_c_kidlist_t *list);

			   
isc_result_t dns_c_kidlist_undef(dns_c_kidlist_t *list, const char *keyid);

isc_result_t dns_c_kidlist_find(dns_c_kidlist_t *list, const char *keyid,
				dns_c_kid_t **retval);

void dns_c_kidlist_append(dns_c_kidlist_t *list, dns_c_kid_t *keyid);

void dns_c_kidlist_print(FILE *fp, int indent, dns_c_kidlist_t *list);

isc_result_t dns_c_kid_new(isc_mem_t *mem, const char *name,
			   dns_c_kid_t **keyid);

isc_result_t dns_c_kdeflist_new(isc_mem_t *mem, dns_c_kdeflist_t **list);

isc_result_t dns_c_kdeflist_delete(dns_c_kdeflist_t **list);

isc_result_t dns_c_kdeflist_copy(isc_mem_t *mem, dns_c_kdeflist_t **dest,
				 dns_c_kdeflist_t *src);

isc_result_t dns_c_kdeflist_append(dns_c_kdeflist_t *list, dns_c_kdef_t *key,
				   isc_boolean_t copy);

isc_result_t dns_c_kdeflist_undef(dns_c_kdeflist_t *list, const char *keyid); 

isc_result_t dns_c_kdeflist_find(dns_c_kdeflist_t *list, const char *keyid,
				 dns_c_kdef_t **retval);

void dns_c_kdeflist_print(FILE *fp, int indent, dns_c_kdeflist_t *list);

isc_result_t dns_c_kdef_new(isc_mem_t *mem, const char *name,
			    dns_c_kdef_t **keyid);

isc_result_t dns_c_kdef_delete(dns_c_kdef_t **keydef);

isc_result_t dns_c_kdef_copy(isc_mem_t *mem, dns_c_kdef_t **dest,
			     dns_c_kdef_t *src);

void dns_c_kdef_print(FILE *fp, int indent, dns_c_kdef_t *keydef);

isc_result_t dns_c_kdef_setalgorithm(dns_c_kdef_t *elem,
				     const char *algorithm);

isc_result_t dns_c_kdef_setsecret(dns_c_kdef_t *elem, const char *secret);

isc_result_t dns_c_tkeylist_new(isc_mem_t *mem, dns_c_tkeylist_t **newlist);

isc_result_t dns_c_tkeylist_delete(dns_c_tkeylist_t **list);

isc_result_t dns_c_tkeylist_copy(isc_mem_t *mem, dns_c_tkeylist_t **dest,
				 dns_c_tkeylist_t *src);

void dns_c_tkeylist_print(FILE *fp, int indent, dns_c_tkeylist_t *list);

isc_result_t dns_c_tkeylist_append(dns_c_tkeylist_t *list,
				   dns_c_tkey_t *element,
				   isc_boolean_t copy);

isc_result_t dns_c_tkey_new(isc_mem_t *mem, const char *domain,
			    isc_uint32_t flags,
			    isc_uint32_t protocol, isc_uint32_t algorithm,
			    const char *key, dns_c_tkey_t **newkey);

isc_result_t dns_c_tkey_delete(dns_c_tkey_t **tkey);

isc_result_t dns_c_tkey_copy(isc_mem_t *mem, dns_c_tkey_t **dest,
			     dns_c_tkey_t *src);

isc_result_t dns_c_tkey_getflags(dns_c_tkey_t *tkey, isc_uint32_t *flags);

isc_result_t dns_c_tkey_getprotocol(dns_c_tkey_t *tkey,
				    isc_uint32_t *protocol);

isc_result_t dns_c_tkey_getalgorithm(dns_c_tkey_t *tkey,
				     isc_uint32_t *algorithm);

isc_result_t dns_c_tkey_getkey(dns_c_tkey_t *tkey, const char **key);

void dns_c_tkey_print(FILE *fp, int indent, dns_c_tkey_t *tkey);

ISC_LANG_ENDDECLS

#endif /* DNS_CONFKEYS_H */
