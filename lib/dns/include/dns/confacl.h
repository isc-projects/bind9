/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
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

/* $Id: confacl.h,v 1.14.4.1 2001/01/09 22:45:10 bwelling Exp $ */

#ifndef DNS_CONFACL_H
#define DNS_CONFACL_H 1

/*****
 ***** Module Info
 *****/

/*
 * ADT for ACLs as used by the config file module. An ACL is a name and a
 * list of ipmatch lists or references to other acls. ACLS are created in
 * ACL tables, and ACLs that reference other ACLs must be created in the
 * same table.
 */


/*
 * MP:
 *	Caller must do necessary locking.
 *
 * Reliability:
 *
 *	No known problems.
 *
 * Resources:
 *
 *	Uses memory managers supplied by caller.
 *
 * Security:
 *
 *	N/A.
 *
 * Standards:
 *
 *	N/A.
 *
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/magic.h>

#include <dns/confip.h>


#define DNS_C_CONFACL_MAGIC	0x4361636cU
#define DNS_C_CONFACLTABLE_MAGIC 0x32616354U

#define DNS_C_CONFACL_VALID(confacl) \
	ISC_MAGIC_VALID(confacl, DNS_C_CONFACL_MAGIC)
#define DNS_C_CONFACLTABLE_VALID(confacltable) \
	ISC_MAGIC_VALID(confacltable, DNS_C_CONFACLTABLE_MAGIC)


/***
 *** Types
 ***/

typedef struct dns_c_acl		dns_c_acl_t;
typedef struct dns_c_acl_table		dns_c_acltable_t;

struct dns_c_acl {
	isc_uint32_t		magic;

	dns_c_acltable_t       *mytable;

	char		       *name;
	dns_c_ipmatchlist_t    *ipml;
	isc_boolean_t		is_special;

	ISC_LINK(dns_c_acl_t)	next;
};

struct dns_c_acl_table {
	isc_uint32_t		magic;

	isc_mem_t	       *mem;

	ISC_LIST(dns_c_acl_t)	acl_list;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_c_acltable_new(isc_mem_t *mem, dns_c_acltable_t **newtable);
/*
 * Creates a new ACL table. Returns pointer to the new table through
 * NEWTABLE paramater. The memory is allocated from the MEM memory pool.
 *
 * Requires:
 *	mem is a valid memory pool
 *	newtable is a valid non-NULL pointer.
 *	mem remain a valuid memory pool until the table is destroyed.
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well.
 *	ISC_R_NOMEMORY		-- not enough memory.
 *
 */


isc_result_t
dns_c_acltable_delete(dns_c_acltable_t **table);
/*
 * Destroys the table pointed to by *TABLE and all the ACLs in it. The
 * value of *TABLE can be NULL.
 *
 * Requires:
 *	table is a valid pointer.
 *	The memory pool used at creation time still be valid.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *
 */


isc_result_t
dns_c_acltable_getacl(dns_c_acltable_t *table, const char *aclname,
		      dns_c_acl_t **retval);
/*
 * Looks up an ACL by name in the given table. The result is returned
 * through the parameter RETVAL. The returned ACL must not be modified.
 *
 * Requires:
 *	TABLE be a value ACL table.
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOTFOUND		-- acl was not found
 *
 */

isc_result_t
dns_c_acltable_removeacl(dns_c_acltable_t *table, const char *aclname);
/*
 * Removes an acl from a table. The acl is looked up by name.
 *
 * Requires:
 *	table be a valid pointer to an acl table
 *	aclname be a valid pointer to string of positive length.
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOTFOUND		-- acl was not in the table.
 *
 */

void
dns_c_acltable_print(FILE *fp, int indent, dns_c_acltable_t *table);
/*
 * Prints the ACL table and the ACLs in it to the give stdio stream.
 * indent is the indentation level (number of tabs) printed before
 * each line of the table
 *
 * Requires:
 *	fp be a valid stdio stream
 *	indent be a non-negative number
 *	table be a valid acl table.
 *
 */

isc_result_t
dns_c_acltable_clear(dns_c_acltable_t *table);
/*
 * Deletes all the acls from the table.
 *
 * Requires:
 *	table must point to a valid ACL table.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *
 */

isc_result_t
dns_c_acl_new(dns_c_acltable_t *table, const char *aclname,
	      isc_boolean_t isspecial, dns_c_acl_t **newacl);
/*
 * Creates a new ACL. The acl is placed in the given table. If isspecial is
 * true then the acl is not printed by dns_c_acl_print. The new acl is
 * returned via the newacl parameter
 *
 * Requires:
 *	table be a pointer to a valid acl table.
 *	aclname be a pointer to a valid string of positive length
 *	newacl be a valid non-NULL pointer.
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- out of memory
 *
 */


void
dns_c_acl_print(FILE *fp, int indent, dns_c_acl_t *acl);
/*
 * Prints out the acl to the stdio stream. The outupt is indented by INDENT
 * tabs.
 *
 * Requires:
 *	fp be a pointer to a valid stdio stream
 *	indent be non-negative,
 *	acl be a pointer to a valid acl.
 *
 */

isc_result_t
dns_c_acl_setipml(dns_c_acl_t *acl, dns_c_ipmatchlist_t *ipml,
		  isc_boolean_t deepcopy);
/*
 * Sets the ipmatch list of the ACL to the IPML. If DEEPCOPY is true, then
 * a full copy of IPML is made using the MEM memory pool. In which case the
 * caller still is the owner the memory IPML points to. If DEEPCOPY is
 * false, then the acl takes ownership of the memory IPML points to. If the
 * acl already has an ipmatch list, then it is deleted before the new one
 * is added.
 *
 * Requires:
 *	mem be a pointer to a valid memory manager
 *	ipml be a valid dns_c_ipmatchlist_t
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- memory could not be allocated for the
 *				   deepcopy  .
 *
 */

isc_result_t
dns_c_acl_getipmlexpanded(isc_mem_t *mem, dns_c_acl_t *acl,
			  dns_c_ipmatchlist_t **retval);
/*
 * Retuns a copy through the RETVAL parameter (the caller is responsible
 * for deleting the returned value) of the given ACLs ipmatch list. Any
 * references in the acl list are recursivly expanded so that the end
 * result has no references in it. Memory allocation for the copy is done
 * via the memory pool pointed to by the MEM paramater.
 *
 * Requires:
 *	mem be a pointer to a valid memory manager
 *	acl be a pointer to a valid acl.
 *	retval be a valid non-NULL pointer.
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_NOMEMORY		-- not enough memory to make copy.
 *	ISC_R_FAILURE		-- an acl reference couldn't be expanded.
 *
 */

isc_result_t
dns_c_acl_expandacls(dns_c_acltable_t *table, dns_c_ipmatchlist_t *list);
/*
 * Goes through all the entires (direct and indirect) of LIST and
 * expands all references to ACLs using the definitions in TABLE
 *
 * Requires:
 *	table be a pointer to a valid dns_c_acltable_t
 *	list be a pointer to a valid (but possibly empty dns_c_ipmatchlist_t
 *
 * Returns:
 *	ISC_R_SUCCESS		-- all is well
 *	ISC_R_FAILURE		-- some acl(s) couldn't be resolved.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_CONFACL_H */
