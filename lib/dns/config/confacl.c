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

#include <config.h>

#include <isc/assertions.h>

#include <dns/confacl.h>
#include <dns/confcommon.h>


static isc_result_t expand_acls(dns_c_acltable_t *table,
				dns_c_ipmatchlist_t *list);
static isc_result_t acl_delete(dns_c_acl_t **aclptr);



isc_result_t
dns_c_acltable_new(isc_mem_t *mem, dns_c_acltable_t **newtable)
{
	dns_c_acltable_t *table;
	
	REQUIRE(mem != NULL);
	REQUIRE(newtable != NULL);

	table = isc_mem_get(mem, sizeof *table);
	if (table == NULL) {
		dns_c_error(0, "Out of memory");
		return (ISC_R_NOMEMORY);
	}

	table->mem = mem;

	ISC_LIST_INIT(table->acl_list);

	*newtable = table;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_acltable_delete(dns_c_acltable_t **table)
{
	dns_c_acltable_t *acltable;
	
	REQUIRE(table != NULL);

	acltable = *table;
	if (acltable == NULL) {
		return (ISC_R_SUCCESS);
	}

	dns_c_acltable_clear(acltable);

	isc_mem_put(acltable->mem, acltable, sizeof *acltable);

	return (ISC_R_SUCCESS);
}


void
dns_c_acltable_print(FILE *fp, int indent, dns_c_acltable_t *table)
{
	dns_c_acl_t *acl;
	dns_c_acl_t *acltmp;

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);

	if (table == NULL) {
		return;
	}
		
	acl = ISC_LIST_HEAD(table->acl_list);
	while (acl != NULL) {
		acltmp = ISC_LIST_NEXT(acl, next);
		
		if (!acl->is_special) {	/* don't print specials */
			dns_c_acl_print(fp, indent, acl);
			fprintf(fp, "\n");
		}

		acl = acltmp;
	}
}


isc_result_t
dns_c_acltable_clear(dns_c_acltable_t *table)
{
	dns_c_acl_t *elem;
	dns_c_acl_t *tmpelem;
	isc_result_t r;
	
	REQUIRE(table != NULL);
	
	elem = ISC_LIST_HEAD(table->acl_list);
	while (elem != NULL) {
		tmpelem = ISC_LIST_NEXT(elem, next);
		ISC_LIST_UNLINK(table->acl_list, elem, next);
		
		r = acl_delete(&elem);
		if (r != ISC_R_SUCCESS) {
			dns_c_error(r, "Failed to delete acl element.\n");
			return (r);
		}

		elem = tmpelem;
	}

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_acltable_getacl(dns_c_acltable_t *table,
			const char *aclname,
			dns_c_acl_t **retval)
{
	dns_c_acl_t *elem;

	REQUIRE(table != NULL);
	REQUIRE(retval != NULL);
	REQUIRE(aclname != NULL);
	REQUIRE(strlen(aclname) > 0);

	elem = ISC_LIST_HEAD(table->acl_list);
	while (elem != NULL) {
		if (strcmp(aclname, elem->name) == 0) {
			break;
		}

		elem = ISC_LIST_NEXT(elem, next);
	}
	
	if (elem != NULL) {
		*retval = elem;
	}

	return (elem == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_acltable_removeacl(dns_c_acltable_t *table, const char *aclname)
{
	dns_c_acl_t *acl;
	dns_c_acl_t *tmpacl;

	REQUIRE(table != NULL);
	REQUIRE(aclname != NULL);
	
	acl = ISC_LIST_HEAD(table->acl_list);
	while (acl != NULL) {
		tmpacl = ISC_LIST_NEXT(acl, next);
		if (strcmp(aclname, acl->name) == 0) {
			ISC_LIST_UNLINK(table->acl_list, acl, next);
			acl_delete(&acl);
			return (ISC_R_SUCCESS);
		}

		acl = tmpacl;
	}

	return (ISC_R_NOTFOUND);
}


isc_result_t
dns_c_acl_new(dns_c_acltable_t *table, const char *aclname,
	      isc_boolean_t isspecial, dns_c_acl_t **newacl)
{
	dns_c_acl_t *acl;
	
	REQUIRE(table != NULL);
	REQUIRE(aclname != NULL);
	REQUIRE(strlen(aclname) > 0);
	REQUIRE(newacl != NULL);

	acl = isc_mem_get(table->mem, sizeof *acl);
	if (acl == NULL) {
		return (ISC_R_NOMEMORY);
	}

	acl->mytable = table;
	acl->name = NULL;
	acl->ipml = NULL;
	acl->is_special = isspecial;

	acl->name = isc_mem_strdup(table->mem, aclname);
	if (acl->name == NULL) {
		isc_mem_put(table->mem, acl, sizeof *acl);
		dns_c_error(0, "Not enough memory");
		return (ISC_R_NOMEMORY);
	}

	ISC_LIST_APPEND(table->acl_list, acl, next);
	
	*newacl = acl;

	return (ISC_R_SUCCESS);
}


void
dns_c_acl_print(FILE *fp, int indent, dns_c_acl_t *acl)
{
	dns_c_printtabs(fp, indent);
	fprintf(fp, "acl ");
	if (acl->name == NULL) {
		fprintf(fp, "anon-acl-%p ", acl);
	} else {
		fprintf(fp, "%s ", acl->name);
	}

	if (acl->ipml != NULL) {
		dns_c_ipmatchlist_print(fp, indent + 1, acl->ipml);
	} else {
		fprintf(fp, "{\n");
		dns_c_printtabs(fp, indent);
		fprintf(fp, "};");
	}
}


isc_result_t
dns_c_acl_setipml(dns_c_acl_t *acl, dns_c_ipmatchlist_t *ipml,
		   isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(acl != NULL);
	REQUIRE(ipml != NULL);

	if (acl->ipml != NULL) {
		dns_c_ipmatchlist_delete(&acl->ipml);
	}

	if (deepcopy) {
		res = dns_c_ipmatchlist_copy(acl->mytable->mem,
					      &acl->ipml, ipml);
	} else {
		acl->ipml = ipml;
		res = ISC_R_SUCCESS;
	}

	return (res);
}


isc_result_t
dns_c_acl_getipmlexpanded(isc_mem_t *mem, dns_c_acl_t *acl,
			    dns_c_ipmatchlist_t **retval)
{
	dns_c_ipmatchlist_t *newlist;
	isc_result_t r;

	if (acl->ipml == NULL) {
		newlist = NULL;
		r = ISC_R_SUCCESS;
	} else {
		r = dns_c_ipmatchlist_copy(mem, &newlist, acl->ipml);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}

		r = expand_acls(acl->mytable, newlist);
	}

	*retval = newlist;
	
	return (r);
}


static isc_result_t
expand_acls(dns_c_acltable_t *table, dns_c_ipmatchlist_t *list)
{
	dns_c_ipmatchelement_t *elem;
	dns_c_ipmatchelement_t *tmpelem;
	dns_c_acl_t *acl;
	isc_result_t r;
	isc_boolean_t isneg;
	
	if (list == NULL) {
		return (ISC_R_SUCCESS);
	}

	elem = ISC_LIST_HEAD(list->elements);
	while (elem != NULL) {
		switch (elem->type) {
		case dns_c_ipmatch_indirect:
			expand_acls(table, elem->u.indirect.list);
			break;

		case dns_c_ipmatch_acl:
			r = dns_c_acltable_getacl(table,
						    elem->u.aclname, &acl);
			if (r != ISC_R_SUCCESS) {
				return (ISC_R_FAILURE);
			}

			if (acl->ipml != NULL) {
				isneg = dns_c_ipmatchelement_isneg(elem);
				dns_c_ipmatchlist_append(list,
							  acl->ipml, isneg);
			}

		default:
			; /* Do nothing */
		}
			
		tmpelem = ISC_LIST_NEXT(elem, next);

		if (elem->type == dns_c_ipmatch_acl) {
			ISC_LIST_UNLINK(list->elements, elem, next);
		}

		elem = tmpelem;
	}


	return (ISC_R_SUCCESS);
}




static isc_result_t
acl_delete(dns_c_acl_t **aclptr)
{
	dns_c_acl_t *acl;
	isc_result_t res;

	acl = *aclptr;
	if (acl == NULL) {
		return (ISC_R_SUCCESS);
	}

	isc_mem_free(acl->mytable->mem, acl->name);
	res = dns_c_ipmatchlist_delete(&acl->ipml);
	isc_mem_put(acl->mytable->mem, acl, sizeof *acl);
	
	return (res);
}


