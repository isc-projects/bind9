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

/* $Id: confacl.c,v 1.17 2000/05/08 19:23:24 tale Exp $ */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/log.h>
#include <dns/confacl.h>

static isc_result_t
acl_delete(dns_c_acl_t **aclptr);

isc_result_t
dns_c_acltable_new(isc_mem_t *mem, dns_c_acltable_t **newtable) {
	dns_c_acltable_t *table;
	
	REQUIRE(mem != NULL);
	REQUIRE(newtable != NULL);

	table = isc_mem_get(mem, sizeof *table);
	if (table == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Out of memory");
		return (ISC_R_NOMEMORY);
	}

	table->mem = mem;
	table->magic = DNS_C_CONFACLTABLE_MAGIC;

	ISC_LIST_INIT(table->acl_list);

	*newtable = table;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_acltable_delete(dns_c_acltable_t **table) {
	dns_c_acltable_t *acltable;
	isc_mem_t *mem;

	REQUIRE(table != NULL);
	REQUIRE(*table != NULL);
	
	acltable = *table;

	REQUIRE(DNS_C_CONFACLTABLE_VALID(acltable));

	dns_c_acltable_clear(acltable);

	mem = acltable->mem;
	
	acltable->magic = 0;
	acltable->mem = NULL;
	
	
	isc_mem_put(mem, acltable, sizeof *acltable);

	return (ISC_R_SUCCESS);
}

void
dns_c_acltable_print(FILE *fp, int indent, dns_c_acltable_t *table) {
	dns_c_acl_t *acl;
	dns_c_acl_t *acltmp;

	REQUIRE(fp != NULL);
	REQUIRE(indent >= 0);

	if (table == NULL) {
		return;
	}
		
	REQUIRE(DNS_C_CONFACLTABLE_VALID(table));
			
	acl = ISC_LIST_HEAD(table->acl_list);
	while (acl != NULL) {
		acltmp = ISC_LIST_NEXT(acl, next);
		
		if (!acl->is_special) { /* don't print specials */
			dns_c_acl_print(fp, indent, acl);
			fprintf(fp, "\n");
		}

		acl = acltmp;
	}
}

isc_result_t
dns_c_acltable_clear(dns_c_acltable_t *table) {
	dns_c_acl_t *elem;
	dns_c_acl_t *tmpelem;
	isc_result_t r;
	
	REQUIRE(DNS_C_CONFACLTABLE_VALID(table));
			
	elem = ISC_LIST_HEAD(table->acl_list);
	while (elem != NULL) {
		tmpelem = ISC_LIST_NEXT(elem, next);
		ISC_LIST_UNLINK(table->acl_list, elem, next);
		
		r = acl_delete(&elem);
		if (r != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG,
				      ISC_LOG_CRITICAL,
				      "Failed to delete acl element.");
			return (r);
		}

		elem = tmpelem;
	}

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_acltable_getacl(dns_c_acltable_t *table,
		      const char *aclname, dns_c_acl_t **retval)
{
	dns_c_acl_t *elem;

	REQUIRE(DNS_C_CONFACLTABLE_VALID(table));
	REQUIRE(retval != NULL);
	REQUIRE(aclname != NULL);
	REQUIRE(*aclname != '\0');

	elem = ISC_LIST_HEAD(table->acl_list);
	while (elem != NULL) {
		if (strcmp(aclname, elem->name) == 0) {
			break;
		}

		elem = ISC_LIST_NEXT(elem, next);
	}
	
	if (elem != NULL) {
		REQUIRE(DNS_C_CONFACL_VALID(elem));
		*retval = elem;
	}

	return (elem == NULL ? ISC_R_NOTFOUND : ISC_R_SUCCESS);
}


isc_result_t
dns_c_acltable_removeacl(dns_c_acltable_t *table, const char *aclname) {
	dns_c_acl_t *acl;
	dns_c_acl_t *tmpacl;

	REQUIRE(DNS_C_CONFACLTABLE_VALID(table));
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
	
	REQUIRE(DNS_C_CONFACLTABLE_VALID(table));
	REQUIRE(aclname != NULL);
	REQUIRE(*aclname != '\0');
	REQUIRE(newacl != NULL);

	acl = isc_mem_get(table->mem, sizeof *acl);
	if (acl == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Not enough memory");
		return (ISC_R_NOMEMORY);
	}

	acl->mytable = table;
	acl->magic = DNS_C_CONFACL_MAGIC;
	acl->name = NULL;
	acl->ipml = NULL;
	acl->is_special = isspecial;

	acl->name = isc_mem_strdup(table->mem, aclname);
	if (acl->name == NULL) {
		isc_mem_put(table->mem, acl, sizeof *acl);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "Not enough memory");
		return (ISC_R_NOMEMORY);
	}

	ISC_LIST_APPEND(table->acl_list, acl, next);
	
	*newacl = acl;

	return (ISC_R_SUCCESS);
}


void
dns_c_acl_print(FILE *fp, int indent, dns_c_acl_t *acl) {
	REQUIRE(DNS_C_CONFACL_VALID(acl));
	
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
		fprintf(fp, "}");
	}
	fprintf(fp, ";\n");
}


isc_result_t
dns_c_acl_setipml(dns_c_acl_t *acl,
		  dns_c_ipmatchlist_t *ipml, isc_boolean_t deepcopy)
{
	isc_result_t res;
	
	REQUIRE(DNS_C_CONFACL_VALID(acl));
	REQUIRE(ipml != NULL);

	if (acl->ipml != NULL) {
		dns_c_ipmatchlist_detach(&acl->ipml);
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

	REQUIRE(DNS_C_CONFACL_VALID(acl));
	
	if (acl->ipml == NULL) {
		newlist = NULL;
		r = ISC_R_SUCCESS;
	} else {
		r = dns_c_ipmatchlist_copy(mem, &newlist, acl->ipml);
		if (r != ISC_R_SUCCESS) {
			return (r);
		}

		r = dns_c_acl_expandacls(acl->mytable, newlist);
	}

	*retval = newlist;
	
	return (r);
}



/* XXX this should really be a function in the confip module */

isc_result_t
dns_c_acl_expandacls(dns_c_acltable_t *table, dns_c_ipmatchlist_t *list) {
	dns_c_ipmatchelement_t *elem;
	dns_c_ipmatchelement_t *tmpelem;
	dns_c_acl_t *acl;
	isc_result_t r;
	isc_boolean_t isneg;

	REQUIRE(DNS_C_CONFACLTABLE_VALID(table));
	
	if (list == NULL) {
		return (ISC_R_SUCCESS);
	}

	elem = ISC_LIST_HEAD(list->elements);
	while (elem != NULL) {
		switch (elem->type) {
		case dns_c_ipmatch_indirect:
			dns_c_acl_expandacls(table,
					     elem->u.indirect.list);
			break;

		case dns_c_ipmatch_acl:
			r = dns_c_acltable_getacl(table,
						  elem->u.aclname, &acl);
			if (r != ISC_R_SUCCESS) {
				return (ISC_R_FAILURE);
			}

			if (acl->ipml != NULL) {
				isneg = dns_c_ipmatchelement_isneg(elem);

				/* XXX I this should be inserted in place and 
				 *   not appended
				 */
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
acl_delete(dns_c_acl_t **aclptr) {
	dns_c_acl_t *acl;
	isc_result_t res;
	isc_mem_t *mem;

	REQUIRE(aclptr != NULL);
	REQUIRE(*aclptr != NULL);
	
	acl = *aclptr;

	REQUIRE(DNS_C_CONFACL_VALID(acl));

	mem = acl->mytable->mem;

	acl->mytable = NULL;
	
	isc_mem_free(mem, acl->name);

	if (acl->ipml != NULL)
		res = dns_c_ipmatchlist_detach(&acl->ipml);
	else
		res = ISC_R_SUCCESS;
	
	acl->magic = 0;
	
	isc_mem_put(mem, acl, sizeof *acl);
	
	return (res);
}


