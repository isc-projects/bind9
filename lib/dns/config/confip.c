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

/* $Id: confip.c,v 1.24 2000/05/08 14:35:27 tale Exp $ */

#include <config.h>


#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/confip.h>
#include <dns/log.h>

/*
 * Flag for dns_c_ipmatch_element.
 */
#define DNS_C_IPMATCH_NEGATE	0x01	/* match means deny access */


static isc_result_t checkmask(isc_sockaddr_t *address, isc_uint32_t bits);
static isc_result_t bits2v6mask(struct in6_addr *addr, isc_uint32_t bits);

isc_result_t
dns_c_ipmatchelement_new(isc_mem_t *mem, dns_c_ipmatchelement_t **result) {
	dns_c_ipmatchelement_t *ime ;

	REQUIRE(result != NULL);

	*result = NULL;

	ime = isc_mem_get(mem, sizeof *ime);
	if (ime == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ime->magic = DNS_C_IPMELEM_MAGIC;
	ime->type = dns_c_ipmatch_none;
	ime->flags = 0;
	memset(&ime->u, 0x0, sizeof ime->u);

	ISC_LINK_INIT(ime, next);

	*result = ime;

	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_c_ipmatchelement_isneg(dns_c_ipmatchelement_t *elem) {

	REQUIRE(DNS_C_IPMELEM_VALID(elem));
	
	return (ISC_TF((elem->flags & DNS_C_IPMATCH_NEGATE) ==
			DNS_C_IPMATCH_NEGATE));
}

isc_result_t
dns_c_ipmatchelement_delete(isc_mem_t *mem, dns_c_ipmatchelement_t **ipme) {
	dns_c_ipmatchelement_t *elem;
	
	REQUIRE(mem != NULL);
	REQUIRE(ipme != NULL);
	REQUIRE(*ipme != NULL);
	
	elem = *ipme;

	REQUIRE(DNS_C_IPMELEM_VALID(elem));
	
	switch (elem->type) {
	case dns_c_ipmatch_localhost:
	case dns_c_ipmatch_localnets:
	case dns_c_ipmatch_pattern:
		/* nothing */
		break;

	case dns_c_ipmatch_indirect:
		INSIST(elem->u.indirect.list != NULL);

		if (elem->u.indirect.list != NULL)
			dns_c_ipmatchlist_detach(&elem->u.indirect.list);

		if (elem->u.indirect.refname.base != NULL) {
			isc_mem_put(mem, elem->u.indirect.refname.base,
				    elem->u.indirect.refname.length);
		}
		break;

	case dns_c_ipmatch_key:
		isc_mem_free(mem, elem->u.key);
		break;

	case dns_c_ipmatch_acl:
		isc_mem_free(mem, elem->u.aclname);
		break;

	case dns_c_ipmatch_any:
		/* nothing */
		break;

	case dns_c_ipmatch_none:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "dns_ipmath_none element type");
		return (ISC_R_FAILURE);
	}

	elem->magic = 0;
	isc_mem_put(mem, elem, sizeof *elem);

	*ipme = NULL;
	
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatchelement_copy(isc_mem_t *mem,
			  dns_c_ipmatchelement_t **dest,
			  dns_c_ipmatchelement_t *src)
{
	isc_result_t result;
	dns_c_ipmatchelement_t *newel;

	REQUIRE(mem != NULL);
	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_IPMELEM_VALID(src));
		
	result = dns_c_ipmatchelement_new(mem, &newel);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	newel->type = src->type;
	newel->flags = src->flags;
	
	switch(src->type) {
	case dns_c_ipmatch_pattern:
		newel->u.direct.address = src->u.direct.address;
		newel->u.direct.mask = src->u.direct.mask;
		break;

	case dns_c_ipmatch_indirect:
		result = dns_c_ipmatchlist_copy(mem,
						&newel->u.indirect.list,
						src->u.indirect.list);
		break;	

	case dns_c_ipmatch_localhost:
		break;

	case dns_c_ipmatch_localnets:
		break;

	case dns_c_ipmatch_key:
		newel->u.key = isc_mem_strdup(mem, src->u.key);
		break;

	case dns_c_ipmatch_acl:
		newel->u.aclname = isc_mem_strdup(mem, src->u.aclname);
		break;
		
	case dns_c_ipmatch_any:
		break;

	case dns_c_ipmatch_none:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "ipmatch 'none' element type");
		return (ISC_R_FAILURE);
	}

	*dest = newel;
	
	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_c_ipmatchelement_equal(dns_c_ipmatchelement_t *e1,
			   dns_c_ipmatchelement_t *e2)
{
	REQUIRE(DNS_C_IPMELEM_VALID(e1));
	REQUIRE(DNS_C_IPMELEM_VALID(e2));

	if ((e1->type != e2->type) || (e1->flags != e2->flags))
		return (ISC_FALSE);

	switch (e1->type) {
	case dns_c_ipmatch_pattern:
		if (e1->u.direct.mask != e2->u.direct.mask)
			return (ISC_FALSE);
		return (isc_sockaddr_equal(&e1->u.direct.address,
					   &e2->u.direct.address));

	case dns_c_ipmatch_indirect:
		return (dns_c_ipmatchlist_equal(e1->u.indirect.list,
						e2->u.indirect.list));

	case dns_c_ipmatch_localhost:
		break;

	case dns_c_ipmatch_localnets:
		break;

	case dns_c_ipmatch_key:
		return (ISC_TF(strcmp(e1->u.key, e2->u.key) == 0));

	case dns_c_ipmatch_acl:
		return (ISC_TF(strcmp(e1->u.aclname, e2->u.aclname) == 0));

	case dns_c_ipmatch_any:
		break;

	case dns_c_ipmatch_none:
		break;
	}
	return (ISC_TRUE);
}

isc_result_t
dns_c_ipmatchlocalhost_new(isc_mem_t *mem, dns_c_ipmatchelement_t **result) {
	dns_c_ipmatchelement_t *ime = NULL;
	isc_result_t res;

	REQUIRE(mem != NULL);
	REQUIRE(result != NULL);

	*result = NULL;

	res = dns_c_ipmatchelement_new(mem, &ime);
	if (res == ISC_R_SUCCESS) {
		ime->type = dns_c_ipmatch_localhost;
	}

	*result = ime;

	return (res);
}

isc_result_t
dns_c_ipmatchlocalnets_new(isc_mem_t *mem, dns_c_ipmatchelement_t **result) {
	dns_c_ipmatchelement_t *ime = NULL;
	isc_result_t res;

	REQUIRE(mem != NULL);
	REQUIRE(result != NULL);

	*result = NULL;

	res = dns_c_ipmatchelement_new(mem, &ime);
	if (res == ISC_R_SUCCESS) {
		ime->type = dns_c_ipmatch_localnets;
	}

	*result = ime;

	return (res);
}

isc_result_t
dns_c_ipmatchany_new(isc_mem_t *mem, dns_c_ipmatchelement_t **result) {
	dns_c_ipmatchelement_t *ime = NULL;
	isc_result_t res;

	REQUIRE(mem != NULL);
	REQUIRE(result != NULL);

	*result = NULL;

	res = dns_c_ipmatchelement_new(mem, &ime);
	if (res == ISC_R_SUCCESS) {
		ime->type = dns_c_ipmatch_any;
	}

	*result = ime;

	return (res);
}

isc_result_t
dns_c_ipmatchindirect_new(isc_mem_t *mem,
			  dns_c_ipmatchelement_t **result,
			  dns_c_ipmatchlist_t *iml,
			  const char *name)
{
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchlist_t *iml_copy;
	isc_result_t res;

	REQUIRE(mem != NULL);
	REQUIRE(result != NULL);
	REQUIRE(DNS_C_IPMLIST_VALID(iml));

	*result = NULL;

	res = dns_c_ipmatchlist_copy(mem, &iml_copy, iml);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_ipmatchelement_new(mem, &ime);
	if (res == ISC_R_SUCCESS) {
		ime->type = dns_c_ipmatch_indirect;
		ime->u.indirect.list = iml_copy;
		if (name != NULL) {
			ime->u.indirect.refname.length = strlen(name) + 1;
			ime->u.indirect.refname.base =
				isc_mem_get(mem,
					    ime->u.indirect.refname.length);
			RUNTIME_CHECK(ime->u.indirect.refname.base != NULL);
			strcpy(ime->u.indirect.refname.base, name);
		}
	} else {
		dns_c_ipmatchlist_detach(&iml_copy);
	}
	
	*result = ime;

	return (res);
}

isc_result_t
dns_c_ipmatchpattern_new(isc_mem_t *mem,
			 dns_c_ipmatchelement_t **result,
			 isc_sockaddr_t address,
			 isc_uint32_t maskbits)
{
	dns_c_ipmatchelement_t *ime ;
	isc_result_t res;

	REQUIRE(result != NULL);
	REQUIRE(mem != NULL);

	*result = NULL;

	res = checkmask(&address, maskbits);

	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	res = dns_c_ipmatchelement_new(mem, &ime);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	ime->type = dns_c_ipmatch_pattern;
	ime->u.direct.address = address;
	ime->u.direct.mask = maskbits;

	*result = ime;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatchkey_new(isc_mem_t *mem,
		     dns_c_ipmatchelement_t **result,
		     const char *key)
{
	dns_c_ipmatchelement_t *ipme;
	isc_result_t res;

	REQUIRE(result != NULL);
	REQUIRE(mem != NULL);
	REQUIRE(key != NULL);

	*result = NULL;

	res = dns_c_ipmatchelement_new(mem, &ipme);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	ipme->type = dns_c_ipmatch_key;
	ipme->u.key = isc_mem_strdup(mem, key);

	*result = ipme;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatch_aclnew(isc_mem_t *mem,
		     dns_c_ipmatchelement_t **result,
		     const char *aclname)
{
	dns_c_ipmatchelement_t *ipme;
	isc_result_t res;

	REQUIRE(result != NULL);
	REQUIRE(mem != NULL);
	REQUIRE(aclname != NULL);
	REQUIRE(*aclname != '\0');

	*result = NULL;

	res = dns_c_ipmatchelement_new(mem, &ipme);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	ipme->type = dns_c_ipmatch_acl;
	ipme->u.aclname = isc_mem_strdup(mem, aclname);

	*result = ipme;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatch_negate(dns_c_ipmatchelement_t *ipe) {
	REQUIRE(DNS_C_IPMELEM_VALID(ipe));

	if ((ipe->flags & DNS_C_IPMATCH_NEGATE) == DNS_C_IPMATCH_NEGATE) {
		ipe->flags &= ~DNS_C_IPMATCH_NEGATE;
	} else {
		ipe->flags |= DNS_C_IPMATCH_NEGATE;
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatchlist_new(isc_mem_t *mem, dns_c_ipmatchlist_t **ptr) {
	dns_c_ipmatchlist_t *newlist;

	REQUIRE(ptr != NULL);
	REQUIRE(mem != NULL);

	newlist = isc_mem_get(mem, sizeof *newlist);
	if (newlist == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newlist->magic = DNS_C_IPMLIST_MAGIC;
	newlist->mem = mem;
	newlist->refcount = 1;
	
	ISC_LIST_INIT(newlist->elements);

	*ptr = newlist;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatchlist_detach(dns_c_ipmatchlist_t **ml) {
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchelement_t *iptr;
	dns_c_ipmatchlist_t *iml;
	isc_mem_t *mem;

	REQUIRE(ml != NULL);
	REQUIRE(*ml != NULL);
	
	iml = *ml;
	*ml = NULL;

	REQUIRE(DNS_C_IPMLIST_VALID(iml));
	INSIST(iml->refcount > 0);

	iml->refcount--;
	if (iml->refcount > 0) {
		return (ISC_R_SUCCESS);
	}
	
	mem = iml->mem;
	INSIST(mem != NULL);

	ime = ISC_LIST_HEAD(iml->elements);
	while (ime != NULL) {
		iptr = ISC_LIST_NEXT(ime, next);
		dns_c_ipmatchelement_delete(mem, &ime);
		
		ime = iptr;
	}

	isc_mem_put(mem, iml, sizeof *iml);

	return (ISC_R_SUCCESS);
}

void
dns_c_ipmatchlist_attach(dns_c_ipmatchlist_t *source,
			 dns_c_ipmatchlist_t **target)
{

	REQUIRE(DNS_C_IPMLIST_VALID(source));
	
	INSIST(source->refcount > 0);

	source->refcount++;
	*target = source;
}

isc_result_t
dns_c_ipmatchlist_empty(dns_c_ipmatchlist_t *ipml) {
	dns_c_ipmatchelement_t *ime ;
	dns_c_ipmatchelement_t *imptmp;
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(DNS_C_IPMLIST_VALID(ipml));
	
	ime = ISC_LIST_HEAD(ipml->elements);
	while (ime != NULL) {
		imptmp = ISC_LIST_NEXT(ime, next);
		res = dns_c_ipmatchelement_delete(ipml->mem, &ime);
		if (res != ISC_R_SUCCESS) {
			break;
		}
		ime = imptmp;
	}
	
	return (res);
}

isc_result_t
dns_c_ipmatchlist_copy(isc_mem_t *mem,
		       dns_c_ipmatchlist_t **dest, dns_c_ipmatchlist_t *src)
{
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchelement_t *ptr;
	dns_c_ipmatchlist_t *newlist;
	isc_result_t result;

	REQUIRE(mem != NULL);
	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_IPMLIST_VALID(src));

	*dest = NULL;

	result = dns_c_ipmatchlist_new(mem, &newlist);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	ime = ISC_LIST_HEAD(src->elements);
	while (ime != NULL) {
		result = dns_c_ipmatchelement_copy(mem, &ptr, ime);
		if (result != ISC_R_SUCCESS) {
			dns_c_ipmatchlist_detach(&newlist);
			return (result);
		}
		
		ISC_LIST_APPEND(newlist->elements, ptr, next);

		ime = ISC_LIST_NEXT(ime, next);
	}

	*dest = newlist;

	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_c_ipmatchlist_equal(dns_c_ipmatchlist_t *l1, dns_c_ipmatchlist_t *l2) {
	dns_c_ipmatchelement_t *e1, *e2;

	REQUIRE(l1 == NULL || DNS_C_IPMLIST_VALID(l1));
	REQUIRE(l2 == NULL || DNS_C_IPMLIST_VALID(l2));
	
	if (l1 == NULL && l2 == NULL)
		return (ISC_TRUE);
	if (l1 != NULL || l2 != NULL)
		return (ISC_FALSE);

	e1 = ISC_LIST_HEAD(l1->elements);
	e2 = ISC_LIST_HEAD(l2->elements);
	while (e1 != NULL && e2 != NULL) {
		if (!dns_c_ipmatchelement_equal(e1, e2))
			return (ISC_FALSE);
		e1 = ISC_LIST_NEXT(e1, next);
		e2 = ISC_LIST_NEXT(e2, next);
	}

	if (l1 != NULL || l2 != NULL)
		return (ISC_FALSE);
	return (ISC_TRUE);
}

isc_result_t
dns_c_ipmatchlist_append(dns_c_ipmatchlist_t *dest,
			 dns_c_ipmatchlist_t *src,
			 isc_boolean_t negate)
{
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchelement_t *ime_copy;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(DNS_C_IPMLIST_VALID(dest));
	REQUIRE(DNS_C_IPMLIST_VALID(src));

	ime = ISC_LIST_HEAD(src->elements);
	while (ime != NULL) {
		result = dns_c_ipmatchelement_copy(dest->mem,
						   &ime_copy,
						   ime);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		if (negate) {
			dns_c_ipmatch_negate(ime_copy);
		}
		
		ISC_LIST_APPEND(dest->elements, ime_copy, next);

		ime = ISC_LIST_NEXT(ime, next);
	}

	return (result);
}

isc_result_t
dns_c_ipmatchelement_print(FILE *fp, int indent, dns_c_ipmatchelement_t *ipme)
{
	int bits;

	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_IPMELEM_VALID(ipme));

	if (dns_c_ipmatchelement_isneg(ipme) &&
	    ipme->type != dns_c_ipmatch_any) {
		/* a '!any' element gets printed as 'none' */
		fputc('!', fp);
	} else {
		fputc(' ', fp);
	}

	switch (ipme->type) {
	case dns_c_ipmatch_pattern:
		dns_c_print_ipaddr(fp, &ipme->u.direct.address);
		
		bits = ipme->u.direct.mask;
		if (bits > 0) {
			isc_uint32_t fam =
				ipme->u.direct.address.type.sa.sa_family;
			if ((fam == AF_INET && bits < 32) ||
			    (fam == AF_INET6 && bits < 128)) {
				fprintf(fp, "/%d", bits);
			}
		}
		break;

	case dns_c_ipmatch_indirect:
		if (ipme->u.indirect.refname.base != NULL) {
			fprintf(fp, "%s", ipme->u.indirect.refname.base);
		} else {
			dns_c_ipmatchlist_print(fp, indent,
						ipme->u.indirect.list);
		}
		break;

	case dns_c_ipmatch_key:
		fprintf(fp, "key %s", ipme->u.key);
		break;

	case dns_c_ipmatch_localhost:
		fprintf(fp, "localhost");
		break;

	case dns_c_ipmatch_localnets:
		fprintf(fp, "localnets");
		break;

	case dns_c_ipmatch_any:
		if (dns_c_ipmatchelement_isneg(ipme)) {
			fprintf(fp, "none");
		} else {
			fprintf(fp, "any");
		}
		break;

	case dns_c_ipmatch_none:
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "dns_ipmatch_none element type");
		return (ISC_R_FAILURE);

	case dns_c_ipmatch_acl:
		fprintf(fp, "%s", ipme->u.aclname);
		break;
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ipmatchlist_print(FILE *fp, int indent, dns_c_ipmatchlist_t *ml) {
	dns_c_ipmatchelement_t *ipme ;

	REQUIRE(DNS_C_IPMLIST_VALID(ml));
	REQUIRE(fp != NULL);

	/* no indent on first line. */
	fprintf(fp, "{\n");
	ipme = ISC_LIST_HEAD(ml->elements);
	if (ipme == NULL) {
		dns_c_printtabs(fp, indent);
		fprintf(fp,
			"/* this list intentionally left blank */\n");
	} else {
		while (ipme != NULL) {
			dns_c_printtabs(fp, indent);
			dns_c_ipmatchelement_print(fp, indent + 1, ipme);
			fprintf(fp, ";\n");
			
			ipme = ISC_LIST_NEXT(ipme, next);
		}
	}
	
	dns_c_printtabs(fp, indent - 1);
	fprintf(fp, "}");

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_iplist_new(isc_mem_t *mem, int length, dns_c_iplist_t **newlist) {
	dns_c_iplist_t *list;
	size_t bytes;

	REQUIRE(mem != NULL);
	REQUIRE(length > 0);
	REQUIRE(newlist != NULL);

	list = isc_mem_get(mem, sizeof *list);
	if (list == NULL) {
		return (ISC_R_NOMEMORY);
	}

	bytes = sizeof (isc_sockaddr_t) * length;
	list->ips = isc_mem_get(mem, bytes);
	if (list->ips == NULL) {
		isc_mem_put(mem, list, sizeof *list);
		return (ISC_R_NOMEMORY);
	}

	memset(list->ips, 0x0, bytes);

	list->magic = DNS_C_IPLIST_MAGIC;
	list->size = length;
	list->nextidx = 0;
	list->mem = mem;
	list->refcount = 1;

	*newlist = list;
	
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_iplist_detach(dns_c_iplist_t **list) {
	dns_c_iplist_t *l ;

	REQUIRE(list != NULL);
	REQUIRE(*list != NULL);
	
	l = *list;

	REQUIRE(DNS_C_IPLIST_VALID(l));
	INSIST(l->refcount > 0);

	l->refcount--;

	if (l->refcount == 0) {
		isc_mem_put(l->mem, l->ips, sizeof (isc_sockaddr_t) * l->size);
		isc_mem_put(l->mem, l, sizeof *l);
	}

	*list = NULL;

	return (ISC_R_SUCCESS);
}

void
dns_c_iplist_attach(dns_c_iplist_t *source, dns_c_iplist_t **target) {
	REQUIRE(DNS_C_IPLIST_VALID(source));
	INSIST(source->refcount > 0);

	source->refcount++;
	*target = source;
}

isc_result_t
dns_c_iplist_copy(isc_mem_t *mem, dns_c_iplist_t **dest, dns_c_iplist_t *src) {
	dns_c_iplist_t *newl;
	isc_result_t res;
	isc_uint32_t i;

	REQUIRE(dest != NULL);
	REQUIRE(DNS_C_IPLIST_VALID(src));

	res = dns_c_iplist_new(mem, src->size, &newl);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	for (i = 0 ; i < src->nextidx ; i++) {
		newl->ips[i] = src->ips[i];
	}
	newl->nextidx = src->nextidx;

	*dest = newl;

	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_c_iplist_equal(dns_c_iplist_t *list1, dns_c_iplist_t *list2) {
	isc_uint32_t i;

	REQUIRE(DNS_C_IPLIST_VALID(list1));
	REQUIRE(DNS_C_IPLIST_VALID(list2));

	if (list1->nextidx != list2->nextidx)
		return (ISC_FALSE);

	for (i = 0 ; i < list1->nextidx ; i++) {
		if (!isc_sockaddr_equal(&list1->ips[i], &list2->ips[i]))
			return (ISC_FALSE);
	}

	return (ISC_TRUE);
}

void
dns_c_iplist_printfully(FILE *fp, int indent, isc_boolean_t porttoo,
			dns_c_iplist_t *list)
{
	isc_uint32_t i;
	in_port_t port;
	in_port_t tmpport;
	isc_boolean_t athead = ISC_TRUE;

	REQUIRE(DNS_C_IPLIST_VALID(list));
		
	if (list->nextidx == 0) {
		fputc('{', fp);
		fputc('\n', fp);
		dns_c_printtabs(fp, indent);
		fprintf(fp, "/* no ip addresses defined */\n");
		dns_c_printtabs(fp, indent - 1); 
		fputc('}', fp);
	} else {
		if (porttoo) {
			port = isc_sockaddr_getport(&list->ips[0]);
			
			for (i = 0 ; i < list->nextidx ; i++) {
				tmpport = isc_sockaddr_getport(&list->ips[i]);
				if (tmpport != port) {
					athead = ISC_FALSE;
				}
			}

			if (athead) {
				fprintf(fp, "port %d ", port);
			}
		}

		fputc('{', fp);
		fputc('\n', fp);

		for (i = 0 ; i < list->nextidx ; i++) {
			dns_c_printtabs(fp, indent);
			dns_c_print_ipaddr(fp, &list->ips[i]);
			if (!athead) {
				fprintf(fp, " port %d",
					isc_sockaddr_getport(&list->ips[i]));
			}
			fprintf(fp, ";\n");
		}
		dns_c_printtabs(fp, indent - 1);
		fputc('}', fp);
	}

	fputc('\n', fp);
}

void
dns_c_iplist_print(FILE *fp, int indent, dns_c_iplist_t *list) {
	dns_c_iplist_printfully(fp, indent, ISC_FALSE, list);
}

isc_result_t
dns_c_iplist_append(dns_c_iplist_t *list, isc_sockaddr_t newaddr) {
	isc_uint32_t i;

	REQUIRE(DNS_C_IPLIST_VALID(list));

	for (i = 0 ; i < list->nextidx ; i++) {
		if (memcmp(&list->ips[i], &newaddr, sizeof newaddr) == 0) {
			break;
		}
	}

	if (i < list->nextidx) {
		return (ISC_R_FAILURE);
	}

	if (list->nextidx == list->size) {
		isc_sockaddr_t *newlist;
		size_t newbytes;
		size_t oldbytes = list->size * sizeof (list->ips[0]);
		size_t newsize = list->size + 10;

		newbytes = sizeof (list->ips[0]) * newsize;
		newlist = isc_mem_get(list->mem, newbytes);
		if (newlist == NULL) {
			return (ISC_R_NOMEMORY);
		}

		memset(newlist, 0x0, newbytes);
		memcpy(newlist, list->ips, oldbytes);

		isc_mem_put(list->mem, list->ips, oldbytes);
		list->ips = newlist;
		list->size = newsize;
	}
	
	list->ips[i] = newaddr;
	list->nextidx++;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_iplist_remove(dns_c_iplist_t *list, isc_sockaddr_t newaddr) {
	isc_uint32_t i;

	REQUIRE(DNS_C_IPLIST_VALID(list));
	
	for (i = 0 ; i < list->nextidx ; i++) {
		if (memcmp(&list->ips[0], &newaddr, sizeof newaddr) == 0) {
			break;
		}
	}

	if (i == list->nextidx) {
		return (ISC_R_FAILURE);
	}

	list->nextidx--;
	for ( /* nothing */ ; i < list->nextidx ; i++) {
		list->ips[i] = list->ips[i + 1];
	}

	return (ISC_R_SUCCESS);
}

/*
 * Check that the address given is a network address with the given number
 * of high order bits.
 */
static isc_result_t
checkmask(isc_sockaddr_t *address, isc_uint32_t bits) {
	if (bits > 0) {
		if (address->type.sa.sa_family == AF_INET) {
			isc_uint32_t mask;
			
			if (bits > 32) {
				return (ISC_R_FAILURE);
			}
			
			mask = ntohl(0xffffffffU << (32 - bits));
			
			if ((mask & address->type.sin.sin_addr.s_addr) !=
			    address->type.sin.sin_addr.s_addr) {
				return (ISC_R_FAILURE);
			}
		} else if (address->type.sa.sa_family == AF_INET6) {
			struct in6_addr iaddr;
			unsigned char *maskp;
			unsigned char *addrp;
			int i;
			
			if (bits > 128) {
				return (ISC_R_FAILURE);
			}
					
			if (bits2v6mask(&iaddr, bits) != ISC_R_SUCCESS) {
				return (ISC_R_FAILURE);
			}
			
			addrp = (unsigned char *)&address->type.sin6.sin6_addr;
			maskp = (unsigned char *)&iaddr;
			for (i = 0 ; i < 16 ; i++) {
				if ((addrp[i] & maskp[i]) != addrp[i]) {
					return (ISC_R_FAILURE);
				}
			}
		}
	}
	
	return (ISC_R_SUCCESS);
}

/*
 * Create a 128 bits mask in network byte order in the the IPv6 address
 * section of the sockaddr. The bits argument is the number of high bits
 * that are to be set to 1.
 */
static isc_result_t
bits2v6mask(struct in6_addr *addr, isc_uint32_t bits) {
	int i;
	isc_uint32_t bitmask[4];
	char addrbuff [ sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" + 1 ];

	INSIST(bits <= 128);
	
	/* Break the 128 bits up into 32-bit sections */
	bitmask[0] = bitmask[1] = bitmask[2] = bitmask[3] = 0U;
	
	if (bits >= 32) {
		bitmask[0] = 0xffffffffU;
	} else if (bits > 0) {
		bitmask[0] = 0xffffffffU << (32 - bits);
	}

	if (bits >= 64) {
		bitmask[1] = 0xffffffffU;
	} else if (bits > 32) {
		bitmask[1] = 0xffffffffU << (64 - bits);
	}

	if (bits >= 96) {
		bitmask[2] = 0xffffffffU;
		bitmask[3] = 0xffffffffU << (128 - bits);
	} else if (bits > 64) {
		bitmask[2] = 0xffffffffU << (96 - bits);
	}
      
	memset(addr, 0x0, sizeof *addr);
	
	sprintf(addrbuff, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		(((bitmask[0] & 0xffff0000U) >> 16) & 0xffffU),
		(bitmask[0] & 0xffff),
		(((bitmask[1] & 0xffff0000U) >> 16) & 0xffffU),
		(bitmask[1] & 0xffff),
		(((bitmask[2] & 0xffff0000U) >> 16) & 0xffffU),
		(bitmask[2] & 0xffff),
		(((bitmask[3] & 0xffff0000U) >> 16) & 0xffffU),
		(bitmask[3] & 0xffff));

	i = inet_pton(AF_INET6, addrbuff, addr);

	return (i == 1 ? ISC_R_SUCCESS : ISC_R_FAILURE);
}

	

