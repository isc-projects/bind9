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
#include <isc/error.h>

#include <dns/confip.h>
#include <dns/confcommon.h>


/* Flag for dns_c_ipmatch_element */
#define DNS_C_IPMATCH_NEGATE	0x01	/* match means deny access */


isc_result_t
dns_c_ipmatchelement_new(isc_mem_t *mem, dns_c_ipmatchelement_t **result)
{
	dns_c_ipmatchelement_t *ime ;

	REQUIRE(result != NULL);

	*result = NULL;

	ime = isc_mem_get(mem, sizeof *ime);
	if (ime == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ime->type = dns_c_ipmatch_none;
	ime->flags = 0;
	memset(&ime->u, 0x0, sizeof ime->u);

	ISC_LINK_INIT(ime, next);

	*result = ime;

	return (ISC_R_SUCCESS);
}


isc_boolean_t
dns_c_ipmatchelement_isneg(dns_c_ipmatchelement_t *elem)
{
	return ((elem->flags & DNS_C_IPMATCH_NEGATE) == DNS_C_IPMATCH_NEGATE);
}


isc_result_t
dns_c_ipmatchelement_delete(isc_mem_t *mem, dns_c_ipmatchelement_t **ipme)
{
	dns_c_ipmatchelement_t *elem;
	
	REQUIRE(mem != NULL);
	REQUIRE(ipme != NULL);
	
	if (*ipme == NULL) {
		return (ISC_R_SUCCESS);
	}

	elem = *ipme;
	
	switch (elem->type) {
	case dns_c_ipmatch_localhost:
	case dns_c_ipmatch_localnets:
	case dns_c_ipmatch_pattern:
		/* nothing */
		break;

	case dns_c_ipmatch_indirect:
		INSIST(elem->u.indirect.list != NULL);

		dns_c_ipmatchlist_delete(&elem->u.indirect.list);
		if (elem->u.indirect.refname.base != NULL) {
			isc_mem_put(mem, elem->u.indirect.refname.base,
				    elem->u.indirect.refname.length);
		}
		break;

	case dns_c_ipmatch_key:
		isc_mem_free(mem, elem->u.key );
		break;

	case dns_c_ipmatch_acl:
		isc_mem_free(mem, elem->u.aclname);
		break;
		
	case dns_c_ipmatch_none:
		dns_c_error(0, "dns_ipmath_none element type\n");
		return (ISC_R_FAILURE);
	}

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
	REQUIRE(src != NULL);
		
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
		
	case dns_c_ipmatch_none:
		dns_c_error(0, "ipmatch 'none' element type\n");
		return (ISC_R_FAILURE);
	}

	*dest = newel;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ipmatchlocalhost_new(isc_mem_t *mem, dns_c_ipmatchelement_t **result)
{
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
dns_c_ipmatchlocalnets_new(isc_mem_t *mem,
			    dns_c_ipmatchelement_t **result)
{
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
	REQUIRE(iml != NULL);

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
		dns_c_ipmatchlist_delete(&iml_copy);
	}
	
	*result = ime;

	return (res);
}


isc_result_t
dns_c_ipmatchpattern_new(isc_mem_t *mem,
			  dns_c_ipmatchelement_t **result,
			  dns_c_addr_t address,
			  isc_uint32_t maskbits)
{
	dns_c_ipmatchelement_t *ime ;
	isc_result_t res;
	isc_uint32_t mask;

	REQUIRE(result != NULL);
	REQUIRE(mem != NULL);
	REQUIRE(maskbits < 32);

	*result = NULL;

	res = dns_c_ipmatchelement_new(mem, &ime);
	if (res != ISC_R_SUCCESS) {
		return (res);
	}

	ime->type = dns_c_ipmatch_pattern;

	if (maskbits == 0) {
		mask = 0;
	} else {
		mask = 0xffffffffU;
		mask >>= (32 - maskbits);
		mask <<= (32 - maskbits);
	}

#if 0
	/* XXX this is not complete for IPV6 -- masks need fixing. */
#endif
	
	if (mask != 0) {
		mask = ntohl(mask);
		/* Make sure mask is on a net and not a host. */
		if ((mask & address.u.a.s_addr) != address.u.a.s_addr) {
			dns_c_ipmatchelement_delete(mem, &ime);
			return (ISC_R_FAILURE);
		}
	}

	ime->u.direct.address = address;
	ime->u.direct.mask.u.a.s_addr = mask; /* XXX not right. */

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
	REQUIRE(strlen(aclname) > 0);

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
dns_c_ipmatch_negate(dns_c_ipmatchelement_t *ipe)
{
	REQUIRE(ipe != NULL);

	if ((ipe->flags & DNS_C_IPMATCH_NEGATE) == DNS_C_IPMATCH_NEGATE) {
		ipe->flags &= ~DNS_C_IPMATCH_NEGATE;
	} else {
		ipe->flags |= DNS_C_IPMATCH_NEGATE;
	}

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ipmatchlist_new(isc_mem_t *mem, dns_c_ipmatchlist_t **ptr)
{
	dns_c_ipmatchlist_t *newlist;

	REQUIRE(ptr != NULL);
	REQUIRE(mem != NULL);

	newlist = isc_mem_get(mem, sizeof *newlist);
	if (newlist == NULL) {
		return (ISC_R_NOMEMORY);
	}

	ISC_LIST_INIT(newlist->elements);
	newlist->mem = mem;
	newlist->refcount = 1;
	
	*ptr = newlist;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ipmatchlist_delete(dns_c_ipmatchlist_t **ml)
{
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchelement_t *iptr;
	dns_c_ipmatchlist_t *iml;
	isc_mem_t *mem;

	REQUIRE(ml != NULL);

	iml = *ml;
	if (iml == NULL) {
		return (ISC_R_SUCCESS);
	}
	*ml = NULL;

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


dns_c_ipmatchlist_t *
dns_c_ipmatchlist_attach(dns_c_ipmatchlist_t *ipml)
{
	REQUIRE(ipml != NULL);
	INSIST(ipml->refcount > 0);

	ipml->refcount++;
	return (ipml);
}


isc_result_t
dns_c_ipmatchlist_empty(dns_c_ipmatchlist_t *ipml)
{
	dns_c_ipmatchelement_t *ime ;
	dns_c_ipmatchelement_t *imptmp;
	isc_result_t res = ISC_R_SUCCESS;

	REQUIRE(ipml != NULL);
	
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
	REQUIRE(src != NULL);

	*dest = NULL;

	result = dns_c_ipmatchlist_new(mem, &newlist);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	ime = ISC_LIST_HEAD(src->elements);
	while (ime != NULL) {
		result = dns_c_ipmatchelement_copy(mem, &ptr, ime);
		if (result != ISC_R_SUCCESS) {
			dns_c_ipmatchlist_delete(&newlist);
			return (result);
		}
		
		ISC_LIST_APPEND(newlist->elements, ptr, next);

		ime = ISC_LIST_NEXT(ime, next);
	}

	*dest = newlist;

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ipmatchlist_append(dns_c_ipmatchlist_t *dest,
			  dns_c_ipmatchlist_t *src,
			  isc_boolean_t negate)
{
	dns_c_ipmatchelement_t *ime;
	dns_c_ipmatchelement_t *ime_copy;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(dest != NULL);
	REQUIRE(src != NULL);

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
dns_c_ipmatchelement_print(FILE *fp, int indent,
			    dns_c_ipmatchelement_t *ipme)
{
	int bits;
	isc_uint32_t tmpaddr;

	REQUIRE(fp != NULL);
	REQUIRE(ipme != NULL);

	if ((ipme->flags & DNS_C_IPMATCH_NEGATE) == DNS_C_IPMATCH_NEGATE) {
		fputc('!', fp);
	} else {
		fputc(' ', fp);
	}

	switch (ipme->type) {
	case dns_c_ipmatch_pattern:
		dns_c_print_ipaddr(fp, &ipme->u.direct.address);

		bits = 0;
		if (ipme->u.direct.mask.u.a.s_addr != 0) {
			tmpaddr = ntohl(ipme->u.direct.mask.u.a.s_addr);
			while ((tmpaddr & 0x1) == 0x0) {
				bits++;
				tmpaddr >>= 1;
			}
			INSIST(bits < 32);
		}
		if (bits > 0) {
			fprintf(fp, "/%d", 32 - bits);
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

	case dns_c_ipmatch_none:
		dns_c_error(0, "dns_ipmath_none element type\n");
		return (ISC_R_FAILURE);

	case dns_c_ipmatch_acl:
		fprintf(fp, "%s", ipme->u.aclname);
		break;
	}

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ipmatchlist_print(FILE *fp, int indent, dns_c_ipmatchlist_t *ml)
{
	dns_c_ipmatchelement_t *ipme ;

	REQUIRE(ml != NULL);
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
	fprintf(fp, "};\n");

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_iplist_new(isc_mem_t *mem, int length, dns_c_iplist_t **newlist)
{
	dns_c_iplist_t *list;
	size_t bytes;
	
	REQUIRE(mem != NULL);
	REQUIRE(length > 0);
	REQUIRE(newlist != NULL);

	list = isc_mem_get(mem, sizeof *list);
	if (list == NULL) {
		return (ISC_R_NOMEMORY);
	}

	bytes = sizeof (dns_c_addr_t) * length;
	list->ips = isc_mem_get(mem, bytes);
	if (list->ips == NULL) {
		isc_mem_put(mem, list, sizeof *list);
		return (ISC_R_NOMEMORY);
	}

	memset(list->ips, 0x0, bytes);

	list->size = length;
	list->nextidx = 0;
	list->mem = mem;
	list->refcount = 1;

	*newlist = list;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_iplist_delete(dns_c_iplist_t **list)
{
	dns_c_iplist_t *l ;

	REQUIRE(list != NULL);

	l = *list;
	if (l == NULL) {
		return (ISC_R_SUCCESS);
	}

	INSIST(l->refcount > 0);

	l->refcount--;

	if (l->refcount == 0) {
		isc_mem_put(l->mem, l->ips, sizeof (dns_c_addr_t) * l->size);
		isc_mem_put(l->mem, l, sizeof *l);
	}

	*list = NULL;

	return (ISC_R_SUCCESS);
}

dns_c_iplist_t *
dns_c_iplist_attach(dns_c_iplist_t *list)
{
	REQUIRE(list != NULL);
	INSIST(list->refcount > 0);

	list->refcount++;
	return (list);
}



isc_result_t
dns_c_iplist_copy(isc_mem_t *mem, dns_c_iplist_t **dest, dns_c_iplist_t *src)
{
	dns_c_iplist_t *newl;
	isc_result_t res;
	isc_uint32_t i;

	REQUIRE(dest != NULL);
	REQUIRE(src != NULL);

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


void
dns_c_iplist_print(FILE *fp, int indent, dns_c_iplist_t *list)
{
	isc_uint32_t i;

	fprintf(fp, "{\n");

	if (list->nextidx == 0) {
		dns_c_printtabs(fp, indent);
		fprintf(fp, "/* no ip addresses defined */\n");
	} else {
		for (i = 0 ; i < list->nextidx ; i++) {
			dns_c_printtabs(fp, indent);
			dns_c_print_ipaddr(fp, &list->ips[i]);
			fprintf(fp, ";\n");
		}
	}
	
	dns_c_printtabs(fp, indent - 1);
	fprintf(fp, "};\n");
}


isc_result_t
dns_c_iplist_append(dns_c_iplist_t *list, dns_c_addr_t newaddr)
{
	isc_uint32_t i;

	REQUIRE(list != NULL);

	for (i = 0 ; i < list->nextidx ; i++) {
		if (memcmp(&list->ips[i], &newaddr, sizeof newaddr) == 0) {
			break;
		}
	}

	if (i < list->nextidx) {
		return (ISC_R_FAILURE);
	}

	if (list->nextidx == list->size) {
		dns_c_addr_t *newlist;
		size_t newbytes;
		size_t oldbytes = list->size * sizeof (list->ips[0]);
		size_t newsize = list->size + 10;

		newbytes = sizeof (list->ips[0]) * newsize;
		newlist = isc_mem_get(list->mem, newbytes);
		if (newlist == NULL) {
			return (ISC_R_NOMEMORY);
		}

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
dns_c_iplist_remove(dns_c_iplist_t *list, dns_c_addr_t newaddr)
{
	isc_uint32_t i;
	
	REQUIRE(list != NULL);
	
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


