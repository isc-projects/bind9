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

/* $Id: aclconf.c,v 1.18.2.2 2000/08/11 02:38:16 bwelling Exp $ */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/aclconf.h>
#include <dns/fixedname.h>
#include <dns/log.h>

void
dns_aclconfctx_init(dns_aclconfctx_t *ctx) {
	ISC_LIST_INIT(ctx->named_acl_cache);
}

void
dns_aclconfctx_destroy(dns_aclconfctx_t *ctx) {
     	dns_acl_t *dacl, *next;	
	for (dacl = ISC_LIST_HEAD(ctx->named_acl_cache);
	     dacl != NULL;
	     dacl = next)
	{
		next = ISC_LIST_NEXT(dacl, nextincache);
		dns_acl_detach(&dacl);
	}
}

static isc_result_t
convert_named_acl(char *aclname, dns_c_ctx_t *cctx,
		  dns_aclconfctx_t *ctx, isc_mem_t *mctx,
		  dns_acl_t **target)
{
	isc_result_t result;
	dns_c_acl_t *cacl;
	dns_acl_t *dacl;

	/* Look for an already-converted version. */
	for (dacl = ISC_LIST_HEAD(ctx->named_acl_cache);
	     dacl != NULL;
	     dacl = ISC_LIST_NEXT(dacl, nextincache))
	{
		if (strcmp(aclname, dacl->name) == 0) {
			dns_acl_attach(dacl, target);
			return (ISC_R_SUCCESS);
		}
	}
	/* Not yet converted.  Convert now. */
	result = dns_c_acltable_getacl(cctx->acls, aclname, &cacl);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      DNS_LOGMODULE_ACL, ISC_LOG_WARNING,
			      "undefined ACL '%s'", aclname);
		return (result);
	}
	result = dns_acl_fromconfig(cacl->ipml, cctx, ctx, mctx, &dacl);
	if (result != ISC_R_SUCCESS)
		return (result);
	dacl->name = isc_mem_strdup(dacl->mctx, aclname);
	if (dacl->name == NULL)
		return (ISC_R_NOMEMORY);
	ISC_LIST_APPEND(ctx->named_acl_cache, dacl, nextincache);
	dns_acl_attach(dacl, target);
	return (ISC_R_SUCCESS);
}

static isc_result_t
convert_keyname(char *txtname, isc_mem_t *mctx, dns_name_t *dnsname) {
	isc_result_t result;
	isc_buffer_t buf;
	dns_fixedname_t fixname;
	unsigned int keylen;

	keylen = strlen(txtname);
	isc_buffer_init(&buf, txtname, keylen);
	isc_buffer_add(&buf, keylen);
	dns_fixedname_init(&fixname);
	result = dns_name_fromtext(dns_fixedname_name(&fixname), &buf,
				   dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      DNS_LOGMODULE_ACL, ISC_LOG_WARNING,
			      "key name \"%s\" is not a valid domain name",
			      txtname);
		return (result);
	}
	return (dns_name_dup(dns_fixedname_name(&fixname), mctx, dnsname));
}
	       
isc_result_t
dns_acl_fromconfig(dns_c_ipmatchlist_t *caml,
		   dns_c_ctx_t *cctx,
		   dns_aclconfctx_t *ctx,
		   isc_mem_t *mctx,
		   dns_acl_t **target)
{
	isc_result_t result;
	unsigned int count;
	dns_acl_t *dacl = NULL;
	dns_aclelement_t *de;
	dns_c_ipmatchelement_t *ce;

	REQUIRE(target != NULL && *target == NULL);
	
	count = 0;
	for (ce = ISC_LIST_HEAD(caml->elements);
	     ce != NULL;
	     ce = ISC_LIST_NEXT(ce, next))
		count++;

	result = dns_acl_create(mctx, count, &dacl);
	if (result != ISC_R_SUCCESS)
		return (result);
	
	de = dacl->elements;
	for (ce = ISC_LIST_HEAD(caml->elements);
	     ce != NULL;
	     ce = ISC_LIST_NEXT(ce, next))
	{
		de->negative = dns_c_ipmatchelement_isneg(ce);
		switch (ce->type) {
		case dns_c_ipmatch_pattern:
			de->type = dns_aclelementtype_ipprefix;
			isc_netaddr_fromsockaddr(&de->u.ip_prefix.address,
						 &ce->u.direct.address);
			/* XXX "mask" is a misnomer */
			de->u.ip_prefix.prefixlen = ce->u.direct.mask;
			break;
		case dns_c_ipmatch_key:
			de->type = dns_aclelementtype_keyname;
			dns_name_init(&de->u.keyname, NULL);
			result = convert_keyname(ce->u.key, mctx,
						 &de->u.keyname);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			break;
		case dns_c_ipmatch_indirect:
			de->type = dns_aclelementtype_nestedacl;
			result = dns_acl_fromconfig(ce->u.indirect.list,
						    cctx, ctx, mctx,
						    &de->u.nestedacl);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			break;
		case dns_c_ipmatch_localhost:
			de->type = dns_aclelementtype_localhost;
			break;

		case dns_c_ipmatch_any:
			de->type = dns_aclelementtype_any;
			break;

		case dns_c_ipmatch_localnets:
			de->type = dns_aclelementtype_localnets;
			break;
		case dns_c_ipmatch_acl:
			de->type = dns_aclelementtype_nestedacl;
			result = convert_named_acl(ce->u.aclname,
						   cctx, ctx, mctx,
						   &de->u.nestedacl);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			break;
		default:
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
				      DNS_LOGMODULE_ACL, ISC_LOG_WARNING,
				      "address match list contains "
				      "unsupported element type");
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		de++;
		dacl->length++;
	}

	*target = dacl;
	return (ISC_R_SUCCESS);
	
 cleanup:
	dns_acl_detach(&dacl);
	return (result);
}
