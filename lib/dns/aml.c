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
#include <isc/mem.h>
#include <isc/result.h>

#include <dns/aml.h>
#include <dns/fixedname.h>
#include <dns/journal.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/result.h>
#include <dns/types.h>

isc_result_t
dns_aml_checkrequest(dns_message_t *request, isc_sockaddr_t *reqaddr,
		     dns_c_acltable_t *acltable, const char *opname,
		     dns_c_ipmatchlist_t *main_aml,
		     dns_c_ipmatchlist_t *fallback_aml,
		     isc_boolean_t default_allow)
{
	isc_result_t result, sig_result;
	dns_name_t signer;
	dns_name_t *ok_signer = NULL;
	int match;
	dns_c_ipmatchlist_t *aml = NULL;

	dns_name_init(&signer, NULL);
	
	/*
	 * Check for a TSIG.  We log bad TSIGs regardless of whether they
	 * cause the request to be rejected or not (it may be allowd 
	 * because of another AML).  We do not log the lack of a TSIG
	 * unless we are debugging.
	 */
	sig_result = result = dns_message_signer(request, &signer);
	if (result == DNS_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      DNS_LOGMODULE_AML, ISC_LOG_DEBUG(3),
			      "request has valid signature");
		ok_signer = &signer;
	} else if (result == DNS_R_NOTFOUND) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      DNS_LOGMODULE_AML, ISC_LOG_DEBUG(3),
			      "request is not signed");
	} else {
		/* There is a signature, but it is bad. */
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      DNS_LOGMODULE_AML, ISC_LOG_ERROR,
			      "request has invalid signature: %s",
			      isc_result_totext(result));
	}

	if (main_aml != NULL)
		aml = main_aml;
	else if (fallback_aml != NULL)
		aml = fallback_aml;
	else if (default_allow)
		goto allow;
	else
		goto deny;

	result = dns_aml_match(reqaddr, ok_signer, aml,
			       acltable, &match, NULL);
	if (result != DNS_R_SUCCESS)
		goto deny; /* Internal error, already logged. */
	if (match > 0)
		goto allow;
	goto deny; /* Negative match or no match. */

 allow:
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
		      DNS_LOGMODULE_AML, ISC_LOG_DEBUG(3),
		      "%s approved", opname);
	return (DNS_R_SUCCESS);

 deny:
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
		      DNS_LOGMODULE_AML, ISC_LOG_ERROR,
		      "%s denied", opname);
	return (DNS_R_REFUSED);
}

static isc_result_t
signer_matches(dns_name_t *signer, char *keyname, isc_boolean_t *match)
{
	isc_result_t result;
	isc_buffer_t buf;
	dns_fixedname_t fixname;
	unsigned int keylen;

	keylen = strlen(keyname);
	isc_buffer_init(&buf, keyname, keylen, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&buf, keylen);
	dns_fixedname_init(&fixname);
	result = dns_name_fromtext(dns_fixedname_name(&fixname), &buf,
				   dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
			      DNS_LOGMODULE_AML, ISC_LOG_WARNING,
			      "key name \"%s\" is not a valid domain name",
			      keyname);
		return (result);
	}
	*match = dns_name_equal(signer, dns_fixedname_name(&fixname));
	return (ISC_R_SUCCESS);
}
     
isc_result_t
dns_aml_match(isc_sockaddr_t *reqaddr,
	      dns_name_t *reqsigner,
	      dns_c_ipmatchlist_t *aml,
	      dns_c_acltable_t *acltable,
	      int *match,
	      dns_c_ipmatchelement_t **matchelt)
{
	isc_result_t result;
	dns_c_ipmatchelement_t *e;
	int distance;
	int indirectmatch;
	dns_c_acl_t *acl = NULL;

	REQUIRE(matchelt == NULL || *matchelt == NULL);

	for (e = ISC_LIST_HEAD(aml->elements), distance = 1;
	     e != NULL;
	     e = ISC_LIST_NEXT(e, next), distance++)
	{
		dns_c_ipmatchlist_t *indirect_acl = NULL;
		
		switch (e->type) {
		case dns_c_ipmatch_pattern:
			/* XXX "mask" is a misnomer, should be
			   "prefix length" */
			if (isc_sockaddr_eqaddrprefix(reqaddr,
						      &e->u.direct.address,
						      e->u.direct.mask))
				goto matched;
			break;
		
		case dns_c_ipmatch_key:
			if (reqsigner != NULL) {
				isc_boolean_t match;
				result = signer_matches(reqsigner, e->u.key,
							&match);
				if (result != ISC_R_SUCCESS)
					return (result);
				if (match == ISC_TRUE)
					goto matched;
			}
			break;
		
		case dns_c_ipmatch_indirect:
			indirect_acl = e->u.indirect.list;
			goto indirect;

#ifdef notyet			
		case dns_c_ipmatch_localhost:
			indirect_acl = localhost_acl;
			goto indirect;
			
		case dns_c_ipmatch_localnets:
			indirect_acl = localnets_acl;
			goto indirect;
#else
		case dns_c_ipmatch_localhost:
		case dns_c_ipmatch_localnets:			
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
				      DNS_LOGMODULE_AML, ISC_LOG_WARNING,
				      "the \"localhost\" and \"localnets\""
				      "ACLs are not yet supported");
			return (ISC_R_NOTIMPLEMENTED);
#endif

		case dns_c_ipmatch_acl:
			result = dns_c_acltable_getacl(dns_lctx,
						       acltable,
						       e->u.aclname,
						       &acl);
			if (result == ISC_R_SUCCESS) {
				indirect_acl = acl->ipml;
				goto indirect;
			}
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
				      DNS_LOGMODULE_AML, ISC_LOG_WARNING,
				      "undefined ACL \"%s\"", e->u.aclname);
			return (result);
		
		default:
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_SECURITY,
				      DNS_LOGMODULE_AML, ISC_LOG_WARNING,
				      "address match list contains "
				      "unsupported element type");
			break;

		indirect:
			INSIST(indirect_acl != NULL);
			result = dns_aml_match(reqaddr, reqsigner,
					       indirect_acl, acltable,
					       &indirectmatch, matchelt);
			if (result != DNS_R_SUCCESS)
				return (result);
			/*
			 * Treat negative matches in indirect AMLs as
			 * "no match".
			 * That way, a negated indirect AML will never become 
			 * a surprise positive match through double negation.
			 */
			if (indirectmatch > 0)
				goto matched;

			/* A negative indirect match may have set *matchelt. */
			if (matchelt != NULL)
				*matchelt = NULL;
			break;

		matched:
			*match = dns_c_ipmatchelement_isneg(dns_lctx, e) ?
				-distance : distance;
			if (matchelt != NULL)
				*matchelt = e;
			return (ISC_R_SUCCESS);

		}
	}
	/* No match. */
	*match = 0;
	return (ISC_R_SUCCESS);
}

