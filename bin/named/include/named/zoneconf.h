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

#ifndef NS_ZONECONF_H
#define NS_ZONECONF_H 1

#include <isc/types.h>

#include <dns/acl.h>
#include <dns/confacl.h>
#include <dns/confip.h>

/*
 * Create a dns_acl_t from the corresponding configuration data structure,
 * 'caml'.  References to named ACLs in caml are resolved against the ACL
 * table in 'cctx'.
 */

dns_result_t dns_zone_configure(isc_log_t *lctx, dns_c_ctx_t *ctx,
				dns_aclconfctx_t *ac,
				dns_c_zone_t *czone, dns_zone_t *zone);
/*
 *	Configure or reconfigure a zone according to the named.conf
 *      data in 'ctx' and 'czone'.
 *
 * Require:
 *	'lctx' to be initalised or NULL.
 *	'ctx' to be initalised or NULL.
 *	'ac' to point to an initialized ns_aclconfctx_t.
 *	'czone' to be initalised.
 *	'zone' to be initalised.
 */


ISC_LANG_ENDDECLS

#endif /* NS_ZONECONF_H */
