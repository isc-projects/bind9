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

#ifndef DNS_ZONECONF_H
#define DNS_ZONECONF_H 1

#include <isc/lang.h>
#include <isc/types.h>

#include <dns/aclconf.h>

ISC_LANG_BEGINDECLS

isc_result_t
dns_zone_configure(dns_c_ctx_t *cctx, dns_c_view_t *cview, dns_c_zone_t *czone,
		   dns_aclconfctx_t *ac, dns_zone_t *zone);
/*
 * Configure or reconfigure a zone according to the named.conf
 * data in 'cctx' and 'czone'.
 *
 * The zone origin is not configured, it is assumed to have been set
 * at zone creation time.
 *
 * Require:
 *	'lctx' to be initalised or NULL.
 *	'cctx' to be initalised or NULL.
 *	'ac' to point to an initialized ns_aclconfctx_t.
 *	'czone' to be initalised.
 *	'zone' to be initalised.
 */

isc_boolean_t
dns_zone_reusable(dns_zone_t *zone, dns_c_zone_t *czone);
/*
 * If 'zone' can be safely reconfigured according to the configuration
 * data in 'czone', return ISC_TRUE.  If the configuration data is so
 * different from the current zone state that the zone needs to be destroyed
 * and recreated, return ISC_FALSE.
 */

isc_result_t
dns_zonemgr_configure(dns_c_ctx_t *cctx, dns_zonemgr_t *zonemgr);
/*
 * Configure the zone manager according to the named.conf data
 * in 'cctx'.
 */
ISC_LANG_ENDDECLS

#endif /* DNS_ZONECONF_H */
