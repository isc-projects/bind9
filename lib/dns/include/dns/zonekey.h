#ifndef DNS_ZONEKEY_H
#define DNS_ZONEKEY_H 1

#include <isc/lang.h>

ISC_LANG_BEGINDECLS

isc_boolean_t
dns_zonekey_iszonekey(dns_rdata_t *keyrdata);
/*
 *	Determines if the key record contained in the rdata is a zone key.
 *
 *	Requires:
 *		'keyrdata' is not NULL.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_ZONEKEY_H */
