/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#ifndef ISC_NETADDR_H
#define ISC_NETADDR_H 1

#include <isc/net.h>
#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

struct isc_netaddr {
	unsigned int family;
	union {
    		struct in_addr in;
		struct in6_addr in6;
	} type;
};

isc_boolean_t
isc_netaddr_equal(const isc_netaddr_t *a, const isc_netaddr_t *b);

isc_boolean_t
isc_netaddr_eqprefix(const isc_netaddr_t *a, const isc_netaddr_t *b,
		     unsigned int prefixlen);
/*
 * Compare the 'prefixlen' most significant bits of the network
 * addresses 'a' and 'b'.  Return ISC_TRUE if they are equal,
 * ISC_FALSE if not.
 */

isc_result_t
isc_netaddr_masktoprefixlen(const isc_netaddr_t *s, unsigned int *lenp);
/*
 * Convert a netmask in 's' into a prefix length in '*lenp'.
 * The mask should consist of zero or more '1' bits in the most
 * most significant part of the address, followed by '0' bits.
 * If this is not the case, ISC_R_MASKNONCONTIG is returned.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *	ISC_R_MASKNONCONTIG
 */

void
isc_netaddr_fromsockaddr(isc_netaddr_t *netaddr, const isc_sockaddr_t *source);

void
isc_netaddr_fromin(isc_netaddr_t *netaddr, const struct in_addr *ina);

void
isc_netaddr_fromin6(isc_netaddr_t *netaddr, const struct in6_addr *ina6);

ISC_LANG_ENDDECLS

#endif /* ISC_NETADDR_H */
