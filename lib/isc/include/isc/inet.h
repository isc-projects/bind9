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

#ifndef ISC_INET_H
#define ISC_INET_H 1

#include <isc/lang.h>
#include <isc/net.h>

ISC_LANG_BEGINDECLS

/*
 * Provide missing functionality that functions internal to the isc/dns
 * library will need.  The #defines used in this file would need to be
 * moved to net.h (and converted to the ISC_ name space) if this file were
 * to be installed.
 */

#ifdef NEED_INET_NTOP
const char *isc_inet_ntop(int af, const void *src, char *dst, size_t size);
#else
#define isc_inet_ntop inet_ntop
#endif

#ifdef NEED_INET_PTON
int isc_inet_pton(int af, const char *src, void *dst);
#else
#define isc_inet_pton inet_pton
#endif

#ifdef NEED_INET_ATON
int isc_inet_aton(const char *cp, struct in_addr *addr);
#else
#define isc_inet_aton inet_aton
#endif

ISC_LANG_ENDDECLS

#endif /* ISC_INET_H */
