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

#ifndef DNS_XFRIN_H
#define DNS_XFRIN_H 1

/*****
 ***** Module Info
 *****/

/*
 * Incoming zone transfers (AXFR + IXFR).
 */

#include <dns/types.h>

/***
 *** Functions
 ***/

void dns_xfrin_start(dns_zone_t *zone, isc_sockaddr_t *master, 
		isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		isc_timermgr_t *timermgr, isc_socketmgr_t *socketmgr,
		dns_xfrindone_t done);

#endif /* DNS_XFRIN_H */
