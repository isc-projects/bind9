/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: opt.h,v 1.2 2000/10/12 21:51:57 mws Exp $ */

#ifndef DNS_OPT_H
#define DNS_OPT_H 1

#include <isc/lang.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/types.h>

#include <dns/rdataset.h>
#include <dns/message.h>

#ifndef NOMINUM_PUBLIC
/*
 * XXX For GNS, We're enabling the new option codes.  This is
 * internal use only.
 */
#define DNS_OPT_NEWCODES
#endif /* NOMINUM_PUBLIC */

/*
 * XXX WARNING XXX  These codes have not yet been assigned by IANA.
 * These are here as placekeepers ONLY.
 * Hide these definitions and anything that uses them behind a #define 
 * which happens only in internal debugging code.
 * This #ifdef will go away once these are defined by IANA.
 */
#ifdef DNS_OPT_NEWCODES
#define DNS_OPTCODE_ZONE 0xfff0
#define DNS_OPTCODE_VIEW 0xfff1
#endif /* DNS_OPT_NEWCODES */

/*
 * OPT records contain a series of attributes which contain different types.
 * These structures are used for holding the individual attribute
 * records.
 */
typedef struct dns_optattr {
	isc_uint16_t                    code;
	isc_region_t                    value;
} dns_optattr_t;

typedef struct dns_optlist {
	unsigned int                    size;
        unsigned int                    used;
	unsigned int                    next;
        dns_optattr_t                  *attrs;
} dns_optlist_t;

isc_result_t
dns_opt_decode(dns_optlist_t *optlist, dns_rdataset_t *optset,
	       isc_uint16_t code);

isc_result_t
dns_opt_decodeall(dns_optlist_t *optlist, dns_rdataset_t *optset);

isc_result_t
dns_opt_add(dns_rdata_t *rdata, dns_optlist_t *optlist,
	    isc_buffer_t *target);

isc_result_t
dns_opt_attrtotext(dns_optattr_t *attr, isc_buffer_t *target,
		   dns_messagetextflag_t flags);

isc_result_t
dns_opt_totext(dns_rdataset_t *opt, isc_buffer_t *target,
	       dns_messagetextflag_t flags);

ISC_LANG_ENDDECLS

#endif /* DNS_OPT_H */
