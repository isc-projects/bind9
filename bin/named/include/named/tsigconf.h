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

/* $Id: tsigconf.h,v 1.4 2000/06/22 21:56:18 tale Exp $ */

#ifndef DNS_TSIGCONF_H
#define DNS_TSIGCONF_H 1

#include <isc/types.h>
#include <isc/lang.h>

#include <dns/confctx.h>

ISC_LANG_BEGINDECLS

isc_result_t
dns_tsigkeyring_fromconfig(dns_c_view_t *confview, dns_c_ctx_t *confctx,
			   isc_mem_t *mctx, dns_tsig_keyring_t **ringp);
/*
 * Create a TSIG key ring and configure it according to the 'key'
 * statements in 'confview' and 'confctx'.
 *
 *	Requires:
 *		'confctx' is a valid configuration context.
 *		'mctx' is not NULL
 *		'ring' is not NULL, and '*ring' is NULL
 *
 *	Returns:
 *		ISC_R_SUCCESS
 *		ISC_R_NOMEMORY
 */
 
ISC_LANG_ENDDECLS

#endif /* DNS_TSIGCONF_H */
