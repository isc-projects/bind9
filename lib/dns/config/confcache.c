/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
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

/* $Id: confcache.c,v 1.8.4.1 2001/01/09 22:44:36 bwelling Exp $ */

#include <config.h>

#include <dns/confcache.h>
#include <isc/result.h>

#include "confpvt.h"

isc_result_t
dns_c_cache_new(isc_mem_t *mem, dns_c_cache_t **cfgcache) {

	(void) mem ; (void) cfgcache; /* lint */

	/* XXX nothing yet */

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_cache_delete(dns_c_cache_t **cfgcache) {
	(void) cfgcache ;	/* lint */

	/* XXX nothin yet */

	return (ISC_R_SUCCESS);
}



