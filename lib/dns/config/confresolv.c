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

/* $Id: confresolv.c,v 1.9.4.1 2001/01/09 22:44:51 bwelling Exp $ */

#include <config.h>

#include <isc/util.h>

#include <dns/confresolv.h>

#include "confpvt.h"

isc_result_t
dns_c_resolv_new(isc_mem_t *mem, dns_c_resolv_t **cfgres) {
	UNUSED(mem);
	UNUSED(cfgres);

	/* XXX nothing yet */

	return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_resolv_delete(dns_c_resolv_t **cfgres) {
	UNUSED(cfgres);

	/* XXX nothin yet */

	return (ISC_R_SUCCESS);
}



