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

/* $Id: log.c,v 1.2 1999/10/02 21:13:42 brister Exp $ */

/* Principal Authors: DCL */

#include <isc/assertions.h>
#include <isc/log.h>
#include <isc/result.h>

#include <dns/log.h>
#include <dns/result.h>

/*
 * When adding a new category, be sure to add the appropriate
 * #define to <dns/log.h>.
 */
isc_logcategory_t dns_categories[] = {
	{ "dns_general: ", 	0 },
	{ "dns_database: ", 	0 },
	{ "dns_security: ", 	0 },
	{ "dns_config: ",	0 },
	{ "dns_parser: ",	0 },
	{ NULL, 		0 }
};

/*
 * When adding a new module, be sure to add the appropriate
 * #define to <dns/log.h>.
 */
isc_logmodule_t dns_modules[] = {
	{ "db: ", 	0 },
	{ "rbtdb: ", 	0 }, 
	{ "rbtdb64: ", 	0 }, 
	{ "rbt: ", 	0 }, 
	{ "rdata: ", 	0 },
	{ "master: ", 	0 },
	{ "message: ", 	0 },
	{ "cache: ", 	0 },
	{ "config: ",	0 },
	{ NULL, 	0 }
};

isc_log_t *dns_lctx;

dns_result_t
dns_log_init(isc_log_t *lctx) {
	isc_result_t result;

	REQUIRE(dns_lctx == NULL);

	result = isc_log_registercategories(lctx, dns_categories);

	if (result == ISC_R_SUCCESS) {
		isc_log_registermodules(lctx, dns_modules);
		dns_lctx = lctx;
	}

	return (result);
}
