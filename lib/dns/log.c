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

/* $Id: log.c,v 1.13 2000/02/03 23:43:49 halley Exp $ */

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
	{ "dns_general", 	0 },
	{ "dns_database", 	0 },
	{ "dns_security", 	0 },
	{ "dns_config",		0 },
	{ "dns_parser",		0 },
	{ "dns_resolver",	0 },
	{ "dns_xfer_in",	0 },
	{ "dns_xfer_out",	0 },
	{ NULL, 		0 }
};

/*
 * When adding a new module, be sure to add the appropriate
 * #define to <dns/log.h>.
 */
isc_logmodule_t dns_modules[] = {
	{ "dns/db",	 	0 },
	{ "dns/rbtdb", 		0 }, 
	{ "dns/rbtdb64", 	0 }, 
	{ "dns/rbt", 		0 }, 
	{ "dns/rdata", 		0 },
	{ "dns/master", 	0 },
	{ "dns/message", 	0 },
	{ "dns/cache", 		0 },
	{ "dns/config",		0 },
	{ "dns/resolver",	0 },
	{ "dns/zone",		0 },
	{ "dns/journal",	0 },
	{ "dns/adb",		0 },
	{ "dns/xfrin",		0 },
	{ "dns/xfrout",		0 },
	{ "dns/acl",		0 },	
	{ NULL, 		0 }
};

isc_log_t *dns_lctx;

isc_result_t
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
