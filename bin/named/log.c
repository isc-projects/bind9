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

#include <config.h>

#include <isc/assertions.h>
#include <isc/log.h>
#include <isc/result.h>

#include <dns/log.h>

#include <named/globals.h>
#include <named/log.h>

/*
 * When adding a new category, be sure to add the appropriate
 * #define to <named/log.h>.
 */
static isc_logcategory_t categories[] = {
	{ "",		 		0 },
	{ "client",	 		0 },
	{ "network",	 		0 },
	{ "update",	 		0 },
	{ NULL, 			0 }
};

/*
 * When adding a new module, be sure to add the appropriate
 * #define to <dns/log.h>.
 */
static isc_logmodule_t modules[] = {
	{ "main",	 		0 },
	{ "client",	 		0 },
	{ "server",		 	0 },
	{ "query",		 	0 },
	{ "interfacemgr",	 	0 },
	{ "update",	 		0 },
	{ "xfer-in",	 		0 },
	{ "xfer-out",	 		0 },
	{ "notify",	 		0 },
	{ NULL, 			0 }
};

isc_result_t
ns_log_init(void) {
	isc_result_t result;
	isc_logconfig_t *lcfg;

	ns_g_categories = categories;
	ns_g_modules = modules;

	/*
	 * XXXRTH  This is not necessarily the final default logging
	 *         setup.
	 */

	/*
	 * Setup a logging context.
	 */
	result = isc_log_create(ns_g_mctx, &ns_g_lctx, &lcfg);
	if (result != ISC_R_SUCCESS)
		return (result);

	isc_log_registercategories(ns_g_lctx, ns_g_categories);
	isc_log_registermodules(ns_g_lctx, ns_g_modules);
	dns_log_init(ns_g_lctx);

	result = ns_log_setdefaults(lcfg);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	return (ISC_R_SUCCESS);

 cleanup:
	isc_log_destroy(&ns_g_lctx);

	return (result);
}

isc_result_t
ns_log_setdefaults(isc_logconfig_t *lcfg) {
	isc_result_t result;
	isc_logdestination_t destination;
	
	/*
	 * By default, the logging library makes "default_debug" log to
	 * stderr.  In BIND, we want to override this and log to named.run
	 * instead, unless the the -g option was given.
	 */
	if (! ns_g_logstderr) {
		destination.file.stream = NULL;
		destination.file.name = "named.run";
		destination.file.versions = ISC_LOG_ROLLNEVER;
		destination.file.maximum_size = 0;
		result = isc_log_createchannel(lcfg, "default_debug",
                                               ISC_LOG_TOFILE,
                                               ISC_LOG_DYNAMIC,
                                               &destination,
                                               ISC_LOG_PRINTTIME|
					       ISC_LOG_DEBUGONLY);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	}

	result = isc_log_usechannel(lcfg, "default_syslog",
				    ISC_LOGCATEGORY_DEFAULT, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = isc_log_usechannel(lcfg, "default_debug",
				    ISC_LOGCATEGORY_DEFAULT, NULL);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/*
	 * Set the initial debug level.
	 */
	isc_log_setdebuglevel(ns_g_lctx, ns_g_debuglevel);

	return (ISC_R_SUCCESS);

 cleanup:
	return (result);
}

void
ns_log_shutdown(void) {
	isc_log_destroy(&ns_g_lctx);
}
