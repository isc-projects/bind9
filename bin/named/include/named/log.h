/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef NAMED_LOG_H
#define NAMED_LOG_H 1

/*! \file */

#include <isc/log.h>
#include <isc/types.h>

#include <dns/log.h>

#include <named/globals.h>	/* Required for ns_g_(categories|modules). */

/* Unused slot 0. */
#define NS_LOGCATEGORY_CLIENT		(&ns_g_categories[1])
#define NS_LOGCATEGORY_NETWORK		(&ns_g_categories[2])
#define NS_LOGCATEGORY_UPDATE		(&ns_g_categories[3])
#define NS_LOGCATEGORY_QUERIES		(&ns_g_categories[4])
#define NS_LOGCATEGORY_UNMATCHED	(&ns_g_categories[5])
#define NS_LOGCATEGORY_UPDATE_SECURITY	(&ns_g_categories[6])
#define NS_LOGCATEGORY_QUERY_ERRORS	(&ns_g_categories[7])
#define NS_LOGCATEGORY_TAT		(&ns_g_categories[8])

/*
 * Backwards compatibility.
 */
#define NS_LOGCATEGORY_GENERAL		ISC_LOGCATEGORY_GENERAL

#define NS_LOGMODULE_MAIN		(&ns_g_modules[0])
#define NS_LOGMODULE_CLIENT		(&ns_g_modules[1])
#define NS_LOGMODULE_SERVER		(&ns_g_modules[2])
#define NS_LOGMODULE_QUERY		(&ns_g_modules[3])
#define NS_LOGMODULE_INTERFACEMGR	(&ns_g_modules[4])
#define NS_LOGMODULE_UPDATE		(&ns_g_modules[5])
#define NS_LOGMODULE_XFER_IN		(&ns_g_modules[6])
#define NS_LOGMODULE_XFER_OUT		(&ns_g_modules[7])
#define NS_LOGMODULE_NOTIFY		(&ns_g_modules[8])
#define NS_LOGMODULE_CONTROL		(&ns_g_modules[9])
#define NS_LOGMODULE_LWRESD		(&ns_g_modules[10])

isc_result_t
ns_log_init(bool safe);
/*%
 * Initialize the logging system and set up an initial default
 * logging default configuration that will be used until the
 * config file has been read.
 *
 * If 'safe' is true, use a default configuration that refrains
 * from opening files.  This is to avoid creating log files
 * as root.
 */

isc_result_t
ns_log_setdefaultchannels(isc_logconfig_t *lcfg);
/*%
 * Set up logging channels according to the named defaults, which
 * may differ from the logging library defaults.  Currently,
 * this just means setting up default_debug.
 */

isc_result_t
ns_log_setsafechannels(isc_logconfig_t *lcfg);
/*%
 * Like ns_log_setdefaultchannels(), but omits any logging to files.
 */

isc_result_t
ns_log_setdefaultcategory(isc_logconfig_t *lcfg);
/*%
 * Set up "category default" to go to the right places.
 */

isc_result_t
ns_log_setunmatchedcategory(isc_logconfig_t *lcfg);
/*%
 * Set up "category unmatched" to go to the right places.
 */

void
ns_log_shutdown(void);

#endif /* NAMED_LOG_H */
