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

#ifndef NS_LOG_H
#define NS_LOG_H 1

#include <isc/types.h>
#include <isc/log.h>

#include <dns/log.h>

#include <named/globals.h>

#define NS_LOGCATEGORY_GENERAL		(&ns_g_categories[0])
#define NS_LOGCATEGORY_CLIENT		(&ns_g_categories[1])
#define NS_LOGCATEGORY_NETWORK		(&ns_g_categories[2])
#define NS_LOGCATEGORY_UPDATE		(&ns_g_categories[3])
#define NS_LOGCATEGORY_XFER_IN		(&ns_g_categories[4])
#define NS_LOGCATEGORY_XFER_OUT		(&ns_g_categories[5])
#define NS_LOGCATEGORY_NOTIFY		(&ns_g_categories[6])

#define NS_LOGMODULE_MAIN		(&ns_g_modules[0])
#define NS_LOGMODULE_CLIENT		(&ns_g_modules[1])
#define NS_LOGMODULE_SERVER		(&ns_g_modules[2])
#define NS_LOGMODULE_QUERY		(&ns_g_modules[3])
#define NS_LOGMODULE_INTERFACEMGR	(&ns_g_modules[4])
#define NS_LOGMODULE_UPDATE		(&ns_g_modules[5])
#define NS_LOGMODULE_XFER_IN		(&ns_g_modules[6])
#define NS_LOGMODULE_XFER_OUT		(&ns_g_modules[7])
#define NS_LOGMODULE_NOTIFY		(&ns_g_modules[8])
#define NS_LOGMODULE_OMAPI		(&ns_g_modules[9])

isc_result_t
ns_log_init(void);

void
ns_log_shutdown(void);

#endif /* NS_LOG_H */
