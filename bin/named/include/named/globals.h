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

#ifndef NS_GLOBALS_H
#define NS_GLOBALS_H 1

#include <isc/types.h>
#include <isc/rwlock.h>
#include <isc/log.h>
#include <isc/net.h>

#include <dns/types.h>

#include <omapi/types.h>

#include <named/types.h>

#undef EXTERN
#undef INIT
#ifdef NS_MAIN
#define EXTERN
#define INIT(v)	= (v)
#else
#define EXTERN extern
#define INIT(v)
#endif

EXTERN isc_mem_t *		ns_g_mctx		INIT(NULL);
EXTERN unsigned int		ns_g_cpus		INIT(1);
EXTERN isc_taskmgr_t *		ns_g_taskmgr		INIT(NULL);
/*
 * XXXRTH  We're going to want multiple timer managers eventually.  One
 *         for really short timers, another for client timers, and one
 *         for zone timers.
 */
EXTERN isc_timermgr_t *		ns_g_timermgr		INIT(NULL);
EXTERN isc_socketmgr_t *	ns_g_socketmgr		INIT(NULL);
EXTERN omapi_object_t *		ns_g_omapimgr		INIT(NULL);
EXTERN char *			ns_g_version		INIT(VERSION);
EXTERN in_port_t		ns_g_port		INIT(53);

EXTERN ns_server_t *		ns_g_server		INIT(NULL);

/*
 * Logging.
 */
EXTERN isc_log_t *		ns_g_lctx		INIT(NULL);
EXTERN isc_logcategory_t *	ns_g_categories		INIT(NULL);
EXTERN isc_logmodule_t *	ns_g_modules		INIT(NULL);
EXTERN unsigned int		ns_g_debuglevel		INIT(0);

/*
 * Current config information
 */
EXTERN const char *		ns_g_conffile	INIT("/etc/named.conf");

/*
 * Misc.
 */
EXTERN isc_boolean_t		ns_g_coreok		INIT(ISC_TRUE);
EXTERN const char *		ns_g_chrootdir		INIT(NULL);
EXTERN isc_boolean_t		ns_g_foreground		INIT(ISC_FALSE);

EXTERN const char *		ns_g_defaultpidfile INIT("/var/run/named.pid");
EXTERN char *			ns_g_pidfile		INIT(NULL);
EXTERN const char *		ns_g_username		INIT(NULL);

/*
 * XXX  Temporary.
 */
EXTERN const char *		ns_g_cachefile		INIT(NULL);

#undef EXTERN
#undef INIT

#endif /* NS_GLOBALS_H */
