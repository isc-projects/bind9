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

#ifndef NS_GLOBALS_H
#define NS_GLOBALS_H 1

#include <isc/types.h>
#include <isc/rwlock.h>

#include <dns/types.h>

#include <named/types.h>
#include <named/interfacemgr.h>

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
EXTERN ns_interfacemgr_t *	ns_g_interfacemgr	INIT(NULL);
EXTERN ns_clientmgr_t *		ns_g_clientmgr		INIT(NULL);
EXTERN char *			ns_g_version		INIT(VERSION);

EXTERN isc_rwlock_t		ns_g_viewlock;
EXTERN dns_viewlist_t		ns_g_views;

/* XXXRTH  This next one is temporary. */
EXTERN ns_dbinfolist_t		ns_g_dbs;

#undef EXTERN
#undef INIT

#endif /* NS_GLOBALS_H */
