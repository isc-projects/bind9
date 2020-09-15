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

#ifndef NAMED_GLOBALS_H
#define NAMED_GLOBALS_H 1

/*! \file */

#include <stdbool.h>
#include <isc/rwlock.h>
#include <isc/log.h>
#include <isc/net.h>

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>

#include <dns/acl.h>
#include <dns/zone.h>

#include <dst/dst.h>

#include <named/types.h>
#include <named/fuzz.h>

#undef EXTERN
#undef INIT
#ifdef NS_MAIN
#define EXTERN
#define INIT(v)	= (v)
#else
#define EXTERN extern
#define INIT(v)
#endif

#ifndef NS_RUN_PID_DIR
#define NS_RUN_PID_DIR 1
#endif

EXTERN isc_mem_t *		ns_g_mctx		INIT(NULL);
EXTERN unsigned int		ns_g_cpus		INIT(0);
EXTERN unsigned int		ns_g_udpdisp		INIT(0);
EXTERN isc_taskmgr_t *		ns_g_taskmgr		INIT(NULL);
EXTERN dns_dispatchmgr_t *	ns_g_dispatchmgr	INIT(NULL);
EXTERN isc_entropy_t *		ns_g_entropy		INIT(NULL);
EXTERN isc_entropy_t *		ns_g_fallbackentropy	INIT(NULL);
EXTERN unsigned int		ns_g_cpus_detected	INIT(1);

#ifdef ENABLE_AFL
EXTERN bool		ns_g_run_done		INIT(false);
#endif
/*
 * XXXRTH  We're going to want multiple timer managers eventually.  One
 *         for really short timers, another for client timers, and one
 *         for zone timers.
 */
EXTERN isc_timermgr_t *		ns_g_timermgr		INIT(NULL);
EXTERN isc_socketmgr_t *	ns_g_socketmgr		INIT(NULL);
EXTERN cfg_parser_t *		ns_g_parser		INIT(NULL);
EXTERN cfg_parser_t *		ns_g_addparser		INIT(NULL);
EXTERN const char *		ns_g_version		INIT(VERSION);
EXTERN const char *		ns_g_product		INIT(PRODUCT);
EXTERN const char *		ns_g_description	INIT(DESCRIPTION);
EXTERN const char *		ns_g_srcid		INIT(SRCID);
EXTERN const char *		ns_g_configargs		INIT(CONFIGARGS);
EXTERN const char *		ns_g_builder		INIT(BUILDER);
EXTERN in_port_t		ns_g_port		INIT(0);
EXTERN isc_dscp_t		ns_g_dscp		INIT(-1);
EXTERN in_port_t		lwresd_g_listenport	INIT(0);

EXTERN ns_server_t *		ns_g_server		INIT(NULL);

EXTERN bool			ns_g_lwresdonly		INIT(false);

/*
 * Logging.
 */
EXTERN isc_log_t *		ns_g_lctx		INIT(NULL);
EXTERN isc_logcategory_t *	ns_g_categories		INIT(NULL);
EXTERN isc_logmodule_t *	ns_g_modules		INIT(NULL);
EXTERN unsigned int		ns_g_debuglevel		INIT(0);

/*
 * Current configuration information.
 */
EXTERN cfg_obj_t *		ns_g_config		INIT(NULL);
EXTERN const cfg_obj_t *	ns_g_defaults		INIT(NULL);
EXTERN const char *		ns_g_conffile		INIT(NS_SYSCONFDIR
							     "/named.conf");
EXTERN cfg_obj_t *		ns_g_bindkeys		INIT(NULL);
EXTERN const char *		ns_g_keyfile		INIT(NS_SYSCONFDIR
							     "/rndc.key");

EXTERN dns_tsigkey_t *		ns_g_sessionkey		INIT(NULL);
EXTERN dns_name_t		ns_g_sessionkeyname;

EXTERN const char *		lwresd_g_conffile	INIT(NS_SYSCONFDIR
							     "/lwresd.conf");
EXTERN const char *		lwresd_g_resolvconffile	INIT("/etc"
							     "/resolv.conf");
EXTERN bool			ns_g_conffileset	INIT(false);
EXTERN bool			lwresd_g_useresolvconf	INIT(false);
EXTERN uint16_t			ns_g_udpsize		INIT(4096);
EXTERN cfg_aclconfctx_t *	ns_g_aclconfctx		INIT(NULL);

/*
 * Initial resource limits.
 */
EXTERN isc_resourcevalue_t	ns_g_initstacksize	INIT(0);
EXTERN isc_resourcevalue_t	ns_g_initdatasize	INIT(0);
EXTERN isc_resourcevalue_t	ns_g_initcoresize	INIT(0);
EXTERN isc_resourcevalue_t	ns_g_initopenfiles	INIT(0);

/*
 * Misc.
 */
EXTERN bool			ns_g_coreok		INIT(true);
EXTERN const char *		ns_g_chrootdir		INIT(NULL);
EXTERN bool			ns_g_foreground		INIT(false);
EXTERN bool			ns_g_logstderr		INIT(false);
EXTERN bool			ns_g_nosyslog		INIT(false);
EXTERN const char *		ns_g_logfile		INIT(NULL);

EXTERN const char *		ns_g_defaultsessionkeyfile
					INIT(NS_LOCALSTATEDIR "/run/named/"
							      "session.key");
EXTERN const char *		ns_g_defaultlockfile	INIT(NS_LOCALSTATEDIR
							     "/run/named/"
							     "named.lock");
EXTERN bool			ns_g_forcelock		INIT(false);

#if NS_RUN_PID_DIR
EXTERN const char *		ns_g_defaultpidfile 	INIT(NS_LOCALSTATEDIR
							     "/run/named/"
							     "named.pid");
EXTERN const char *		lwresd_g_defaultpidfile INIT(NS_LOCALSTATEDIR
							     "/run/lwresd/"
							     "lwresd.pid");
#else
EXTERN const char *		ns_g_defaultpidfile 	INIT(NS_LOCALSTATEDIR
							     "/run/named.pid");
EXTERN const char *		lwresd_g_defaultpidfile INIT(NS_LOCALSTATEDIR
							     "/run/lwresd.pid");
#endif

EXTERN const char *		ns_g_username		INIT(NULL);

#if defined(USE_PKCS11)
EXTERN const char *		ns_g_engine		INIT(PKCS11_ENGINE);
#else
EXTERN const char *		ns_g_engine		INIT(NULL);
#endif

EXTERN int			ns_g_listen		INIT(3);
EXTERN isc_time_t		ns_g_boottime;
EXTERN isc_time_t		ns_g_configtime;
EXTERN bool			ns_g_memstatistics	INIT(false);
EXTERN bool			ns_g_clienttest		INIT(false);
EXTERN bool			ns_g_dropedns		INIT(false);
EXTERN bool			ns_g_ednsformerr	INIT(false);
EXTERN bool			ns_g_ednsnotimp		INIT(false);
EXTERN bool			ns_g_ednsrefused	INIT(false);
EXTERN bool			ns_g_noedns		INIT(false);
EXTERN bool			ns_g_nosoa		INIT(false);
EXTERN bool			ns_g_noaa		INIT(false);
EXTERN bool			ns_g_keepstderr		INIT(false);
EXTERN unsigned int		ns_g_delay		INIT(0);
EXTERN bool			ns_g_nonearest		INIT(false);
EXTERN bool			ns_g_notcp		INIT(false);
EXTERN bool			ns_g_disable6		INIT(false);
EXTERN bool			ns_g_disable4		INIT(false);
EXTERN unsigned int		ns_g_tat_interval	INIT(24*3600);
EXTERN bool			ns_g_fixedlocal		INIT(false);
EXTERN bool			ns_g_sigvalinsecs	INIT(false);

#if defined(HAVE_GEOIP) || defined(HAVE_GEOIP2)
EXTERN dns_geoip_databases_t	*ns_g_geoip		INIT(NULL);
#endif

EXTERN const char *		ns_g_fuzz_named_addr	INIT(NULL);
EXTERN ns_fuzz_t		ns_g_fuzz_type		INIT(ns_fuzz_none);

EXTERN dns_acl_t *		ns_g_mapped		INIT(NULL);

#undef EXTERN
#undef INIT

#endif /* NAMED_GLOBALS_H */
