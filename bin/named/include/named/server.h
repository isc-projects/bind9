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

#ifndef NAMED_SERVER_H
#define NAMED_SERVER_H 1

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/log.h>
#include <isc/magic.h>
#include <isc/quota.h>
#include <isc/sockaddr.h>
#include <isc/types.h>
#include <isc/xml.h>

#include <dns/acl.h>
#include <dns/dnstap.h>
#include <dns/types.h>

#include <named/types.h>

#define NS_EVENTCLASS		ISC_EVENTCLASS(0x4E43)
#define NS_EVENT_RELOAD		(NS_EVENTCLASS + 0)
#define NS_EVENT_CLIENTCONTROL	(NS_EVENTCLASS + 1)
#define NS_EVENT_DELZONE	(NS_EVENTCLASS + 2)
#define NS_EVENT_TATSEND	(NS_EVENTCLASS + 3)

/*%
 * Name server state.  Better here than in lots of separate global variables.
 */
struct ns_server {
	unsigned int		magic;
	isc_mem_t *		mctx;

	isc_task_t *		task;

	/* Configurable data. */
	isc_quota_t		xfroutquota;
	isc_quota_t		tcpquota;
	isc_quota_t		recursionquota;

	dns_acl_t		*blackholeacl;
	dns_acl_t		*keepresporder;
	char *			statsfile;	/*%< Statistics file name */
	char *			dumpfile;	/*%< Dump file name */
	char *			secrootsfile;	/*%< Secroots file name */
	char *			bindkeysfile;	/*%< bind.keys file name */
	char *			recfile;	/*%< Recursive file name */
	bool		version_set;	/*%< User has set version */
	char *			version;	/*%< User-specified version */
	bool		hostname_set;	/*%< User has set hostname */
	char *			hostname;	/*%< User-specified hostname */
	/*% Use hostname for server id */
	bool		server_usehostname;
	char *			server_id;	/*%< User-specified server id */

	/*%
	 * Current ACL environment.  This defines the
	 * current values of the localhost and localnets
	 * ACLs.
	 */
	dns_aclenv_t		aclenv;

	/* Server data structures. */
	dns_loadmgr_t *		loadmgr;
	dns_zonemgr_t *		zonemgr;
	dns_viewlist_t		viewlist;
	ns_interfacemgr_t *	interfacemgr;
	dns_db_t *		in_roothints;
	dns_tkeyctx_t *		tkeyctx;

	isc_timer_t *		interface_timer;
	isc_timer_t *		heartbeat_timer;
	isc_timer_t *		pps_timer;
	isc_timer_t *		tat_timer;

	uint32_t		interface_interval;
	uint32_t		heartbeat_interval;

	isc_mutex_t		reload_event_lock;
	isc_event_t *		reload_event;

	bool		flushonshutdown;
	bool		log_queries;	/*%< For BIND 8 compatibility */

	ns_cachelist_t		cachelist;	/*%< Possibly shared caches */
	isc_stats_t *		nsstats;	/*%< Server stats */
	dns_stats_t *		rcvquerystats;	/*% Incoming query stats */
	dns_stats_t *		opcodestats;	/*%< Incoming message stats */
	isc_stats_t *		zonestats;	/*% Zone management stats */
	isc_stats_t  *		resolverstats;	/*% Resolver stats */
	isc_stats_t *		sockstats;	/*%< Socket stats */
	isc_stats_t *		udpinstats4;	/*%< Traffic size: UDPv4 in */
	isc_stats_t *		udpoutstats4;	/*%< Traffic size: UDPv4 out */
	isc_stats_t *		udpinstats6;	/*%< Traffic size: UDPv6 in */
	isc_stats_t *		udpoutstats6;	/*%< Traffic size: UDPv6 out */
	isc_stats_t *		tcpinstats4;	/*%< Traffic size: TCPv4 in */
	isc_stats_t *		tcpoutstats4;	/*%< Traffic size: TCPv4 out */
	isc_stats_t *		tcpinstats6;	/*%< Traffic size: TCPv6 in */
	isc_stats_t *		tcpoutstats6;	/*%< Traffic size: TCPv6 out */
	dns_stats_t *		rcodestats;	/*%< Sent Response code stats */

	ns_controls_t *		controls;	/*%< Control channels */
	unsigned int		dispatchgen;
	ns_dispatchlist_t	dispatches;

	dns_acache_t		*acache;

	ns_statschannellist_t	statschannels;

	dns_tsigkey_t		*sessionkey;
	char			*session_keyfile;
	dns_name_t		*session_keyname;
	unsigned int		session_keyalg;
	uint16_t		session_keybits;
	bool		interface_auto;
	unsigned char		secret[32];	/*%< Server Cookie Secret */
	ns_altsecretlist_t	altsecrets;
	ns_cookiealg_t		cookiealg;
	bool		answercookie;

	dns_dtenv_t		*dtenv;		/*%< Dnstap environment */

	char *			lockfile;

	uint16_t		transfer_tcp_message_size;
};

struct ns_altsecret {
	ISC_LINK(ns_altsecret_t) link;
	unsigned char		secret[32];
};

#define NS_SERVER_MAGIC			ISC_MAGIC('S','V','E','R')
#define NS_SERVER_VALID(s)		ISC_MAGIC_VALID(s, NS_SERVER_MAGIC)

/*%
 * Server statistics counters.  Used as isc_statscounter_t values.
 */
enum {
	dns_nsstatscounter_requestv4 = 0,
	dns_nsstatscounter_requestv6 = 1,
	dns_nsstatscounter_edns0in = 2,
	dns_nsstatscounter_badednsver = 3,
	dns_nsstatscounter_tsigin = 4,
	dns_nsstatscounter_sig0in = 5,
	dns_nsstatscounter_invalidsig = 6,
	dns_nsstatscounter_requesttcp = 7,

	dns_nsstatscounter_authrej = 8,
	dns_nsstatscounter_recurserej = 9,
	dns_nsstatscounter_xfrrej = 10,
	dns_nsstatscounter_updaterej = 11,

	dns_nsstatscounter_response = 12,
	dns_nsstatscounter_truncatedresp = 13,
	dns_nsstatscounter_edns0out = 14,
	dns_nsstatscounter_tsigout = 15,
	dns_nsstatscounter_sig0out = 16,

	dns_nsstatscounter_success = 17,
	dns_nsstatscounter_authans = 18,
	dns_nsstatscounter_nonauthans = 19,
	dns_nsstatscounter_referral = 20,
	dns_nsstatscounter_nxrrset = 21,
	dns_nsstatscounter_servfail = 22,
	dns_nsstatscounter_formerr = 23,
	dns_nsstatscounter_nxdomain = 24,
	dns_nsstatscounter_recursion = 25,
	dns_nsstatscounter_duplicate = 26,
	dns_nsstatscounter_dropped = 27,
	dns_nsstatscounter_failure = 28,

	dns_nsstatscounter_xfrdone = 29,

	dns_nsstatscounter_updatereqfwd = 30,
	dns_nsstatscounter_updaterespfwd = 31,
	dns_nsstatscounter_updatefwdfail = 32,
	dns_nsstatscounter_updatedone = 33,
	dns_nsstatscounter_updatefail = 34,
	dns_nsstatscounter_updatebadprereq = 35,

	dns_nsstatscounter_recursclients = 36,

	dns_nsstatscounter_dns64 = 37,

	dns_nsstatscounter_ratedropped = 38,
	dns_nsstatscounter_rateslipped = 39,

	dns_nsstatscounter_rpz_rewrites = 40,

	dns_nsstatscounter_udp = 41,
	dns_nsstatscounter_tcp = 42,

	dns_nsstatscounter_nsidopt = 43,
	dns_nsstatscounter_expireopt = 44,
	dns_nsstatscounter_otheropt = 45,
	dns_nsstatscounter_ecsopt = 46,

	dns_nsstatscounter_nxdomainredirect = 47,
	dns_nsstatscounter_nxdomainredirect_rlookup = 48,

	dns_nsstatscounter_cookiein = 49,
	dns_nsstatscounter_cookiebadsize = 50,
	dns_nsstatscounter_cookiebadtime = 51,
	dns_nsstatscounter_cookienomatch = 52,
	dns_nsstatscounter_cookiematch = 53,
	dns_nsstatscounter_cookienew = 54,
	dns_nsstatscounter_badcookie = 55,

	dns_nsstatscounter_keytagopt = 56,

	dns_nsstatscounter_tcphighwater = 57,

	dns_nsstatscounter_reclimitdropped = 58,

	dns_nsstatscounter_max = 59
};

/*%
 * Traffic size statistics counters. Used as isc_statscounter_t values.
 */
enum {
	dns_sizecounter_in_0 = 0,
	dns_sizecounter_in_16 = 1,
	dns_sizecounter_in_32 = 2,
	dns_sizecounter_in_48 = 3,
	dns_sizecounter_in_64 = 4,
	dns_sizecounter_in_80 = 5,
	dns_sizecounter_in_96 = 6,
	dns_sizecounter_in_112 = 7,
	dns_sizecounter_in_128 = 8,
	dns_sizecounter_in_144 = 9,
	dns_sizecounter_in_160 = 10,
	dns_sizecounter_in_176 = 11,
	dns_sizecounter_in_192 = 12,
	dns_sizecounter_in_208 = 13,
	dns_sizecounter_in_224 = 14,
	dns_sizecounter_in_240 = 15,
	dns_sizecounter_in_256 = 16,
	dns_sizecounter_in_272 = 17,
	dns_sizecounter_in_288 = 18,

	dns_sizecounter_in_max = 19,
};

enum {
	dns_sizecounter_out_0 = 0,
	dns_sizecounter_out_16 = 1,
	dns_sizecounter_out_32 = 2,
	dns_sizecounter_out_48 = 3,
	dns_sizecounter_out_64 = 4,
	dns_sizecounter_out_80 = 5,
	dns_sizecounter_out_96 = 6,
	dns_sizecounter_out_112 = 7,
	dns_sizecounter_out_128 = 8,
	dns_sizecounter_out_144 = 9,
	dns_sizecounter_out_160 = 10,
	dns_sizecounter_out_176 = 11,
	dns_sizecounter_out_192 = 12,
	dns_sizecounter_out_208 = 13,
	dns_sizecounter_out_224 = 14,
	dns_sizecounter_out_240 = 15,
	dns_sizecounter_out_256 = 16,
	dns_sizecounter_out_272 = 17,
	dns_sizecounter_out_288 = 18,
	dns_sizecounter_out_304 = 19,
	dns_sizecounter_out_320 = 20,
	dns_sizecounter_out_336 = 21,
	dns_sizecounter_out_352 = 22,
	dns_sizecounter_out_368 = 23,
	dns_sizecounter_out_384 = 24,
	dns_sizecounter_out_400 = 25,
	dns_sizecounter_out_416 = 26,
	dns_sizecounter_out_432 = 27,
	dns_sizecounter_out_448 = 28,
	dns_sizecounter_out_464 = 29,
	dns_sizecounter_out_480 = 30,
	dns_sizecounter_out_496 = 31,
	dns_sizecounter_out_512 = 32,
	dns_sizecounter_out_528 = 33,
	dns_sizecounter_out_544 = 34,
	dns_sizecounter_out_560 = 35,
	dns_sizecounter_out_576 = 36,
	dns_sizecounter_out_592 = 37,
	dns_sizecounter_out_608 = 38,
	dns_sizecounter_out_624 = 39,
	dns_sizecounter_out_640 = 40,
	dns_sizecounter_out_656 = 41,
	dns_sizecounter_out_672 = 42,
	dns_sizecounter_out_688 = 43,
	dns_sizecounter_out_704 = 44,
	dns_sizecounter_out_720 = 45,
	dns_sizecounter_out_736 = 46,
	dns_sizecounter_out_752 = 47,
	dns_sizecounter_out_768 = 48,
	dns_sizecounter_out_784 = 49,
	dns_sizecounter_out_800 = 50,
	dns_sizecounter_out_816 = 51,
	dns_sizecounter_out_832 = 52,
	dns_sizecounter_out_848 = 53,
	dns_sizecounter_out_864 = 54,
	dns_sizecounter_out_880 = 55,
	dns_sizecounter_out_896 = 56,
	dns_sizecounter_out_912 = 57,
	dns_sizecounter_out_928 = 58,
	dns_sizecounter_out_944 = 59,
	dns_sizecounter_out_960 = 60,
	dns_sizecounter_out_976 = 61,
	dns_sizecounter_out_992 = 62,
	dns_sizecounter_out_1008 = 63,
	dns_sizecounter_out_1024 = 64,
	dns_sizecounter_out_1040 = 65,
	dns_sizecounter_out_1056 = 66,
	dns_sizecounter_out_1072 = 67,
	dns_sizecounter_out_1088 = 68,
	dns_sizecounter_out_1104 = 69,
	dns_sizecounter_out_1120 = 70,
	dns_sizecounter_out_1136 = 71,
	dns_sizecounter_out_1152 = 72,
	dns_sizecounter_out_1168 = 73,
	dns_sizecounter_out_1184 = 74,
	dns_sizecounter_out_1200 = 75,
	dns_sizecounter_out_1216 = 76,
	dns_sizecounter_out_1232 = 77,
	dns_sizecounter_out_1248 = 78,
	dns_sizecounter_out_1264 = 79,
	dns_sizecounter_out_1280 = 80,
	dns_sizecounter_out_1296 = 81,
	dns_sizecounter_out_1312 = 82,
	dns_sizecounter_out_1328 = 83,
	dns_sizecounter_out_1344 = 84,
	dns_sizecounter_out_1360 = 85,
	dns_sizecounter_out_1376 = 86,
	dns_sizecounter_out_1392 = 87,
	dns_sizecounter_out_1408 = 88,
	dns_sizecounter_out_1424 = 89,
	dns_sizecounter_out_1440 = 90,
	dns_sizecounter_out_1456 = 91,
	dns_sizecounter_out_1472 = 92,
	dns_sizecounter_out_1488 = 93,
	dns_sizecounter_out_1504 = 94,
	dns_sizecounter_out_1520 = 95,
	dns_sizecounter_out_1536 = 96,
	dns_sizecounter_out_1552 = 97,
	dns_sizecounter_out_1568 = 98,
	dns_sizecounter_out_1584 = 99,
	dns_sizecounter_out_1600 = 100,
	dns_sizecounter_out_1616 = 101,
	dns_sizecounter_out_1632 = 102,
	dns_sizecounter_out_1648 = 103,
	dns_sizecounter_out_1664 = 104,
	dns_sizecounter_out_1680 = 105,
	dns_sizecounter_out_1696 = 106,
	dns_sizecounter_out_1712 = 107,
	dns_sizecounter_out_1728 = 108,
	dns_sizecounter_out_1744 = 109,
	dns_sizecounter_out_1760 = 110,
	dns_sizecounter_out_1776 = 111,
	dns_sizecounter_out_1792 = 112,
	dns_sizecounter_out_1808 = 113,
	dns_sizecounter_out_1824 = 114,
	dns_sizecounter_out_1840 = 115,
	dns_sizecounter_out_1856 = 116,
	dns_sizecounter_out_1872 = 117,
	dns_sizecounter_out_1888 = 118,
	dns_sizecounter_out_1904 = 119,
	dns_sizecounter_out_1920 = 120,
	dns_sizecounter_out_1936 = 121,
	dns_sizecounter_out_1952 = 122,
	dns_sizecounter_out_1968 = 123,
	dns_sizecounter_out_1984 = 124,
	dns_sizecounter_out_2000 = 125,
	dns_sizecounter_out_2016 = 126,
	dns_sizecounter_out_2032 = 127,
	dns_sizecounter_out_2048 = 128,
	dns_sizecounter_out_2064 = 129,
	dns_sizecounter_out_2080 = 130,
	dns_sizecounter_out_2096 = 131,
	dns_sizecounter_out_2112 = 132,
	dns_sizecounter_out_2128 = 133,
	dns_sizecounter_out_2144 = 134,
	dns_sizecounter_out_2160 = 135,
	dns_sizecounter_out_2176 = 136,
	dns_sizecounter_out_2192 = 137,
	dns_sizecounter_out_2208 = 138,
	dns_sizecounter_out_2224 = 139,
	dns_sizecounter_out_2240 = 140,
	dns_sizecounter_out_2256 = 141,
	dns_sizecounter_out_2272 = 142,
	dns_sizecounter_out_2288 = 143,
	dns_sizecounter_out_2304 = 144,
	dns_sizecounter_out_2320 = 145,
	dns_sizecounter_out_2336 = 146,
	dns_sizecounter_out_2352 = 147,
	dns_sizecounter_out_2368 = 148,
	dns_sizecounter_out_2384 = 149,
	dns_sizecounter_out_2400 = 150,
	dns_sizecounter_out_2416 = 151,
	dns_sizecounter_out_2432 = 152,
	dns_sizecounter_out_2448 = 153,
	dns_sizecounter_out_2464 = 154,
	dns_sizecounter_out_2480 = 155,
	dns_sizecounter_out_2496 = 156,
	dns_sizecounter_out_2512 = 157,
	dns_sizecounter_out_2528 = 158,
	dns_sizecounter_out_2544 = 159,
	dns_sizecounter_out_2560 = 160,
	dns_sizecounter_out_2576 = 161,
	dns_sizecounter_out_2592 = 162,
	dns_sizecounter_out_2608 = 163,
	dns_sizecounter_out_2624 = 164,
	dns_sizecounter_out_2640 = 165,
	dns_sizecounter_out_2656 = 166,
	dns_sizecounter_out_2672 = 167,
	dns_sizecounter_out_2688 = 168,
	dns_sizecounter_out_2704 = 169,
	dns_sizecounter_out_2720 = 170,
	dns_sizecounter_out_2736 = 171,
	dns_sizecounter_out_2752 = 172,
	dns_sizecounter_out_2768 = 173,
	dns_sizecounter_out_2784 = 174,
	dns_sizecounter_out_2800 = 175,
	dns_sizecounter_out_2816 = 176,
	dns_sizecounter_out_2832 = 177,
	dns_sizecounter_out_2848 = 178,
	dns_sizecounter_out_2864 = 179,
	dns_sizecounter_out_2880 = 180,
	dns_sizecounter_out_2896 = 181,
	dns_sizecounter_out_2912 = 182,
	dns_sizecounter_out_2928 = 183,
	dns_sizecounter_out_2944 = 184,
	dns_sizecounter_out_2960 = 185,
	dns_sizecounter_out_2976 = 186,
	dns_sizecounter_out_2992 = 187,
	dns_sizecounter_out_3008 = 188,
	dns_sizecounter_out_3024 = 189,
	dns_sizecounter_out_3040 = 190,
	dns_sizecounter_out_3056 = 191,
	dns_sizecounter_out_3072 = 192,
	dns_sizecounter_out_3088 = 193,
	dns_sizecounter_out_3104 = 194,
	dns_sizecounter_out_3120 = 195,
	dns_sizecounter_out_3136 = 196,
	dns_sizecounter_out_3152 = 197,
	dns_sizecounter_out_3168 = 198,
	dns_sizecounter_out_3184 = 199,
	dns_sizecounter_out_3200 = 200,
	dns_sizecounter_out_3216 = 201,
	dns_sizecounter_out_3232 = 202,
	dns_sizecounter_out_3248 = 203,
	dns_sizecounter_out_3264 = 204,
	dns_sizecounter_out_3280 = 205,
	dns_sizecounter_out_3296 = 206,
	dns_sizecounter_out_3312 = 207,
	dns_sizecounter_out_3328 = 208,
	dns_sizecounter_out_3344 = 209,
	dns_sizecounter_out_3360 = 210,
	dns_sizecounter_out_3376 = 211,
	dns_sizecounter_out_3392 = 212,
	dns_sizecounter_out_3408 = 213,
	dns_sizecounter_out_3424 = 214,
	dns_sizecounter_out_3440 = 215,
	dns_sizecounter_out_3456 = 216,
	dns_sizecounter_out_3472 = 217,
	dns_sizecounter_out_3488 = 218,
	dns_sizecounter_out_3504 = 219,
	dns_sizecounter_out_3520 = 220,
	dns_sizecounter_out_3536 = 221,
	dns_sizecounter_out_3552 = 222,
	dns_sizecounter_out_3568 = 223,
	dns_sizecounter_out_3584 = 224,
	dns_sizecounter_out_3600 = 225,
	dns_sizecounter_out_3616 = 226,
	dns_sizecounter_out_3632 = 227,
	dns_sizecounter_out_3648 = 228,
	dns_sizecounter_out_3664 = 229,
	dns_sizecounter_out_3680 = 230,
	dns_sizecounter_out_3696 = 231,
	dns_sizecounter_out_3712 = 232,
	dns_sizecounter_out_3728 = 233,
	dns_sizecounter_out_3744 = 234,
	dns_sizecounter_out_3760 = 235,
	dns_sizecounter_out_3776 = 236,
	dns_sizecounter_out_3792 = 237,
	dns_sizecounter_out_3808 = 238,
	dns_sizecounter_out_3824 = 239,
	dns_sizecounter_out_3840 = 240,
	dns_sizecounter_out_3856 = 241,
	dns_sizecounter_out_3872 = 242,
	dns_sizecounter_out_3888 = 243,
	dns_sizecounter_out_3904 = 244,
	dns_sizecounter_out_3920 = 245,
	dns_sizecounter_out_3936 = 246,
	dns_sizecounter_out_3952 = 247,
	dns_sizecounter_out_3968 = 248,
	dns_sizecounter_out_3984 = 249,
	dns_sizecounter_out_4000 = 250,
	dns_sizecounter_out_4016 = 251,
	dns_sizecounter_out_4032 = 252,
	dns_sizecounter_out_4048 = 253,
	dns_sizecounter_out_4064 = 254,
	dns_sizecounter_out_4080 = 255,
	dns_sizecounter_out_4096 = 256,

	dns_sizecounter_out_max = 257
};

void
ns_server_create(isc_mem_t *mctx, ns_server_t **serverp);
/*%<
 * Create a server object with default settings.
 * This function either succeeds or causes the program to exit
 * with a fatal error.
 */

void
ns_server_destroy(ns_server_t **serverp);
/*%<
 * Destroy a server object, freeing its memory.
 */

void
ns_server_reloadwanted(ns_server_t *server);
/*%<
 * Inform a server that a reload is wanted.  This function
 * may be called asynchronously, from outside the server's task.
 * If a reload is already scheduled or in progress, the call
 * is ignored.
 */

void
ns_server_scan_interfaces(ns_server_t *server);
/*%<
 * Trigger a interface scan.
 * Must only be called when running under server->task.
 */

void
ns_server_flushonshutdown(ns_server_t *server, bool flush);
/*%<
 * Inform the server that the zones should be flushed to disk on shutdown.
 */

isc_result_t
ns_server_reloadcommand(ns_server_t *server, isc_lex_t *lex,
			isc_buffer_t **text);
/*%<
 * Act on a "reload" command from the command channel.
 */

isc_result_t
ns_server_reconfigcommand(ns_server_t *server);
/*%<
 * Act on a "reconfig" command from the command channel.
 */

isc_result_t
ns_server_notifycommand(ns_server_t *server, isc_lex_t *lex,
			isc_buffer_t **text);
/*%<
 * Act on a "notify" command from the command channel.
 */

isc_result_t
ns_server_refreshcommand(ns_server_t *server, isc_lex_t *lex,
			 isc_buffer_t **text);
/*%<
 * Act on a "refresh" command from the command channel.
 */

isc_result_t
ns_server_retransfercommand(ns_server_t *server, isc_lex_t *lex,
			    isc_buffer_t **text);
/*%<
 * Act on a "retransfer" command from the command channel.
 */

isc_result_t
ns_server_togglequerylog(ns_server_t *server, isc_lex_t *lex);
/*%<
 * Enable/disable logging of queries.  (Takes "yes" or "no" argument,
 * but can also be used as a toggle for backward comptibility.)
 */

/*%
 * Save the current NTAs for all views to files.
 */
isc_result_t
ns_server_saventa(ns_server_t *server);

/*%
 * Load NTAs for all views from files.
 */
isc_result_t
ns_server_loadnta(ns_server_t *server);

/*%
 * Dump the current statistics to the statistics file.
 */
isc_result_t
ns_server_dumpstats(ns_server_t *server);

/*%
 * Dump the current cache to the dump file.
 */
isc_result_t
ns_server_dumpdb(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Dump the current security roots to the secroots file.
 */
isc_result_t
ns_server_dumpsecroots(ns_server_t *server, isc_lex_t *lex,
		       isc_buffer_t **text);

/*%
 * Change or increment the server debug level.
 */
isc_result_t
ns_server_setdebuglevel(ns_server_t *server, isc_lex_t *lex);

/*%
 * Flush the server's cache(s)
 */
isc_result_t
ns_server_flushcache(ns_server_t *server, isc_lex_t *lex);

/*%
 * Flush a particular name from the server's cache.  If 'tree' is false,
 * also flush the name from the ADB and badcache.  If 'tree' is true, also
 * flush all the names under the specified name.
 */
isc_result_t
ns_server_flushnode(ns_server_t *server, isc_lex_t *lex,
		    bool tree);

/*%
 * Report the server's status.
 */
isc_result_t
ns_server_status(ns_server_t *server, isc_buffer_t **text);

/*%
 * Report a list of dynamic and static tsig keys, per view.
 */
isc_result_t
ns_server_tsiglist(ns_server_t *server, isc_buffer_t **text);

/*%
 * Delete a specific key (with optional view).
 */
isc_result_t
ns_server_tsigdelete(ns_server_t *server, isc_lex_t *lex,
		     isc_buffer_t **text);

/*%
 * Enable or disable updates for a zone.
 */
isc_result_t
ns_server_freeze(ns_server_t *server, bool freeze,
		 isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Dump zone updates to disk, optionally removing the journal file
 */
isc_result_t
ns_server_sync(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Update a zone's DNSKEY set from the key repository.  If
 * the command that triggered the call to this function was "sign",
 * then force a full signing of the zone.  If it was "loadkeys",
 * then don't sign the zone; any needed changes to signatures can
 * take place incrementally.
 */
isc_result_t
ns_server_rekey(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Dump the current recursive queries.
 */
isc_result_t
ns_server_dumprecursing(ns_server_t *server);

/*%
 * Maintain a list of dispatches that require reserved ports.
 */
void
ns_add_reserved_dispatch(ns_server_t *server, const isc_sockaddr_t *addr);

/*%
 * Enable or disable dnssec validation.
 */
isc_result_t
ns_server_validation(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Add a zone to a running process, or modify an existing zone
 */
isc_result_t
ns_server_changezone(ns_server_t *server, char *command, isc_buffer_t **text);

/*%
 * Deletes a zone from a running process
 */
isc_result_t
ns_server_delzone(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Show current configuration for a given zone
 */
isc_result_t
ns_server_showzone(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Lists the status of the signing records for a given zone.
 */
isc_result_t
ns_server_signing(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Lists status information for a given zone (e.g., name, type, files,
 * load time, expiry, etc).
 */
isc_result_t
ns_server_zonestatus(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Adds/updates a Negative Trust Anchor (NTA) for a specified name and
 * duration, in a particular view if specified, or in all views.
 */
isc_result_t
ns_server_nta(ns_server_t *server, isc_lex_t *lex, bool readonly,
	      isc_buffer_t **text);

/*%
 * Generates a test sequence that is only for use in system tests. The
 * argument is the size of required output in bytes.
 */
isc_result_t
ns_server_testgen(isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Force fefresh or print status for managed keys zones.
 */
isc_result_t
ns_server_mkeys(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

/*%
 * Close and reopen DNSTAP output file.
 */
isc_result_t
ns_server_dnstap(ns_server_t *server, isc_lex_t *lex, isc_buffer_t **text);

#endif /* NAMED_SERVER_H */
