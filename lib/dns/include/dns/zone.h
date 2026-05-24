/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file dns/zone.h */

/***
 ***	Imports
 ***/

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <isc/formatcheck.h>
#include <isc/rwlock.h>
#include <isc/tls.h>

#include <dns/catz.h>
#include <dns/diff.h>
#include <dns/master.h>
#include <dns/masterdump.h>
#include <dns/rdatastruct.h>
#include <dns/rpz.h>
#include <dns/skr.h>
#include <dns/types.h>
#include <dns/xfrin.h>
#include <dns/zt.h>

/* Add -DDNS_ZONE_TRACE=1 to CFLAGS for detailed reference tracing */

typedef enum {
	dns_zone_none,
	dns_zone_primary,
	dns_zone_secondary,
	dns_zone_mirror,
	dns_zone_stub,
	dns_zone_staticstub,
	dns_zone_key,
	dns_zone_dlz,
	dns_zone_redirect
} dns_zonetype_t;

#ifndef dns_zone_master
#define dns_zone_master dns_zone_primary
#endif /* dns_zone_master */

#ifndef dns_zone_slave
#define dns_zone_slave dns_zone_secondary
#endif /* dns_zone_slave */

typedef enum {
	dns_zonestat_none = 0,
	dns_zonestat_terse,
	dns_zonestat_full
} dns_zonestat_level_t;

typedef enum {
	DNS_ZONEOPT_MANYERRORS = 1 << 0,    /*%< return many errors on load */
	DNS_ZONEOPT_IXFRFROMDIFFS = 1 << 1, /*%< calculate differences */
	DNS_ZONEOPT_NOMERGE = 1 << 2,	    /*%< don't merge journal */
	DNS_ZONEOPT_CHECKNS = 1 << 3,	    /*%< check if NS's are addresses */
	DNS_ZONEOPT_FATALNS = 1 << 4,	    /*%< DNS_ZONEOPT_CHECKNS is fatal */
	DNS_ZONEOPT_MULTIMASTER = 1 << 5,   /*%< this zone has multiple
						 primaries */
	DNS_ZONEOPT_USEALTXFRSRC = 1 << 6,  /*%< use alternate transfer sources.
						 Obsoleted. */
	DNS_ZONEOPT_CHECKNAMES = 1 << 7,    /*%< check-names */
	DNS_ZONEOPT_CHECKNAMESFAIL = 1 << 8, /*%< fatal check-name failures */
	DNS_ZONEOPT_CHECKWILDCARD = 1 << 9, /*%< check for internal wildcards */
	DNS_ZONEOPT_CHECKMX = 1 << 10,	    /*%< check-mx */
	DNS_ZONEOPT_CHECKMXFAIL = 1 << 11,  /*%< fatal check-mx failures */
	DNS_ZONEOPT_CHECKINTEGRITY = 1 << 12, /*%< perform integrity checks */
	DNS_ZONEOPT_CHECKSIBLING = 1 << 13, /*%< perform sibling glue checks */
	DNS_ZONEOPT_NOCHECKNS = 1 << 14,    /*%< disable IN NS address checks */
	DNS_ZONEOPT_WARNMXCNAME = 1 << 15,  /*%< warn on MX CNAME check */
	DNS_ZONEOPT_IGNOREMXCNAME = 1 << 16,  /*%< ignore MX CNAME check */
	DNS_ZONEOPT_WARNSRVCNAME = 1 << 17,   /*%< warn on SRV CNAME check */
	DNS_ZONEOPT_IGNORESRVCNAME = 1 << 18, /*%< ignore SRV CNAME check */
	DNS_ZONEOPT_UPDATECHECKKSK = 1 << 19, /*%< check dnskey KSK flag */
	DNS_ZONEOPT_TRYTCPREFRESH = 1 << 20, /*%< try tcp refresh on udp failure
					      */
	DNS_ZONEOPT_NOTIFYTOSOA = 1 << 21,   /*%< Notify the SOA MNAME */
	DNS_ZONEOPT_NSEC3TESTZONE = 1 << 22, /*%< nsec3-test-zone */
	DNS_ZONEOPT_LOGREPORTS = 1 << 23,    /* Log error-reporting queries */
	DNS_ZONEOPT_DNSKEYKSKONLY = 1 << 24, /*%< dnssec-dnskey-kskonly */
	DNS_ZONEOPT_CHECKDUPRR = 1 << 25,    /*%< check-dup-records */
	DNS_ZONEOPT_CHECKDUPRRFAIL = 1 << 26, /*%< fatal check-dup-records
					       * failures */
	DNS_ZONEOPT_CHECKSPF = 1 << 27,	      /*%< check SPF records */
	DNS_ZONEOPT_CHECKTTL = 1 << 28,	      /*%< check max-zone-ttl */
	DNS_ZONEOPT_AUTOEMPTY = 1 << 29,      /*%< automatic empty zone */
	DNS_ZONEOPT_CHECKSVCB = 1 << 30,      /*%< check SVBC records */
	DNS_ZONEOPT_ZONEVERSION = 1U << 31,   /*%< enable zoneversion */
	DNS_ZONEOPT_FULLSIGN = 1ULL << 32,    /*%< fully sign zone */
	DNS_ZONEOPT_FORCEKEYMGR = 1ULL << 33, /*%< force keymgr step */
	DNS_ZONEOPT___MAX = UINT64_MAX, /* trick to make the ENUM 64-bit wide */
} dns_zoneopt_t;

/*
 * Zone states
 */
typedef enum {
	DNS_ZONESTATE_XFERRUNNING = 1,
	DNS_ZONESTATE_XFERDEFERRED,
	DNS_ZONESTATE_XFERFIRSTREFRESH,
	DNS_ZONESTATE_SOAQUERY,
	DNS_ZONESTATE_ANY,
	DNS_ZONESTATE_AUTOMATIC,
} dns_zonestate_t;

#ifndef DNS_ZONE_MINREFRESH
#define DNS_ZONE_MINREFRESH 300 /*%< 5 minutes */
#endif				/* ifndef DNS_ZONE_MINREFRESH */
#ifndef DNS_ZONE_MAXREFRESH
#define DNS_ZONE_MAXREFRESH 2419200 /*%< 4 weeks */
#endif				    /* ifndef DNS_ZONE_MAXREFRESH */
#ifndef DNS_ZONE_DEFAULTREFRESH
#define DNS_ZONE_DEFAULTREFRESH 3600 /*%< 1 hour */
#endif				     /* ifndef DNS_ZONE_DEFAULTREFRESH */
#ifndef DNS_ZONE_MINRETRY
#define DNS_ZONE_MINRETRY 300 /*%< 5 minutes */
#endif			      /* ifndef DNS_ZONE_MINRETRY */
#ifndef DNS_ZONE_MAXRETRY
#define DNS_ZONE_MAXRETRY 1209600 /*%< 2 weeks */
#endif				  /* ifndef DNS_ZONE_MAXRETRY */
#ifndef DNS_ZONE_DEFAULTRETRY
#define DNS_ZONE_DEFAULTRETRY        \
	60 /*%< 1 minute, subject to \
	    * exponential backoff */
#endif	   /* ifndef DNS_ZONE_DEFAULTRETRY */

/***
 ***	Functions
 ***/

void
dns_zone_create(dns_zone_t **zonep, isc_mem_t *mctx, isc_tid_t tid);
/*%<
 *	Creates a new empty zone and attach '*zonep' to it.
 *
 * Requires:
 *\li	'zonep' to point to a NULL pointer.
 *\li	'mctx' to be a valid memory context.
 *
 * Ensures:
 *\li	'*zonep' refers to a valid zone.
 */

isc_result_t
dns_zone_makedb(dns_zone_t *zone, dns_db_t **dbp);
/*%<
 *	Creates a new empty database for the 'zone'.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 *\li	'dbp' to point to NULL pointer.
 *
 * Returns:
 *\li	dns_db_create() error codes.
 */

isc_result_t
dns_zone_getserial(dns_zone_t *zone, uint32_t *serialp);
/*%<
 *	Returns the current serial number of the zone.  On success, the SOA
 *	serial of the zone will be copied into '*serialp'.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 *\li	'serialp' to be non NULL
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#DNS_R_NOTLOADED	zone DB is not loaded
 */

void
dns_zone_setviewcommit(dns_zone_t *zone);
/*%<
 *	Commit the previous view saved internally via dns_zone_setview().
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setviewrevert(dns_zone_t *zone);
/*%<
 *	Revert the most recent dns_zone_setview() on this zone,
 *	restoring the previous view.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_lock_keyfiles(dns_zone_t *zone);
/*%<
 *	Lock associated keyfiles for this zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_unlock_keyfiles(dns_zone_t *zone);
/*%<
 *	Unlock associated keyfiles for this zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zone_dnskey_inuse(dns_zone_t *zone, dns_rdata_t *rdata, bool *inuse);
/*%<
 *	Check if the DNSKEY record 'rdata' is used by 'zone' for zone signing.
 *	Store the result in 'inuse'.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'rdata' to represent a DNSKEY, CDNSKEY, or CDS record.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	Any error result from dns_dnssec_keyfromrdata, dns_rdata_tostruct,
 *	dns_dnssec_make_dnskey, dns_ds_buildrdata, or
 *	dns_dnssec_findmatchingkeys.
 *
 */

isc_result_t
dns_zone_load(dns_zone_t *zone, bool newonly);

isc_result_t
dns_zone_loadandthaw(dns_zone_t *zone);

/*%<
 *	Cause the database to be loaded from its backing store.
 *	Confirm that the minimum requirements for the zone type are
 *	met, otherwise DNS_R_BADZONE is returned.
 *
 *	If newonly is set dns_zone_load() only loads new zones.
 *	dns_zone_loadandthaw() is similar to dns_zone_load() but will
 *	also re-enable DNS UPDATEs when the load completes.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	#ISC_R_UNEXPECTED
 *\li	#ISC_R_SUCCESS
 *\li	DNS_R_CONTINUE	  Incremental load has been queued.
 *\li	ISC_R_LOADING	  Load was already in progress.
 *\li	DNS_R_UPTODATE	  The zone has already been loaded based on
 *			  file system timestamps.
 *\li	DNS_R_BADZONE
 *\li	Any result value from dns_db_load().
 */

isc_result_t
dns_zone_asyncload(dns_zone_t *zone, bool newonly, dns_zt_callback_t done,
		   void *arg);
/*%<
 * Cause the database to be loaded from its backing store asynchronously.
 * Other zone maintenance functions are suspended until this is complete.
 * When finished, 'done' is called to inform the caller, with 'arg' as
 * its argument. (Normally, 'arg' is expected to point to the zone table
 * but is left undefined for testing purposes.)
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	#ISC_R_ALREADYRUNNING
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_FAILURE
 */

bool
dns__zone_loadpending(dns_zone_t *zone);
/*%<
 * Indicates whether the zone is waiting to be loaded asynchronously.
 * (Not currently intended for use outside of this module and associated
 * tests.)
 */

void
dns_zone_iattach(dns_zone_t *source, dns_zone_t **target);
/*%<
 *	Attach '*target' to 'source' incrementing its internal
 * 	reference count.  This is intended for use by operations
 * 	such as zone transfers that need to prevent the zone
 * 	object from being freed but not from shutting down.
 *
 * Require:
 *\li	The caller is running in the context of the zone's loop.
 *\li	'zone' to be a valid zone.
 *\li	'target' to be non NULL and '*target' to be NULL.
 */

void
dns_zone_idetach(dns_zone_t **zonep);
/*%<
 *	Detach from a zone decrementing its internal reference count.
 *	If there are no more internal or external references to the
 * 	zone, it will be freed.
 *
 * Require:
 *\li	The caller is running in the context of the zone's loop.
 *\li	'zonep' to point to a valid zone.
 */

void
dns_zone_markdirty(dns_zone_t *zone);
/*%<
 *	Mark a zone as 'dirty'.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_refresh(dns_zone_t *zone);
/*%<
 *	Initiate zone up to date checks.  The zone must already be being
 *	managed.
 *
 * Require
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zone_flush(dns_zone_t *zone);
/*%<
 *	Write the zone to database if there are uncommitted changes.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zone_dumptostream(dns_zone_t *zone, FILE *fd, dns_masterformat_t format,
		      const dns_master_style_t *style,
		      const uint32_t		rawversion);
/*%<
 *    Write the zone to stream 'fd' in the specified 'format'.
 *
 *    If 'format' is dns_masterformat_text (RFC1035), 'style'
 *    specifies the file style (e.g., &dns_master_style_default),
 *    and 'rawversion' is ignored.
 *
 *    If 'format' is dns_masterformat_raw, 'style' is ignored, and
 *    'rawversion" specifies the format version of the raw zone file:
 *    version 0 raw files can be read by all BIND 9 releases;
 *    version 1 was introduced in BIND 9.9.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'fd' to be a stream open for writing.
 */

void
dns_zone_unload(dns_zone_t *zone);
/*%<
 *	detach the database from the zone structure.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zone_dnssecstatus(dns_zone_t *zone, dns_kasp_t *kasp,
		      dns_dnsseckeylist_t *keys, isc_stdtime_t now,
		      bool verbose, char *out, size_t out_len);
/*%<
 * Retrieve the DNSSEC status of given 'zone' and store the printable output
 * in the 'out' buffer.
 *
 *      Requires:
 *\li           'zone' is not NULL.
 *\li           'kasp' is not NULL.
 *\li           'keys' is not NULL.
 *\li           'out' is not NULL.
 *
 *      Returns:
 *\li           ISC_R_SUCCESS on success.
 *\li           ISC_R_NOSPACE if the 'out' buffer is too small.
 *\li           ISC_R_FAILURE if other error occurred.
 *\li           Printable status in 'out'.
 *
 */

dns_skrbundle_t *
dns_zone_getskrbundle(dns_zone_t *zone);
/*%<
 *	Returns the current SKR bundle.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setoption(dns_zone_t *zone, dns_zoneopt_t option, bool value);
/*%<
 *	Set the given options on ('value' == true) or off
 *	('value' == #false).
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

dns_zoneopt_t
dns_zone_getoptions(dns_zone_t *zone);
/*%<
 *	Returns the current zone options.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zone_notifyreceive(dns_zone_t *zone, isc_sockaddr_t *from,
		       isc_sockaddr_t *to, dns_message_t *msg);
/*%<
 *	Tell the zone that it has received a NOTIFY message from another
 *	server.  This may cause some zone maintenance activity to occur.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 *\li	'*from' to contain the address of the server from which 'msg'
 *		was received.
 *\li	'msg' a message with opcode NOTIFY and qr clear.
 *
 * Returns:
 *\li	DNS_R_REFUSED
 *\li	DNS_R_NOTIMP
 *\li	DNS_R_FORMERR
 *\li	DNS_R_SUCCESS
 */

dns_zonetype_t
dns_zone_getredirecttype(dns_zone_t *zone);
/*%<
 * Returns whether the redirect zone is configured as a primary or a
 * secondary zone.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *\li	'zone' to be a redirect zone.
 *
 * Returns:
 *\li	'dns_zone_primary'
 *\li	'dns_zone_secondary'
 */

void
dns_zone_notify(dns_zone_t *zone, bool nodefer);
/*%<
 * Generate notify events for this zone. If 'nodefer' is true, the
 * 'notify-defer' configuration option is ingored.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zone_replacedb(dns_zone_t *zone, dns_db_t *db, bool dump);
/*%<
 * Replace the database of "zone" with a new database "db".
 *
 * If "dump" is true, then the new zone contents are dumped
 * into to the zone's master file for persistence.  When replacing
 * a zone database by one just loaded from a master file, set
 * "dump" to false to avoid a redundant redump of the data just
 * loaded.  Otherwise, it should be set to true.
 *
 * If the "diff-on-reload" option is enabled in the configuration file,
 * the differences between the old and the new database are added to the
 * journal file, and the master file dump is postponed.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 *
 * Returns:
 * \li	DNS_R_SUCCESS
 * \li	DNS_R_BADZONE	zone failed basic consistency checks:
 *			* a single SOA must exist
 *			* some NS records must exist.
 *	Others
 */

isc_result_t
dns_zone_forwardupdate(dns_zone_t *zone, dns_message_t *msg,
		       dns_updatecallback_t callback, void *callback_arg);
/*%<
 * Forward 'msg' to each primary in turn until we get an answer or we
 * have exhausted the list of primaries. 'callback' will be called with
 * ISC_R_SUCCESS if we get an answer and the returned message will be
 * passed as 'answer_message', otherwise a non ISC_R_SUCCESS result code
 * will be passed and answer_message will be NULL.  The callback function
 * is responsible for destroying 'answer_message'.
 *		(callback)(callback_arg, result, answer_message);
 *
 * Require:
 *\li	'zone' to be valid
 *\li	'msg' to be valid.
 *\li	'callback' to be non NULL.
 * Returns:
 *\li	#ISC_R_SUCCESS if the message has been forwarded,
 *\li	Others
 */

isc_result_t
dns_zone_getdnsseckeys(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *ver,
		       isc_stdtime_t now, dns_dnsseckeylist_t *keys);
/*%<
 * Find DNSSEC keys used for signing with dnssec-policy. Load these keys
 * into 'keys'.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *\li	'keys' to be an initialised DNSSEC keylist.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	Error
 */

isc_result_t
dns_zone_findkeys(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *ver,
		  isc_stdtime_t now, isc_mem_t *mctx, unsigned int maxkeys,
		  dst_key_t **keys, unsigned int *nkeys);
/*%<
 * Finds a set of zone keys. Searches in the applicable key stores for the
 * given 'zone' if there is a dnssec-policy attached, otherwise it looks up
 * the keys in the zone's key-directory. The found keys are loaded into 'keys'.
 *
 * Requires:
 *\li	'zone' to be a valid initialised zone.
 *\li	'mctx' is not NULL.
 *\li	'keys' is not NULL and has enough space for 'nkeys' keys.
 *\li	'nkeys' is not NULL.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	Error
 */

void
dns_zone_prepare_shutdown(dns_zone_t *zone);
/*%<
 * Prepare a zone for shutdown by setting the DNS_ZONEFLG_EXITING flag even
 * before the final reference is detached. Useful, because the zone object can
 * be kept around with a valid reference from the zonetable until qp garbage
 * collector runs, and we don't want, for example, zone maintenance to happen
 * while waiting for it. Note that the zone can not be used normally again after
 * this function is called.
 *
 * Requires:
 *\li	'zone' to be a valid initialised zone.
 */

isc_result_t
dns_zone_getxfr(dns_zone_t *zone, dns_xfrin_t **xfrp, bool *is_firstrefresh,
		bool *is_running, bool *is_deferred, bool *is_presoa,
		bool *is_pending, bool *needs_refresh);
/*%<
 *	Returns the xfrin associated with the zone (if any) with the current
 * 	transfer states (as booleans). When no longer needed, the returned xfrin
 * 	must be detached.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 *\li	'xfrp' to be non NULL and '*xfrp' to be NULL.
 *\li	'is_firstrefresh' to be non NULL.
 *\li	'is_running' to be non NULL.
 *\li	'is_deferred' to be non NULL.
 *\li	'is_presoa' to be non NULL.
 *\li	'is_pending' to be non NULL.
 *\li	'needs_refresh' to be non NULL.
 *
 * Returns:
 *	ISC_R_SUCCESS	transfer information is returned
 *	ISC_R_FAILURE	error while trying to get the transfer information
 */

void
dns_zone_stopxfr(dns_zone_t *zone);
/*%<
 *      If 'zone' has an ongoing active transfer, stop it.
 *
 * Requires:
 *\li      'zone' to be a valid zone.
 */

void
dns_zone_forcexfr(dns_zone_t *zone);
/*%<
 *      Force a zone transfer of the specified zone.
 *
 * Requires:
 *\li      'zone' to be a valid zone.
 */

bool
dns_zone_isforced(dns_zone_t *zone);
/*%<
 *      Check if the zone is waiting a forced reload.
 *
 * Requires:
 * \li     'zone' to be a valid zone.
 */

void
dns_zone_logv(dns_zone_t *zone, isc_logcategory_t category, int level,
	      const char *prefix, const char *msg, va_list ap);
/*%<
 * Log the message 'msg...' at 'level' using log category 'category', including
 * text that identifies the message as applying to 'zone'.  If the (optional)
 * 'prefix' is not NULL, it will be placed at the start of the entire log line.
 */

void
dns_zone_log(dns_zone_t *zone, int level, const char *msg, ...)
	ISC_FORMAT_PRINTF(3, 4);
/*%<
 * Log the message 'msg...' at 'level', including text that identifies
 * the message as applying to 'zone'.
 */

void
dns_zone_logc(dns_zone_t *zone, isc_logcategory_t category, int level,
	      const char *msg, ...) ISC_FORMAT_PRINTF(4, 5);
/*%<
 * Log the message 'msg...' at 'level', including text that identifies
 * the message as applying to 'zone'.
 */

isc_result_t
dns_zone_checknames(dns_zone_t *zone, const dns_name_t *name,
		    dns_rdata_t *rdata);
/*%<
 * Check if this record meets the check-names policy.
 *
 * Requires:
 *	'zone' to be valid.
 *	'name' to be valid.
 *	'rdata' to be valid.
 *
 * Returns:
 *	DNS_R_SUCCESS		passed checks.
 *	DNS_R_BADOWNERNAME	failed ownername checks.
 *	DNS_R_BADNAME		failed rdata checks.
 */

isc_result_t
dns_zone_addnsec3chain(dns_zone_t *zone, dns_rdata_nsec3param_t *nsec3param);
/*%<
 * Incrementally add a NSEC3 chain that corresponds to 'nsec3param'.
 */

void
dns_zone_rekey(dns_zone_t *zone, bool fullsign, bool forcekeymgr);
/*%<
 * Update the zone's DNSKEY set from the key repository.
 *
 * If 'fullsign' is true, trigger an immediate full signing of
 * the zone with the new key.  Otherwise, if there are no keys or
 * if the new keys are for algorithms that have already signed the
 * zone, then the zone can be re-signed incrementally.
 *
 * If 'forcekeymgr' is true, trigger a rekey event and allow the
 * next steps in the run to happen.
 */

isc_result_t
dns_zone_nscheck(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *version,
		 unsigned int *errors);
/*%
 * Check if the name servers for the zone are sane (have address, don't
 * refer to CNAMEs/DNAMEs.  The number of constiancy errors detected in
 * returned in '*errors'
 *
 * Requires:
 * \li	'zone' to be valid.
 * \li	'db' to be valid.
 * \li	'version' to be valid or NULL.
 * \li	'errors' to be non NULL.
 *
 * Returns:
 * 	ISC_R_SUCCESS if there were no errors examining the zone contents.
 */

isc_result_t
dns_zone_cdscheck(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *version);
/*%
 * Check if CSD, CDNSKEY and DNSKEY are consistent.
 *
 * Requires:
 * \li	'zone' to be valid.
 * \li	'db' to be valid.
 * \li	'version' to be valid or NULL.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	#DNS_R_BADCDS
 *\li	#DNS_R_BADCDNSKEY
 *	Others
 */

isc_result_t
dns_zone_dlzpostload(dns_zone_t *zone, dns_db_t *db);
/*%
 * Load the origin names for a writeable DLZ database.
 */

bool
dns_zone_isdynamic(dns_zone_t *zone, bool ignore_freeze);
/*%
 * Return true iff the zone is "dynamic", in the sense that the zone's
 * master file (if any) is written by the server, rather than being
 * updated manually and read by the server.
 *
 * This is true for secondary zones, stub zones, key zones, and zones that
 * allow dynamic updates either by having an update policy ("ssutable")
 * or an "allow-update" ACL with a value other than exactly "{ none; }".
 *
 * If 'ignore_freeze' is true, then the zone which has had updates disabled
 * will still report itself to be dynamic.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

isc_result_t
dns_zone_link(dns_zone_t *zone, dns_zone_t *raw);

void
dns_zone_getraw(dns_zone_t *zone, dns_zone_t **raw);

bool
dns_zone_israw(dns_zone_t *zone);

bool
dns_zone_issecure(dns_zone_t *zone);

isc_result_t
dns_zone_keydone(dns_zone_t *zone, const char *data);
/*%<
 * Delete the private-type record from the top of the zone
 * which indicates that signing is complete with the key matching
 * 'data'; this is invoked by 'rndc signing -clear'.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

isc_result_t
dns_zone_setnsec3param(dns_zone_t *zone, uint8_t hash, uint8_t flags,
		       uint16_t iter, isc_region_t *salt, bool replace,
		       bool resalt);
/*%<
 * Set the NSEC3 parameters for the zone.
 *
 * If 'replace' is true, then the existing NSEC3 chain, if any, will
 * be replaced with the new one.  If 'hash' is zero, then the replacement
 * chain will be NSEC rather than NSEC3. If 'resalt' is true, or if 'salt'
 * is NULL, generate a new salt with the given salt length.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setrawdata(dns_zone_t *zone, dns_masterrawheader_t *header);
/*%
 * Set the data to be included in the header when the zone is dumped in
 * binary format.
 */

isc_result_t
dns_zone_synckeyzone(dns_zone_t *zone);
/*%
 * Force the managed key zone to synchronize, and start the key
 * maintenance timer.
 */

unsigned int
dns_zone_getincludes(dns_zone_t *zone, char ***includesp);
/*%
 * Return the number include files that were encountered
 * during load.  If the number is greater than zero, 'includesp'
 * will point to an array containing the filenames.
 *
 * The array and its contents need to be freed using isc_mem_free.
 */

isc_result_t
dns_zone_rpz_enable(dns_zone_t *zone, dns_rpz_zones_t *rpzs,
		    dns_rpz_num_t rpz_num);
/*%
 * Set the response policy associated with a zone.
 */

void
dns_zone_rpz_enable_db(dns_zone_t *zone, dns_db_t *db);
/*%
 * If a zone is a response policy zone, mark its new database.
 */

dns_rpz_num_t
dns_zone_get_rpz_num(dns_zone_t *zone);

void
dns_zone_catz_enable(dns_zone_t *zone, dns_catz_zones_t *catzs);
/*%<
 * Enable zone as catalog zone.
 *
 * Requires:
 *
 * \li	'zone' is a valid zone object
 * \li	'catzs' is not NULL
 * \li	prior to calling, zone->catzs is NULL or is equal to 'catzs'
 */

void
dns_zone_catz_disable(dns_zone_t *zone);
/*%<
 * Disable zone as catalog zone, if it is one.  Also disables any
 * registered callbacks for the catalog zone.
 *
 * Requires:
 *
 * \li	'zone' is a valid zone object
 */

bool
dns_zone_catz_is_enabled(dns_zone_t *zone);
/*%<
 * Return a boolean indicating whether the zone is enabled as catalog zone.
 *
 * Requires:
 *
 * \li	'zone' is a valid zone object
 */

void
dns_zone_catz_enable_db(dns_zone_t *zone, dns_db_t *db);
/*%<
 * If 'zone' is a catalog zone, then set up a notify-on-update trigger
 * in its database. (If not a catalog zone, this function has no effect.)
 *
 * Requires:
 *
 * \li	'zone' is a valid zone object
 * \li	'db' is not NULL
 */
void
dns_zone_set_parentcatz(dns_zone_t *zone, dns_catz_zone_t *catz);
/*%<
 * Set parent catalog zone for this zone
 *
 * Requires:
 *
 * \li	'zone' is a valid zone object
 * \li	'catz' is not NULL
 */

dns_catz_zone_t *
dns_zone_get_parentcatz(dns_zone_t *zone);
/*%<
 * Get parent catalog zone for this zone
 *
 * Requires:
 *
 * \li	'zone' is a valid zone object
 */

isc_result_t
dns_zone_setserial(dns_zone_t *zone, uint32_t serial);
/*%
 * Set the zone's serial to 'serial'.
 */

bool
dns_zone_isloaded(dns_zone_t *zone);
/*%<
 * Return true if 'zone' was loaded and has not expired yet, return
 * false otherwise.
 */

isc_result_t
dns_zone_verifydb(dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *ver);
/*%<
 * If 'zone' is a mirror zone, perform DNSSEC validation of version 'ver' of
 * its database, 'db'.  Ensure that the DNSKEY RRset at zone apex is signed by
 * at least one trust anchor specified for the view that 'zone' is assigned to.
 * If 'ver' is NULL, use the current version of 'db'.
 *
 * If 'zone' is not a mirror zone, return ISC_R_SUCCESS immediately.
 *
 * Returns:
 *
 * \li	#ISC_R_SUCCESS		either 'zone' is not a mirror zone or 'zone' is
 *				a mirror zone and all DNSSEC checks succeeded
 *				and the DNSKEY RRset at zone apex is signed by
 *				a trusted key
 *
 * \li	#DNS_R_VERIFYFAILURE	any other case
 */

const char *
dns_zonetype_name(dns_zonetype_t type);
/*%<
 * Return the name of the zone type 'type'.
 */

bool
dns_zone_check_dnskey_nsec3(dns_zone_t *zone, dns_db_t *db,
			    dns_dbversion_t *ver, dns_diff_t *diff,
			    dst_key_t **keys, unsigned int numkeys);
/**<
 * Return whether the zone would enter an inconsistent state where NSEC only
 * DNSKEYs are present along NSEC3 chains.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'db' is not NULL.
 *
 * Returns:
 * \li	'true' if the check passes, that is the zone remains consistent,
 *	'false' if the zone would have NSEC only DNSKEYs and an NSEC3 chain.
 */

isc_result_t
dns_zone_import_skr(dns_zone_t *zone, const char *file);
/**<
 * Import a Signed Key Response (SKR) from file.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'file' is not NULL.
 *
 * Returns:
 * \li  ISC_R_SUCCESS if there were no errors loading the SKR.
 */

isc_result_t
dns_zone_getzoneversion(dns_zone_t *zone, isc_buffer_t *b);
/**<
 * Return the EDNS ZONEVERSION for this zone.
 *
 * Note: For type SERIAL a buffer of at least 6 octets is required.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'b' to be a valid buffer.
 *
 * Returns
 * \li	ISC_R_SUCCESS if the zone is loaded and supports ZONEVERSION.
 * \li	ISC_R_NOSPACE if the buffer is too small.
 * \li	DNS_R_NOTLOADED if the database is not loaded.
 * \li	ISC_R_FAILURE other failure.
 */

void
dns_zonemgr_setkeystores(dns_zonemgr_t *zmgr, dns_keystorelist_t *keystores);
/**<
 * Set the global setting keystores into the zonemgr, so it can be used from the
 * DNS code.
 *
 * Requires:
 * \li	'zmgr' to be a valid.
 * \li  'keystores' to be a valid.
 */

void
dns_zone_setplugins(dns_zone_t *zone, void *plugins,
		    void (*plugins_free)(isc_mem_t *, void **));
/**<
 * Initialize zone plugins owning list and free callback
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li  'plugins' to be initialized.
 * \li  'plugins_free' to be valid.
 */

void
dns_zone_unloadplugins(dns_zone_t *zone);
/**<
 * Unload all plugins attached to this zone, and free the hooktable as well as
 * the plugins list.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

bool
dns_zone_isexpired(dns_zone_t *zone);
/*%<
 * Return true if a (secondary, mirror, etc.) zone is expired
 *
 * Requires:
 * \li  'zone\ to be a valid zone.
 */

#if DNS_ZONE_TRACE
#define dns_zone_ref(ptr)   dns_zone__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_zone_unref(ptr) dns_zone__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_zone_attach(ptr, ptrp) \
	dns_zone__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_zone_detach(ptrp) \
	dns_zone__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(dns_zone);
#else
ISC_REFCOUNT_DECL(dns_zone);
#endif
