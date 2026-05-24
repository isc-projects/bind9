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

/*! \file dns/zoneproperties.h */

#include <isc/statsmulti.h>

#include <dns/view.h>
#include <dns/zone.h>

void
dns_zone_setclass(dns_zone_t *zone, dns_rdataclass_t rdclass);
/*%<
 *	Sets the class of a zone.  This operation can only be performed
 *	once on a zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	dns_zone_setclass() not to have been called since the zone was
 *	created.
 *\li	'rdclass' != dns_rdataclass_none.
 */

dns_rdataclass_t
dns_zone_getclass(dns_zone_t *zone);
/*%<
 *	Returns the current zone class.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_settype(dns_zone_t *zone, dns_zonetype_t type);
/*%<
 *	Sets the zone type. This operation can only be performed once on
 *	a zone.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 *\li	dns_zone_settype() not to have been called since the zone was
 *	created.
 *\li	'type' != dns_zone_none
 */

void
dns_zone_setview(dns_zone_t *zone, dns_view_t *view);
/*%<
 *	Associate the zone with a view.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

dns_view_t *
dns_zone_getview(dns_zone_t *zone);
/*%<
 *	Returns the zone's associated view.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setorigin(dns_zone_t *zone, const dns_name_t *origin);
/*%<
 *	Sets the zones origin to 'origin'.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'origin' to be non NULL.
 */

dns_name_t *
dns_zone_getorigin(dns_zone_t *zone);
/*%<
 *	Returns the value of the origin.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setfile(dns_zone_t *zone, const char *file, const char *initial_file,
		 dns_masterformat_t format, const dns_master_style_t *style);
/*%<
 *    Sets the name of the master file in the format of 'format' from which
 *    the zone loads its database to 'file'.
 *
 *    For zones that have no associated master file, 'file' will be NULL.
 *    For some zone types, e.g. secondary zones, 'file' is optional, but
 *    for primary zones it is mandatory. If the master file does not exist
 *    during loading, then it will be copied into place from 'initial_file'.
 *
 *    For zones with persistent databases, the file name setting is ignored.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

const char *
dns_zone_getfile(dns_zone_t *zone);
/*%<
 * 	Gets the name of the zone's master file, if any.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	Pointer to null-terminated file name, or NULL.
 */

void
dns_zone_setstream(dns_zone_t *zone, const FILE *stream,
		   dns_masterformat_t format, const dns_master_style_t *style);
/*%<
 *    Sets the source stream from which the zone will load its database.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 *\li	'stream' to be a valid and open FILE *.
 *\li	'zone->masterfile' to be NULL, since we should load data either from
 *	'stream' or from a master file, but not both.
 */

void
dns_zone_setmaxrecords(dns_zone_t *zone, uint32_t records);
/*%<
 * 	Sets the maximum number of records permitted in a zone.
 *	0 implies unlimited.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	void
 */

uint32_t
dns_zone_getmaxrecords(dns_zone_t *zone);
/*%<
 * 	Gets the maximum number of records permitted in a zone.
 *	0 implies unlimited.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	uint32_t maxrecords.
 */

void
dns_zone_setmaxrrperset(dns_zone_t *zone, uint32_t maxrrperset);
/*%<
 * 	Sets the maximum number of records per rrset permitted in a zone.
 *	0 implies unlimited.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	void
 */

void
dns_zone_setmaxtypepername(dns_zone_t *zone, uint32_t maxtypepername);
/*%<
 * 	Sets the maximum number of resource record types per owner name
 *	permitted in a zone.  0 implies unlimited.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	void
 */

void
dns_zone_setmaxttl(dns_zone_t *zone, uint32_t maxttl);
/*%<
 * 	Sets the max ttl of the zone.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	void
 */

dns_ttl_t
dns_zone_getmaxttl(dns_zone_t *zone);
/*%<
 * 	Gets the max ttl of the zone.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *\li	dns_ttl_t maxttl.
 */

isc_result_t
dns_zone_getdb(dns_zone_t *zone, dns_db_t **dbp);
/*%<
 * 	Attach '*dbp' to the database to if it exists otherwise
 *	return DNS_R_NOTLOADED.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'dbp' to be != NULL && '*dbp' == NULL.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *\li	DNS_R_NOTLOADED
 */

void
dns_zone_setdb(dns_zone_t *zone, dns_db_t *db);
/*%<
 *	Sets the zone database to 'db'.
 *
 *	This function is expected to be used to configure a zone with a
 *	database which is not loaded from a file or zone transfer.
 *	It can be used for a general purpose zone, but right now its use
 *	is limited to static-stub zones to avoid possible undiscovered
 *	problems in the general cases.
 *
 * Require:
 *\li	'zone' to be a valid zone of static-stub.
 *\li	zone doesn't have a database.
 */

void
dns_zone_setdbtype(dns_zone_t *zone, unsigned int dbargc,
		   const char *const *dbargv);
/*%<
 *	Sets the database type to dbargv[0] and database arguments
 *	to subsequent dbargv elements.
 *	'db_type' is not checked to see if it is a valid database type.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'database' to be non NULL.
 *\li	'dbargc' to be >= 1
 *\li	'dbargv' to point to dbargc NULL-terminated strings
 */

void
dns_zone_getdbtype(dns_zone_t *zone, char ***argv, isc_mem_t *mctx);
/*%<
 *	Returns the current dbtype.  isc_mem_free() should be used
 * 	to free 'argv' after use.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'argv' to be non NULL and *argv to be NULL.
 *\li	'mctx' to be valid.
 */

void
dns_zone_setprimaries(dns_zone_t *zone, isc_sockaddr_t *addresses,
		      isc_sockaddr_t *sources, dns_name_t **keynames,
		      dns_name_t **tlsnames, uint32_t count);
/*%<
 *	Set the list of primary servers for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'addresses' array of isc_sockaddr_t with port set or NULL.
 *\li	'count' the number of primaries.
 *\li	'keynames' array of dns_name_t's for tsig keys or NULL.
 *
 *\li	If 'addresses' is NULL then 'count' must be zero.
 */

void
dns_zone_setparentals(dns_zone_t *zone, isc_sockaddr_t *addresses,
		      isc_sockaddr_t *sources, dns_name_t **keynames,
		      dns_name_t **tlsnames, uint32_t count);
/*%<
 *	Set the list of parental agents for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'addresses' array of isc_sockaddr_t with port set or NULL.
 *\li	'count' the number of primaries.
 *\li	'keynames' array of dns_name_t's for tsig keys or NULL.
 *
 *\li	If 'addresses' is NULL then 'count' must be zero.
 */

void
dns_zone_setalsonotify(dns_zone_t *zone, isc_sockaddr_t *addresses,
		       isc_sockaddr_t *sources, dns_name_t **keynames,
		       dns_name_t **tlsnames, uint32_t count);
/*%<
 *	Set the list of additional servers to be notified when
 *	a zone changes.	 To clear the list use 'count = 0'.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'addresses' to be non-NULL if count != 0.
 *\li	'count' to be the number of notifiees.
 */

void
dns_zone_setcdsendpoints(dns_zone_t *zone, isc_sockaddr_t *addresses,
			 isc_sockaddr_t *sources, dns_name_t **keynames,
			 dns_name_t **tlsnames, uint32_t count);
/*%<
 *	Set the list of servers to be notified when the zone changes
 *	its CDS/CDNSKEY RRset. To clear the list use 'count = 0'.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'addresses' to be non-NULL if count != 0.
 *\li	'count' to be the number of notifiees.
 */

dns_kasp_t *
dns_zone_getkasp(dns_zone_t *zone);
/*%<
 *	Returns the current kasp.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setkasp(dns_zone_t *zone, dns_kasp_t *kasp);
void
dns_zone_setdefaultkasp(dns_zone_t *zone, dns_kasp_t *kasp);
/*%<
 *	Set kasp for zone.  If a kasp is already set, it will be detached.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setminrefreshtime(dns_zone_t *zone, uint32_t val);
/*%<
 *	Set the minimum refresh time.
 *
 * Requires:
 *\li	'zone' is valid.
 *\li	val > 0.
 */

void
dns_zone_setmaxrefreshtime(dns_zone_t *zone, uint32_t val);
/*%<
 *	Set the maximum refresh time.
 *
 * Requires:
 *\li	'zone' is valid.
 *\li	val > 0.
 */

void
dns_zone_setminretrytime(dns_zone_t *zone, uint32_t val);
/*%<
 *	Set the minimum retry time.
 *
 * Requires:
 *\li	'zone' is valid.
 *\li	val > 0.
 */

void
dns_zone_setmaxretrytime(dns_zone_t *zone, uint32_t val);
/*%<
 *	Set the maximum retry time.
 *
 * Requires:
 *\li	'zone' is valid.
 *	val > 0.
 */

void
dns_zone_setxfrsource4(dns_zone_t *zone, const isc_sockaddr_t *xfrsource);
/*%<
 * 	Set the source address to be used in IPv4 zone transfers.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'xfrsource' to contain the address.
 */

void
dns_zone_getxfrsource4(dns_zone_t *zone, isc_sockaddr_t *xfrsource);
/*%<
 *	Returns the source address set by a previous dns_zone_setxfrsource4
 *	call, or the default of inaddr_any, port 0.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'xfrsource' to not be NULL
 */

void
dns_zone_setxfrsource6(dns_zone_t *zone, const isc_sockaddr_t *xfrsource);
/*%<
 * 	Set the source address to be used in IPv6 zone transfers.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'xfrsource' to contain the address.
 */

void
dns_zone_getxfrsource6(dns_zone_t *zone, isc_sockaddr_t *xfrsource);
/*%<
 *	Returns the source address set by a previous dns_zone_setxfrsource6
 *	call, or the default of in6addr_any, port 0.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'xfrsource' to not be NULL
 */

void
dns_zone_setparentalsrc4(dns_zone_t *zone, const isc_sockaddr_t *parentalsrc);
/*%<
 * 	Set the source address to be used with IPv4 parental DS queries.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'parentalsrc' to contain the address.
 */

void
dns_zone_getparentalsrc4(dns_zone_t *zone, isc_sockaddr_t *parentalsrc);
/*%<
 *	Returns the source address set by a previous dns_zone_setparentalsrc4
 *	call, or the default of inaddr_any, port 0.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'parentalsrc' to be non NULL.
 */

void
dns_zone_setparentalsrc6(dns_zone_t *zone, const isc_sockaddr_t *parentalsrc);
/*%<
 * 	Set the source address to be used with IPv6 parental DS queries.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'parentalsrc' to contain the address.
 */

void
dns_zone_getparentalsrc6(dns_zone_t *zone, isc_sockaddr_t *parentalsrc);
/*%<
 *	Returns the source address set by a previous dns_zone_setparentalsrc6
 *	call, or the default of in6addr_any, port 0.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'parentalsrc' to be non NULL.
 */

void
dns_zone_setnotifysrc4(dns_zone_t *zone, dns_rdatatype_t type,
		       const isc_sockaddr_t *notifysrc);
/*%<
 * 	Set the source address to be used with IPv4 NOTIFY messages.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'type' to be a valid notify RRtype.
 *\li	'notifysrc' to contain the address.
 */

void
dns_zone_setnotifysrc6(dns_zone_t *zone, dns_rdatatype_t type,
		       const isc_sockaddr_t *notifysrc);
/*%<
 * 	Set the source address to be used with IPv6 NOTIFY messages.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'type' to be a valid notify RRtype.
 *\li	'notifysrc' to contain the address.
 */

void
dns_zone_setnotifyacl(dns_zone_t *zone, dns_acl_t *acl);
/*%<
 *	Sets the notify acl list for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'acl' to be a valid acl.
 */

void
dns_zone_setqueryacl(dns_zone_t *zone, dns_acl_t *acl);
/*%<
 *	Sets the query acl list for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'acl' to be a valid acl.
 */

void
dns_zone_setqueryonacl(dns_zone_t *zone, dns_acl_t *acl);
/*%<
 *	Sets the query-on acl list for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'acl' to be a valid acl.
 */

void
dns_zone_setupdateacl(dns_zone_t *zone, dns_acl_t *acl);
/*%<
 *	Sets the update acl list for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'acl' to be valid acl.
 */

void
dns_zone_setforwardacl(dns_zone_t *zone, dns_acl_t *acl);
/*%<
 *	Sets the forward unsigned updates acl list for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'acl' to be valid acl.
 */

void
dns_zone_setxfracl(dns_zone_t *zone, dns_acl_t *acl);
/*%<
 *	Sets the transfer acl list for the zone.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'acl' to be valid acl.
 */

dns_acl_t *
dns_zone_getqueryacl(dns_zone_t *zone);
/*%<
 * 	Returns the current query acl or NULL.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	acl a pointer to the acl.
 *\li	NULL
 */

dns_acl_t *
dns_zone_getqueryonacl(dns_zone_t *zone);
/*%<
 * 	Returns the current query-on acl or NULL.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	acl a pointer to the acl.
 *\li	NULL
 */

dns_acl_t *
dns_zone_getupdateacl(dns_zone_t *zone);
/*%<
 * 	Returns the current update acl or NULL.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	acl a pointer to the acl.
 *\li	NULL
 */

dns_acl_t *
dns_zone_getforwardacl(dns_zone_t *zone);
/*%<
 * 	Returns the current forward unsigned updates acl or NULL.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	acl a pointer to the acl.
 *\li	NULL
 */

dns_acl_t *
dns_zone_getxfracl(dns_zone_t *zone);
/*%<
 * 	Returns the current transfer acl or NULL.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *
 * Returns:
 *\li	acl a pointer to the acl.
 *\li	NULL
 */

void
dns_zone_clearupdateacl(dns_zone_t *zone);
/*%<
 *	Clear the current update acl.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_clearforwardacl(dns_zone_t *zone);
/*%<
 *	Clear the current forward unsigned updates acl.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_clearnotifyacl(dns_zone_t *zone);
/*%<
 *	Clear the current notify acl.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_clearqueryacl(dns_zone_t *zone);
/*%<
 *	Clear the current query acl.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_clearqueryonacl(dns_zone_t *zone);
/*%<
 *	Clear the current query-on acl.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_clearxfracl(dns_zone_t *zone);
/*%<
 *	Clear the current transfer acl.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

bool
dns_zone_getupdatedisabled(dns_zone_t *zone);
/*%<
 * Return true if updates are disabled.
 */

void
dns_zone_setupdatedisabled(dns_zone_t *zone, bool state);
/*%<
 * Enable or disable updates.
 *
 * This should only be called when running in exclusive mode;
 * otherwise, updates that were already in progress could be
 * committed after disabling.
 */

bool
dns_zone_getzeronosoattl(dns_zone_t *zone);
/*%<
 * Return zero-no-soa-ttl status.
 */

void
dns_zone_setzeronosoattl(dns_zone_t *zone, bool state);
/*%<
 * Set zero-no-soa-ttl status.
 */

void
dns_zone_setchecknames(dns_zone_t *zone, dns_severity_t severity);
/*%<
 * 	Set the severity of name checking when loading a zone.
 *
 * Require:
 * \li     'zone' to be a valid zone.
 */

dns_severity_t
dns_zone_getchecknames(dns_zone_t *zone);
/*%<
 *	Return the current severity of name checking.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setjournalsize(dns_zone_t *zone, int32_t size);
/*%<
 *	Sets the journal size for the zone.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

int32_t
dns_zone_getjournalsize(dns_zone_t *zone);
/*%<
 *	Return the journal size as set with a previous call to
 *	dns_zone_setjournalsize().
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

void
dns_zone_setminxfrratein(dns_zone_t *zone, uint32_t bytes, uint32_t seconds);
/*%<
 * Set the minumum traffic rate (in bytes per seconds) that a zone transfer in
 * (AXFR/IXFR) of this zone will use before being aborted.
 *
 * Requires:
 * \li	'zone' to be valid initialised zone.
 */

uint32_t
dns_zone_getminxfrratebytesin(dns_zone_t *zone);
/*%<
 * Returns the 'bytes' portion of the minimum traffic rate for the transfer in
 * for this zone.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 */

uint32_t
dns_zone_getminxfrratesecondsin(dns_zone_t *zone);
/*%<
 * Returns the 'seconds' portion of the minimum traffic rate for the transfer in
 * for this zone.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 */

void
dns_zone_setmaxxfrin(dns_zone_t *zone, uint32_t maxxfrin);
/*%<
 * Set the maximum time (in seconds) that a zone transfer in (AXFR/IXFR)
 * of this zone will use before being aborted.
 *
 * Requires:
 * \li	'zone' to be valid initialised zone.
 */

uint32_t
dns_zone_getmaxxfrin(dns_zone_t *zone);
/*%<
 * Returns the maximum transfer time for this zone.  This will be
 * either the value set by the last call to dns_zone_setmaxxfrin() or
 * the default value of 1 hour.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 */

void
dns_zone_setmaxxfrout(dns_zone_t *zone, uint32_t maxxfrout);
/*%<
 * Set the maximum time (in seconds) that a zone transfer out (AXFR/IXFR)
 * of this zone will use before being aborted.
 *
 * Requires:
 * \li	'zone' to be valid initialised zone.
 */

uint32_t
dns_zone_getmaxxfrout(dns_zone_t *zone);
/*%<
 * Returns the maximum transfer time for this zone.  This will be
 * either the value set by the last call to dns_zone_setmaxxfrout() or
 * the default value of 1 hour.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 */

void
dns_zone_setjournal(dns_zone_t *zone, const char *myjournal);
/*%<
 * Sets the filename used for journaling updates / IXFR transfers.
 * The default journal name is set by dns_zone_setfile() to be
 * "file.jnl".  If 'myjournal' is NULL, the zone will have no
 * journal name.
 *
 * Requires:
 *\li	'zone' to be a valid zone.
 */

char *
dns_zone_getjournal(dns_zone_t *zone);
/*%<
 * Returns the journal name associated with this zone.
 * If no journal has been set this will be NULL.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 */

dns_zonetype_t
dns_zone_gettype(dns_zone_t *zone);
/*%<
 * Returns the type of the zone (primary/secondary/etc.)
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 */

uint32_t
dns_zone_getidlein(dns_zone_t *zone);
/*%<
 * Requires:
 * \li	'zone' to be a valid zone.
 *
 * Returns:
 * \li	number of seconds of idle time before we abort the transfer in.
 */

void
dns_zone_setidlein(dns_zone_t *zone, uint32_t idlein);
/*%<
 * \li	Set the idle timeout for transfer the.
 * \li	Zero set the default value, 1 hour.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

uint32_t
dns_zone_getidleout(dns_zone_t *zone);
/*%<
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 *
 * Returns:
 * \li	number of seconds of idle time before we abort a transfer out.
 */

void
dns_zone_setidleout(dns_zone_t *zone, uint32_t idleout);
/*%<
 * \li	Set the idle timeout for transfers out.
 * \li	Zero set the default value, 1 hour.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_getssutable(dns_zone_t *zone, dns_ssutable_t **table);
/*%<
 * Get the simple-secure-update policy table.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_setssutable(dns_zone_t *zone, dns_ssutable_t *table);
/*%<
 * Set / clear the simple-secure-update policy table.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

isc_mem_t *
dns_zone_getmctx(dns_zone_t *zone);
/*%<
 * Get the memory context of a zone.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

dns_zonemgr_t *
dns_zone_getmgr(dns_zone_t *zone);
/*%<
 *	If 'zone' is managed return the zone manager otherwise NULL.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_setsigvalidityinterval(dns_zone_t *zone, uint32_t interval);
/*%<
 * Set the zone's general signature validity interval.  This is the length
 * of time for which DNSSEC signatures created as a result of dynamic
 * updates to secure zones will remain valid, in seconds.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

uint32_t
dns_zone_getsigvalidityinterval(dns_zone_t *zone);
/*%<
 * Get the zone's general signature validity interval.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_setkeyvalidityinterval(dns_zone_t *zone, uint32_t interval);
/*%<
 * Set the zone's DNSKEY signature validity interval.  This is the length
 * of time for which DNSSEC signatures created for DNSKEY records
 * will remain valid, in seconds.
 *
 * If this value is set to zero, then the regular signature validity
 * interval (see dns_zone_setsigvalidityinterval(), above) is used
 * for all RRSIGs. However, if this value is nonzero, then it is used
 * as the validity interval for RRSIGs covering DNSKEY and CDNSKEY
 * RRsets.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

uint32_t
dns_zone_getkeyvalidityinterval(dns_zone_t *zone);
/*%<
 * Get the zone's DNSKEY signature validity interval.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_setsigresigninginterval(dns_zone_t *zone, uint32_t interval);
/*%<
 * Set the zone's RRSIG re-signing interval.  A dynamic zone's RRSIG's
 * will be re-signed 'interval' amount of time before they expire.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

uint32_t
dns_zone_getsigresigninginterval(dns_zone_t *zone);
/*%<
 * Get the zone's RRSIG re-signing interval.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_getsourceaddr(dns_zone_t *zone, isc_sockaddr_t *sourceaddr);
/*%<
 * Get the zone's source address from which it has last contacted the current
 * primary server.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'zone' has a non-empty primaries list.
 * \li	'sourceaddr' to be non-NULL.
 */

isc_result_t
dns_zone_getprimaryaddr(dns_zone_t *zone, isc_sockaddr_t *primaryaddr);
/*%<
 * Get the zone's current primary server into '*primaryaddr'.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'zone' has a non-empty primaries list.
 * \li	'primaryaddr' to be non-NULL.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS if the current primary server was found
 *\li	#ISC_R_NOMORE if all the primaries were already iterated over
 */

isc_time_t
dns_zone_getxfrintime(dns_zone_t *zone);
/*%<
 * Get the start time of the zone's latest major step before an incoming zone
 * transfer is initiated. The time is set to the current time before the
 * precursory SOA query is queued, then it gets reset when the query starts,
 * when the query restarts (using another transport or another primary server),
 * when an incoming zone transfer is initated and deferred, and, finally, when
 * it gets started.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_setnotifytype(dns_zone_t *zone, dns_rdatatype_t type,
		       dns_notifytype_t notifytype);
/*%<
 * Sets zone notify(type) method to "notifytype"
 */

void
dns_zone_setcheckdstype(dns_zone_t *zone, dns_checkdstype_t checkdstype);
/*%<
 * Sets zone checkds method to "checkdstype"
 */

void
dns_zone_setkeydirectory(dns_zone_t *zone, const char *directory);
/*%<
 *	Sets the name of the directory where private keys used for
 *	online signing or dynamic zones are found.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

const char *
dns_zone_getkeydirectory(dns_zone_t *zone);
/*%<
 * 	Gets the name of the directory where private keys used for
 *	online signing of dynamic zones are found.
 *
 * Requires:
 *\li	'zone' to be valid initialised zone.
 *
 * Returns:
 *	Pointer to null-terminated file name, or NULL.
 */

void
dns_zone_setstats(dns_zone_t *zone, isc_stats_t *stats);
/*%<
 * Set a general zone-maintenance statistics set 'stats' for 'zone'.  This
 * function is expected to be called only on zone creation (when necessary).
 * Once installed, it cannot be removed or replaced.  Also, there is no
 * interface to get the installed stats from the zone; the caller must keep the
 * stats to reference (e.g. dump) it later.
 *
 * Requires:
 * \li	'zone' to be a valid zone and does not have a statistics set already
 *	installed.
 *
 *\li	stats is a valid statistics supporting zone statistics counters
 *	(see dns/stats.h).
 */

void
dns_zone_setrequeststats(dns_zone_t *zone, isc_stats_t *stats);

void
dns_zone_setrcvquerystats(dns_zone_t *zone, isc_statsmulti_t *stats);

void
dns_zone_setdnssecsignstats(dns_zone_t *zone, dns_stats_t *stats);
/*%<
 * Set additional statistics sets to zone.  These are attached to the zone
 * but are not counted in the zone module; only the caller updates the
 * counters.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 *
 *\li	stats is a valid statistics.
 */

isc_stats_t *
dns_zone_getrequeststats(dns_zone_t *zone);

isc_statsmulti_t *
dns_zone_getrcvquerystats(dns_zone_t *zone);

dns_stats_t *
dns_zone_getdnssecsignstats(dns_zone_t *zone);
/*%<
 * Get the additional statistics for zone, if one is installed.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 *
 * Returns:
 * \li	when available, a pointer to the statistics set installed in zone;
 *	otherwise NULL.
 */

void
dns_zone_name(dns_zone_t *zone, char *buf, size_t len);
/*%<
 * Return the name of the zone with class and view.
 *
 * Requires:
 *\li	'zone' to be valid.
 *\li	'buf' to be non NULL.
 */

void
dns_zone_nameonly(dns_zone_t *zone, char *buf, size_t len);
/*%<
 * Return the name of the zone only.
 *
 * Requires:
 *\li	'zone' to be valid.
 *\li	'buf' to be non NULL.
 */

void
dns_zone_setcheckmx(dns_zone_t *zone, dns_checkmxfunc_t checkmx);
/*%<
 *	Set the post load integrity callback function 'checkmx'.
 *	'checkmx' will be called if the MX TARGET is not within the zone.
 *
 * Require:
 *	'zone' to be a valid zone.
 */

void
dns_zone_setchecksrv(dns_zone_t *zone, dns_checkmxfunc_t checksrv);
/*%<
 *	Set the post load integrity callback function 'checksrv'.
 *	'checksrv' will be called if the SRV TARGET is not within the zone.
 *
 * Require:
 *	'zone' to be a valid zone.
 */

void
dns_zone_setcheckns(dns_zone_t *zone, dns_checknsfunc_t checkns);
/*%<
 *	Set the post load integrity callback function 'checkns'.
 *	'checkns' will be called if the NS TARGET is not within the zone.
 *
 * Require:
 *	'zone' to be a valid zone.
 */

void
dns_zone_setcheckisservedby(dns_zone_t		     *zone,
			    dns_checkisservedbyfunc_t checkisserverby);
/*%<
 *	Set the post load integrity callback function 'checkisserverby'.
 *	'checkisserverby' will be called if the NS TARGET is not within
 *	the zone and there are A or AAAA records in the zone.
 *
 * Require:
 *	'zone' to be a valid zone.
 */

void
dns_zone_setnotifydefer(dns_zone_t *zone, dns_rdatatype_t type, uint32_t defer);
/*%<
 * Set the wait/defer time (in seconds) before notify messages are sent when
 * they are ready.
 *
 * Requires:
 *	'zone' to be valid.
 *	'type' to be a valid notify RRtype.
 */

void
dns_zone_setnotifydelay(dns_zone_t *zone, dns_rdatatype_t type, uint32_t delay);
/*%<
 * Set the minimum delay (in seconds) between sets of notify messages.
 *
 * Requires:
 *	'zone' to be valid.
 *	'type' to be a valid notify RRtype.
 */

void
dns_zone_setisself(dns_zone_t *zone, dns_isselffunc_t isself, void *arg);
/*%<
 * Set the isself callback function and argument.
 *
 * bool
 * isself(dns_view_t *myview, dns_tsigkey_t *mykey,
 *	  const isc_netaddr_t *srcaddr, const isc_netaddr_t *destaddr,
 *	  dns_rdataclass_t rdclass, void *arg);
 *
 * 'isself' returns true if a non-recursive query from 'srcaddr' to
 * 'destaddr' with optional key 'mykey' for class 'rdclass' would be
 * delivered to 'myview'.
 */

void
dns_zone_setnodes(dns_zone_t *zone, uint32_t nodes);
/*%<
 * Set the number of nodes that will be checked per quantum.
 */

void
dns_zone_setsignatures(dns_zone_t *zone, uint32_t signatures);
/*%<
 * Set the number of signatures that will be generated per quantum.
 */

uint32_t
dns_zone_getsignatures(dns_zone_t *zone);
/*%<
 * Get the number of signatures that will be generated per quantum.
 */

void
dns_zone_setprivatetype(dns_zone_t *zone, dns_rdatatype_t type);
dns_rdatatype_t
dns_zone_getprivatetype(dns_zone_t *zone);
/*
 * Get/Set the private record type.  It is expected that these interfaces
 * will not be permanent.
 */

void
dns_zone_setadded(dns_zone_t *zone, bool added);
/*%
 * Sets the value of zone->added, which should be true for
 * zones that were originally added by "rndc addzone".
 *
 * Requires:
 * \li	'zone' to be valid.
 */

bool
dns_zone_getadded(dns_zone_t *zone);
/*%
 * Returns true if the zone was originally added at runtime
 * using "rndc addzone".
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setmodded(dns_zone_t *zone, bool added);
/*%
 * Sets the value of zone->modded, which should be true for
 * zones that were modified by "rndc modzone".
 *
 * Requires:
 * \li  'zone' to be valid.
 */

bool
dns_zone_getmodded(dns_zone_t *zone);
/*%
 * Returns true if the zone was modified at runtime
 * using "rndc modzone".
 *
 * Requires:
 * \li  'zone' to be valid.
 */

void
dns_zone_setautomatic(dns_zone_t *zone, bool automatic);
/*%
 * Sets the value of zone->automatic, which should be true for
 * zones that were automatically added by named.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

bool
dns_zone_getautomatic(dns_zone_t *zone);
/*%
 * Returns true if the zone was added automatically by named.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

isc_result_t
dns_zone_setrefreshkeyinterval(dns_zone_t *zone, uint32_t interval);
/*%
 * Sets the frequency, in minutes, with which the key repository will be
 * checked to see if the keys for this zone have been updated.  Any value
 * higher than 1440 minutes (24 hours) will be silently reduced.  A
 * value of zero will return an out-of-range error.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

bool
dns_zone_getrequestexpire(dns_zone_t *zone);
/*%
 * Returns the true/false value of the request-expire option in the zone.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setrequestexpire(dns_zone_t *zone, bool flag);
/*%
 * Sets the request-expire option for the zone. Either true or false. The
 * default value is determined by the setting of this option in the view.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

bool
dns_zone_getrequestixfr(dns_zone_t *zone);
/*%
 * Returns the true/false value of the request-ixfr option in the zone.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setrequestixfr(dns_zone_t *zone, bool flag);
/*%
 * Sets the request-ixfr option for the zone. Either true or false. The
 * default value is determined by the setting of this option in the view.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

bool
dns_zone_getrequestixfrmaxdiffs(dns_zone_t *zone);
/*%
 * Returns the value of the request-ixfr-max-diffs option in the zone.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setrequestixfrmaxdiffs(dns_zone_t *zone, uint32_t maxmsgs);
/*%
 * Sets the request-ixfr-max-diffs option for the zone. 0 means unlimited. The
 * default value is determined by the setting of this option in the view.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

uint32_t
dns_zone_getixfrratio(dns_zone_t *zone);
/*%
 * Returns the zone's current IXFR ratio.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setixfrratio(dns_zone_t *zone, uint32_t ratio);
/*%
 * Sets the ratio of IXFR size to zone size above which we use an AXFR
 * response, expressed as a percentage. Cannot exceed 100.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_setserialupdatemethod(dns_zone_t *zone, dns_updatemethod_t method);
/*%
 * Sets the update method to use when incrementing the zone serial number
 * due to a DDNS update.  Valid options are dns_updatemethod_increment
 * and dns_updatemethod_unixtime.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

dns_updatemethod_t
dns_zone_getserialupdatemethod(dns_zone_t *zone);
/*%<
 * Returns the update method to be used when incrementing the zone serial
 * number due to a DDNS update.
 *
 * Requires:
 * \li	'zone' to be valid.
 */

void
dns_zone_getloadtime(dns_zone_t *zone, isc_time_t *loadtime);
/*%
 * Return the time when the zone was last loaded.
 */

void
dns_zone_getrefreshtime(dns_zone_t *zone, isc_time_t *refreshtime);
/*%
 * Return the time when the (secondary) zone will need to be refreshed.
 */

void
dns_zone_getexpiretime(dns_zone_t *zone, isc_time_t *expiretime);
/*%
 * Return the time when the (secondary) zone will expire.
 */

void
dns_zone_getrefreshkeytime(dns_zone_t *zone, isc_time_t *refreshkeytime);
/*%
 * Return the time of the next scheduled DNSSEC key event.
 */

void
dns_zone_setstatlevel(dns_zone_t *zone, dns_zonestat_level_t level);

dns_zonestat_level_t
dns_zone_getstatlevel(dns_zone_t *zone);
/*%
 * Set and get the statistics reporting level for the zone;
 * full, terse, or none.
 */

unsigned int
dns_zone_gettid(dns_zone_t *zone);
/**<
 * \brief Return thread-id associated with the zone.
 *
 * \param valid dns_zone_t object
 *
 * \return thread id associated with the zone
 */

isc_loop_t *
dns_zone_getloop(dns_zone_t *zone);
/**<
 * \brief Return loop associated with the zone.
 *
 * \param valid dns_zone_t object
 *
 * \return loop associated with the zone
 */

void
dns_zone_setrad(dns_zone_t *zone, dns_name_t *name);
/**<
 * \brief Set the per zone RAD
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'name' is NULL or a valid name.
 */

isc_result_t
dns_zone_getrad(dns_zone_t *zone, dns_name_t *name);
/**<
 * \brief get the per zone RAD
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li	'name' is a valid name with a buffer.
 */

void *
dns_zone_gethooktable(dns_zone_t *zone);
/**<
 * Returns the zone hooktable
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

void
dns_zone_sethooktable(dns_zone_t *zone, void *hooktable,
		      void (*hooktable_free)(isc_mem_t *, void **));
/**<
 * Initialize zone hooktable and free callback
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 * \li  'hooktable' to be initialized.
 * \li  'hooktable_free' to be valid.
 */

void
dns_zone_setcfg(dns_zone_t *zone, const char *cfg);
/*%<
 * Save a copy of the configuration text for 'zone', which can be
 * used later to dump the configuration status.
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

const char *
dns_zone_getcfg(dns_zone_t *zone);
/*%<
 * Return a pointer to the configuration text for 'zone', that was
 * previously saved using _setcfg().
 *
 * Requires:
 * \li	'zone' to be a valid zone.
 */

dns_transport_type_t
dns_zone_getrequesttransporttype(dns_zone_t *zone);
/*%<
 * Get the transport type used for the SOA query to the current primary server
 * before an ongoing incoming zone transfer is lanunched. When the transfer is
 * already running, this information should be retrieved from the xfrin object
 * instead, using the dns_xfrin_gettransporttype() function.
 *
 * Requires:
 * \li  'zone' to be a valid zone.
 */

isc_stats_t *
dns_zone_getgluecachestats(dns_zone_t *zone);
/*%<
 * Get the glue cache statistics for zone.
 *
 * Requires:
 * \li  'zone' to be a valid zone.
 *
 * Returns:
 * \li  if present, a pointer to the statistics set installed in zone;
 *      otherwise NULL.
 */

dns_keystorelist_t *
dns_zone_getkeystores(dns_zone_t *zone);
/**<
 * Get the keystores pointer, it should never be NULL once the server is
 * initialized.
 */

void
dns_zone_expandzonefile(isc_buffer_t *b, const char *filename,
			const dns_name_t *zonename, const char *viewname,
			const char *typename);
/*%<
 * Expands the zone file name ('filename') using the inputs
 * 'zonename', 'viewname' and 'typename'.  The expanded file name
 * is stored in the buffer 'b'.  The follow expansions are available:
 *
 *    - $name or "%s" to the zone name, in lowercase
 *    - $type or "%t" to the zone type
 *    - $view or "%v" to the view name
 *    - $char1 or "%1" to the first character of the zone name
 *    - $char2 or "%2" to the second character of the zone name (or a dot if
 *      there is no second character)
 *    - $char3 or "%3" to the third character of the zone name (or a dot if
 *      there is no third character)
 *    - $label1 or "%z" to the toplevel domain of the zone (or a dot if it is
 *      the TLD)
 *    - $label2 or "%y" to the next label under the toplevel domain (or a dot if
 *      there is no next label)
 *    - $label2 or "%x" to the next-next label under the toplevel domain (or a
 *      dot if there is no next-next label)
 *
 * If 'viewname' is NULL, it is treated as an empty string.
 *
 * Requires:
 *  \li  'b' to be non NULL.
 *  \li  'filename' to be non NULL.
 *  \li  'zonename' to be a valid name.
 *  \li  'typename' to be non NULL.
 */
