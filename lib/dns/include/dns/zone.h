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

#ifndef DNS_ZONE_H
#define DNS_ZONE_H 1

/***
 ***	Imports
 ***/

#include <isc/lang.h>
#include <isc/mem.h>
#include <isc/lex.h>
#include <isc/mutex.h>
#include <isc/time.h>
#include <isc/stdtime.h>
#include <isc/socket.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdataset.h>
#include <dns/callbacks.h>
#include <dns/confctx.h> 


typedef enum {
	dns_zone_none,
	dns_zone_master,
	dns_zone_slave,
	dns_zone_hint,
	dns_zone_stub,
	dns_zone_cache,
	dns_zone_forward
} dns_zonetype_t;

#define DNS_ZONE_O_SERVERS	0x00000001U	/* perform server checks */
#define DNS_ZONE_O_PARENTS	0x00000002U	/* perform parent checks */
#define DNS_ZONE_O_CHILDREN	0x00000004U	/* perform child checks */
#define DNS_ZONE_O_DIALUP	0x00000008U	/* zone xfr over dialup link */
#define DNS_ZONE_O_NOTIFY	0x00000010U	/* perform NOTIFY */

typedef struct dns_zone dns_zone_t;

ISC_LANG_BEGINDECLS

/***
 ***	Functions
 ***/

dns_result_t dns_zone_create(dns_zone_t **zonep, isc_mem_t *mctx);

/*
 *	Creates a new empty zone and attach to it.
 *
 * Requires:
 *	'zonep' to point to a NULL pointer.
 *	'mctx' to be a valid memory context.
 *
 * Ensures:
 *	'*zonep' refers to a valid zone.
 *
 * Returns:
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 *	DNS_R_UNEXPECTED
 */

void dns_zone_setclass(dns_zone_t *zone, dns_rdataclass_t rdclass);
/*
 *	Sets the class of a zone.  This operation can only be performed
 *	once on a zone.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	dns_zone_setclass() not to have been called since the zone was
 *	initalised.
 *	'rdclass' != dns_rdataclass_none.
 */	

void dns_zone_settype(dns_zone_t *zone, dns_zonetype_t type);
/*
 *	Sets the zone type. This operation can only be performed once on
 *	a zone.
 *
 * Requires:
 *	'zone' to be a valid initalised zone.
 *	dns_zone_settype() not to have been called since the zone was
 *	initalised.
 *	'type' != dns_zone_none
 */

dns_result_t dns_zone_setorigin(dns_zone_t *zone, char *origin);
/*
 *	Sets the zones origin to 'origin'.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'origin' to be non NULL.
 *
 * Returns:
 *	All possible values from dns_name_fromtext().
 */

dns_result_t dns_zone_setdatabase(dns_zone_t *zone, const char *database);
/*
 *	Sets the name of the database to be loaded. 
 *	For databases loaded from MASTER files this corresponds to the
 *	file name of the MASTER file.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'database' to be non NULL.
 *
 * Returns:
 *	DNS_R_NOMEMORY
 *	DNS_R_SUCCESS
 */

dns_result_t dns_zone_setixfrlog(dns_zone_t *zone, const char *ixfrlog);
/*
 *	Sets the name of the IXFR log file.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'ixfrlog' to be non NULL.
 *
 * Returns:
 *	DNS_R_NOMEMORY
 *	DNS_R_SUCCESS
 */

dns_result_t dns_zone_setupdatelog(dns_zone_t *zone, char *updatelog);
/*
 *	Sets the name of the UPDATE log file.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'updatelog' to be non NULL.
 *
 * Returns:
 *	DNS_R_NOMEMORY
 *	DNS_R_SUCCESS
 */

dns_result_t dns_zone_load(dns_zone_t *zone);
/*
 *	Cause the database to be loaded from its backing store.
 *	Confirm that the mimimum requirements for the zone type are
 *	met, otherwise DNS_R_BADZONE is return.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *
 * Returns:
 *	DNS_R_UNEXPECTED
 *	DNS_R_SUCCESS
 *	DNS_R_BADZONE
 *	Any result value from dns_db_load().
 */

void dns_zone_checkservers(dns_zone_t *zone);
/*
 *	Initiate a consistancy check of the zones servers.
 *	XXX MPA to be implemented.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_checkparents(dns_zone_t *zone);
/*
 *	Initiate a consistancy check of the zone and the parent zone servers.
 *	XXX MPA to be implemented.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_checkchildren(dns_zone_t *zone);
/*
 *	Initiate a consistancy check of the child delegations from this zone.
 *	XXX MPA to be implemented.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_checkglue(dns_zone_t *zone);
/*
 *	Initiate a consistancy check of the glue records in this zone.
 *	XXX MPA to be implemented.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_attach(dns_zone_t *source, dns_zone_t **target);
/*
 *	Attach 'zone' to 'target'.  Increment reference count.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'target' to be non NULL and '*target' to be NULL.
 */

void dns_zone_detach(dns_zone_t **zonep);
/*
 *	Detach the current zone.  If this is the last reference to the
 *	zone it will be destroyed.
 *
 * Require:
 *	'zonep' to point to a valid initalised zone.
 */

void dns_zone_setflag(dns_zone_t *zone, unsigned int flags,
		      isc_boolean_t value);
/*
 *	Sets ('value' == 'ISC_TRUE') / clears ('value' == 'IS_FALSE')
 *	zone flags.  Valid flag bits are DNS_ZONE_F_*.
 *
 * Requires
 *	'zone' to be a valid initalised zone.
 */

dns_result_t dns_zone_adddbarg(dns_zone_t *zone, char *arg);
/*
 *	Add 'arg' to the end of the list of database arguements.
 *	No attempt in made to validate the arguements.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'arg' to be non NULL.
 *
 * Returns:
 *	DNS_R_NOMEMORY
 *	DNS_R_SUCCESS
 */

void dns_zone_cleardbargs(dns_zone_t *zone);
/*
 *	Clear all database arguements.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

dns_db_t * dns_zone_getdb(dns_zone_t *zone);
/*
 * 	Return a pointer to the database.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *
 * Returns:
 *	A pointer to a database structure or NULL.
 */

dns_result_t dns_zone_setdbtype(dns_zone_t *zone, char *db_type);
/*
 *	Sets the database type. Current database types are: "rbt", "rbt64".
 *	'db_type' is not checked to see if it is a valid database type. 
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'database' to be non NULL.
 *
 * Returns:
 *	DNS_R_NOMEMORY
 *	DNS_R_SUCCESS
 */

void dns_zone_validate(dns_zone_t *zone);

	/* XXX MPA */

void dns_zone_expire(dns_zone_t *zone);
/*
 *	Mark the zone as expired.  If the zone requires dumping cause it to
 *	be initiated.  Set the refresh and retry intervals to there default
 *	values and unload the zone.
 *
 * Require
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_refresh(dns_zone_t *zone);
/*
 *	Initiate zone up to date checks.  The zone must already be being
 *	managed.
 *
 * Require
 *	'zone' to be a valid initalised zone.
 */

dns_result_t dns_zone_dump(dns_zone_t *zone, FILE *fd);
/*
 *	Write the zone to 'fd' in MASTER file format.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'fd' to be an active file handle open for writing.
 */

void dns_zone_maintenance(dns_zone_t *zone);
/*
 *	Perform regular maintenace on the zone.  This is called as a
 *	result of a zone being managed.
 *
 * Require
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_clearmasters(dns_zone_t *zone);
/*
 *	Clear the set of master servers the zone transfers from.
 *
 * Require
 *	'zone' to be a valid initalised zone.
 */

dns_result_t dns_zone_addmaster(dns_zone_t *zone, isc_sockaddr_t *master);
/*
 *	Add a master server to the end of the set of master servers for
 *	the zone.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'master' to be non NULL.
 *
 * Returns:
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 */

void dns_zone_clearnotify(dns_zone_t *zone);
/*
 *	Clear the set of additional servers to be notified when the zone
 *	changes.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

dns_result_t dns_zone_addnotify(dns_zone_t *zone, isc_sockaddr_t *notify);
/*
 *	Add a server to the end of the list of additional servers to be
 *	notified when a zone changes.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'notify' to be non NULL.
 *
 * Returns:
 *	DNS_R_SUCCESS
 *	DNS_R_NOMEMORY
 */

void dns_zone_unmount(dns_zone_t *zone);
	/* XXX MPA */

void dns_zone_unload(dns_zone_t *zone);
/*
 *	detach the database from the zone structure.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

dns_result_t dns_zone_manage(dns_zone_t *zone, isc_taskmgr_t *tmgr);
/*
 *	Bring the zone under control of a task manger.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'tmgr' to be a valid initalised task manager.
 *
 * Returns:
 *	DNS_R_UNEXPECTED
 *	DNS_R_SUCCESS
 */

void dns_zone_setoption(dns_zone_t *zone, unsigned int option,
		        isc_boolean_t value);
/*
 *	Set given options on ('value' == ISC_TRUE) or off ('value' ==
 *	ISC_FALSE).
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_clearoption(dns_zone_t *zone, unsigned int option);
/*
 *	Clear the given options from the zone and allow system wide value
 *	to be used.
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

void dns_zone_getoptions(dns_zone_t *zone, unsigned int *options,
			 unsigned int *optionsmask);
/*
 *	Return which options a set ('options') and which are active
 *	('optionsmask').
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 *	'options' to be non NULL.
 *	'optionsmask' to be non NULL.
 */

void dns_zone_setrefresh(dns_zone_t *zone, isc_uint32_t refresh,
			 isc_uint32_t retry);
/*
 *	Set the refresh and retry values.  Normally this are set as a
 *	result of loading the zone (dns_zone_load).
 *
 * Require:
 *	'zone' to be a valid initalised zone.
 */

dns_result_t
dns_zone_setxfrsource(dns_zone_t *zone, isc_sockaddr_t *xfrsource);

isc_sockaddr_t *
dns_zone_getxfrsource(dns_zone_t *zone);



void dns_zone_setqueryacl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl);
void dns_zone_setupdateacl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl);
void dns_zone_setxfracl(dns_zone_t *zone, dns_c_ipmatchlist_t *acl);
dns_c_ipmatchlist_t * dns_zone_getqueryacl(dns_zone_t *zone);
dns_c_ipmatchlist_t * dns_zone_getupdateacl(dns_zone_t *zone);
dns_c_ipmatchlist_t * dns_zone_getxfracl(dns_zone_t *zone);
void dns_zone_clearupdateacl(dns_zone_t *zone);
void dns_zone_clearqueryacl(dns_zone_t *zone);
void dns_zone_clearxfracl(dns_zone_t *zone);
void dns_zone_setchecknames(dns_zone_t *zone, dns_c_severity_t severity);
dns_c_severity_t dns_zone_getchecknames(dns_zone_t *zone);
void dns_zone_setpubkey(dns_zone_t *zone, dns_c_pubkey_t *pubkey);
dns_c_pubkey_t * dns_zone_getpubkey(dns_zone_t *zone);
void dns_zone_setixfrlogsize(dns_zone_t *zone, isc_int32_t size);
isc_int32_t dns_zone_getixfrlogsize(dns_zone_t *zone);
void dns_zone_setmasterport(dns_zone_t *zone,  isc_uint16_t port);
isc_uint16_t dns_zone_getmasterport(dns_zone_t *zone);
void dns_zone_setresolver(dns_zone_t *zone, dns_resolver_t *resolver);
dns_result_t dns_zone_copy(dns_c_ctx_t *ctx, dns_c_zone_t *czone,
			   dns_zone_t *zone);
dns_result_t dns_zone_notifyreceive(dns_zone_t *zone, isc_sockaddr_t *from,
				dns_message_t *msg);

/*
 *
 */
isc_result_t dns_zone_callback(dns_c_ctx_t *ctx, dns_c_zone_t *zone, void *uap);
/*
 * 
 */

void
dns_zone_setxfrtime(dns_zone_t *zone, isc_uint32_t xfrtime);
/*
 * Set the maximum time (in seconds) that a zone transfer (AXFR/IXFR)
 * in of this zone will use before being aborted.
 *
 * Requires:
 * 	'zone' to be valid initialised zone.
 *	'xfrtime' to be non zero.
 */

isc_uint32_t dns_zone_getxfrtime(dns_zone_t *zone);
/*
 * Returns the maximum transfer time for this zone.  This will be
 * either the value set by the last call to dns_zone_setxfrtime() or
 * the default value of 1 hour.
 *
 * Requires:
 *	'zone' to be valid initialised zone.
 */

dns_zonetype_t dns_zone_gettype(dns_zone_t *zone);
/*
 * Return the type of the zone (master/slave/etc.)
 *
 * Requires:
 *	'zone' to be valid initialised zone.
 */

isc_task_t *dns_zone_gettask(dns_zone_t *zone);
/*
 * Return a pointer to the zone's task.
 *
 * Requires:
 *	'zone' to be valid initialised zone.
 */

ISC_LANG_ENDDECLS

#endif	/* DNS_ZONE_H */
