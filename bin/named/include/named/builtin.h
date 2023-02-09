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

/*! \file */

#include <inttypes.h>

#include <isc/lang.h>
#include <isc/types.h>

#include <dns/clientinfo.h>
#include <dns/types.h>

/*
 * Simple database implementation. Originally sdb.
 * XXX: this will be moved to its own file later.
 */

/* Opaque types: */

/* A simple database.  */
typedef struct sdb		 sdb_t;
typedef struct sdbimplementation sdbimplementation_t;

/* A simple database lookup in progress. */
typedef struct sdblookup sdblookup_t;

/* A simple database traversal in progress. */
typedef struct sdballnodes sdballnodes_t;

/* Callback function types */
typedef isc_result_t (*sdblookupfunc_t)(const dns_name_t *zone,
					const dns_name_t *name, void *dbdata,
					sdblookup_t		*lookup,
					dns_clientinfomethods_t *methods,
					dns_clientinfo_t	*clientinfo);

typedef isc_result_t (*sdbauthorityfunc_t)(const char *zone, void *dbdata,
					   sdblookup_t *);

typedef isc_result_t (*sdballnodesfunc_t)(const char *zone, void *dbdata,
					  sdballnodes_t *allnodes);

typedef isc_result_t (*sdbcreatefunc_t)(const char *zone, int argc, char **argv,
					void *driverdata, void **dbdata);

typedef void (*sdbdestroyfunc_t)(const char *zone, void *driverdata,
				 void **dbdata);

typedef struct sdbmethods {
	sdblookupfunc_t	   lookup;
	sdbauthorityfunc_t authority;
	sdbcreatefunc_t	   create;
	sdbdestroyfunc_t   destroy;
} sdbmethods_t;

/***
 *** Functions
 ***/

#define DNS_SDBFLAG_DNS64 0x00000001U

isc_result_t
sdb_register(const char *drivername, const sdbmethods_t *methods,
	     void *driverdata, unsigned int flags, isc_mem_t *mctx,
	     sdbimplementation_t **sdbimp);
/*%<
 * Register a simple database driver for the database type 'drivername',
 * implemented by the functions in '*methods'.
 *
 * sdbimp must point to a NULL sdbimplementation_t pointer.  That is,
 * sdbimp != NULL && *sdbimp == NULL.  It will be assigned a value that
 * will later be used to identify the driver when deregistering it.
 *
 * The name server will perform lookups in the database by calling the
 * function 'lookup', passing it a printable zone name 'zone', a printable
 * domain name 'name', and a copy of the argument 'dbdata' that
 * was potentially returned by the create function.  The 'sdblookup_t'
 * argument to 'lookup' and 'authority' is an opaque pointer to be passed to
 * ns_sdb_putrr().
 *
 * The lookup function returns the lookup results to the name server
 * by calling ns_sdb_putrr() once for each record found.  On success,
 * the return value of the lookup function should be ISC_R_SUCCESS.
 * If the domain name 'name' does not exist, the lookup function should
 * ISC_R_NOTFOUND.  Any other return value is treated as an error.
 *
 * Lookups at the zone apex will cause the server to also call the
 * function 'authority' (if non-NULL), which must provide an SOA record
 * and NS records for the zone by calling ns_sdb_putrr() once for each of
 * these records.  The 'authority' function may be NULL if invoking
 * the 'lookup' function on the zone apex will return SOA and NS records.
 *
 * The allnodes function, if non-NULL, fills in an opaque structure to be
 * used by a database iterator.  This allows the zone to be transferred.
 * This may use a considerable amount of memory for large zones, and the
 * zone transfer may not be fully RFC1035 compliant if the zone is
 * frequently changed.
 *
 * The create function will be called for each zone configured
 * into the name server using this database type.  It can be used
 * to create a "database object" containing zone specific data,
 * which can make use of the database arguments specified in the
 * name server configuration.
 *
 * The destroy function will be called to free the database object
 * when its zone is destroyed.
 *
 * The create and destroy functions may be NULL.
 *
 * The lookup and authority functions are called with relative names
 * rather than absolute names. The string "@" represents the zone apex.
 *
 * Rdata strings may include relative names.  Be aware that absolute names
 * must contain a trailing dot.
 */

void
sdb_unregister(sdbimplementation_t **sdbimp);
/*%<
 * Removes the simple database driver from the list of registered database
 * types.  There must be no active databases of this type when this function
 * is called.
 */

/*% See sdb_putradata() */
isc_result_t
sdb_putrr(sdblookup_t *lookup, const char *type, dns_ttl_t ttl,
	  const char *data);

/*
 * Add a single resource record to the lookup structure to be
 * returned in the query response.  sdb_putrr() takes the
 * resource record in master file text format as a null-terminated
 * string, and sdb_putrdata() takes the raw RDATA in
 * uncompressed wire format.
 */
isc_result_t
sdb_putrdata(sdblookup_t *lookup, dns_rdatatype_t type, dns_ttl_t ttl,
	     const unsigned char *rdata, unsigned int rdlen);

/*
 * May be called from the 'authority' callback to simplify construction of
 * an SOA record for 'zone'.  It will provide a SOA listing 'mname' as as
 * the primary server and 'rname' as the responsible person mailbox.  It is
 * the responsibility of the driver to increment the serial number between
 * responses if necessary.  All other SOA fields will have reasonable
 * default values.
 */
isc_result_t
sdb_putsoa(sdblookup_t *lookup, const char *mname, const char *rname,
	   uint32_t serial);

/* Initialization functions for builtin zone databases */
isc_result_t
named_builtin_init(void);

void
named_builtin_deinit(void);
