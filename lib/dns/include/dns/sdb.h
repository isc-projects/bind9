/*
 * Copyright (C) 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: sdb.h,v 1.2 2000/08/22 00:53:31 bwelling Exp $ */

/* $Id: sdb.h,v 1.2 2000/08/22 00:53:31 bwelling Exp $ */

#ifndef DNS_SDB_H
#define DNS_SDB_H 1

/*****
 ***** Module Info
 *****/

/*
 * Simple database API.
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>

#include <dns/types.h>

/***
 *** Types
 ***/

/*
 * A simple database.  This is an opaque type.
 */
typedef struct dns_sdb dns_sdb_t;

/*
 * A simple database lookup in progress.  This is an opaque type.
 * It's also the database node returned by dns_db_* functions.
 */
typedef struct dns_sdblookup dns_sdblookup_t;
typedef struct dns_sdblookup dns_sdbnode_t;

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

typedef isc_result_t
(*dns_sdblookupfunc_t)(const char *zone, const char *name, void *dbdata,
		       dns_sdblookup_t *);

typedef isc_result_t
(*dns_sdbauthorityfunc_t)(const char *zone, void *dbdata, dns_sdblookup_t *);

typedef isc_result_t
(*dns_sdbcreatefunc_t)(const char *zone, int argc, char **argv,
		       void *driverdata, void **dbdata);

typedef void
(*dns_sdbdestroyfunc_t)(const char *zone, void *driverdata, void **dbdata);

#define DNS_SDBFLAG_RELATIVEOWNER 0x1U
#define DNS_SDBFLAG_RELATIVERDATA 0x2U

isc_result_t
dns_sdb_register(const char *drivername, dns_sdblookupfunc_t lookup,
		 dns_sdbauthorityfunc_t authority, dns_sdbcreatefunc_t create,
		 dns_sdbdestroyfunc_t destroy, void *driverdata,
		 unsigned int flags);
/*
 * Register a simple database driver of name 'drivername'.  The name
 * server will perform lookups in the database by calling the function
 * 'lookup', passing it a printable zone name 'zone', a printable
 * domain name 'name', and copy of the argument 'driverdata' that
 * was given to ns_sdb_register().  The 'dns_sdblookup_t' argument to
 * 'lookup' and 'authority' is an opaque pointer to be passed to
 * ns_sdb_putrr().
 *
 * The lookup function returns the lookup results to the name server
 * by calling ns_sdb_putrr() once for each record found.
 *
 * Lookups at the zone apex will cause the server to also call the
 * function 'authority', which must provide an SOA record and NS
 * records for the zone by calling ns_sdb_putrr() once for each of
 * these records.
 *
 * The create function will be called when a database is created, and
 * allows the implementation to create database specific data.
 *
 * The destroy function will be called when a database is destroyed,
 * and allows the implementation to free any database specific data.
 *
 * The create and destroy functions may be NULL.
 *
 * If flags includes DNS_SDBFLAG_RELATIVEOWNER, the lookup and authority
 * functions will be called with relative names rather than absolute names.
 * The string "@" represents the zone apex in this case.
 *
 * If flags includes DNS_SDBFLAG_RELATIVERDATA, the rdata strings may
 * include relative names.  Otherwise, all names in the rdata string must
 * be absolute.  Be aware that if relative names are allowed, any
 * absolute names must contain a trailing dot.
 */

void
dns_sdb_unregister(const char *drivername);
/*
 * Removes the simple database driver from the list of registered database
 * types.
 */

isc_result_t
dns_sdb_putrr(dns_sdblookup_t *lookup, const char *type, dns_ttl_t ttl,
	      const char *data);
/*
 * Return a single resource record as a partial result for 'lookup' to
 * the name server.
 */

isc_result_t
dns_sdb_putsoa(dns_sdblookup_t *lookup, const char *mname, const char *rname,
	       isc_uint32_t serial);
/*
 * This function may optionally be called from the 'authority' callback
 * to simplify construction of the SOA record for 'zone'.  It will
 * provide a SOA listing 'mname' as as the master server and 'rname' as
 * the responsible person mailbox.  The serial number will increase
 * with each query, and all other SOA fields will have reasonable
 * default values.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_SDB_H */
