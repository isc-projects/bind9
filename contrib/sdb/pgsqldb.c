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

/* $Id: pgsqldb.c,v 1.10 2000/12/06 00:59:07 bwelling Exp $ */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <pgsql/libpq-fe.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/sdb.h>
#include <dns/result.h>

#include <named/globals.h>

#include "pgsqldb.h"

/*
 * A simple database driver that interfaces to a PostgreSQL database.  This
 * is not complete, and not designed for general use.  It opens one
 * connection to the database per zone, which is inefficient.  It also may
 * not support multiple threads and probably doesn't handle quoting correctly.
 *
 * The table must contain the fields "name", "rdtype", and "rdata", and 
 * is expected to contain a properly constructed zone.  The program "zonetodb"
 * creates such a table.
 */

static dns_sdbimplementation_t *pgsqldb = NULL;

struct dbinfo {
	PGconn *conn;
	char *table;
};

/*
 * Canonicalize a string before writing it to the database.
 * "dest" must be an array of at least size 2*strlen(source) + 1.
 */
static void
quotestring(const char *source, char *dest) {
	while (*source != 0) {
		if (*source == '\'')
			*dest++ = '\'';
		/* SQL doesn't treat \ as special, but PostgreSQL does */
		else if (*source == '\\')
			*dest++ = '\\';
		*dest++ = *source++;
	}
	*dest++ = 0;
}       

/*
 * This database operates on absolute names.
 *
 * Queries are converted into SQL queries and issued synchronously.  Errors
 * are handled really badly.
 */
static isc_result_t
pgsqldb_lookup(const char *zone, const char *name, void *dbdata,
	       dns_sdblookup_t *lookup)
{
	isc_result_t result;
	struct dbinfo *dbi = dbdata;
	PGresult *res;
	char str[1500];
	char *canonname;
	int i;

	UNUSED(zone);

	canonname = isc_mem_get(ns_g_mctx, strlen(name) * 2 + 1);
	if (canonname == NULL)
		return (ISC_R_NOMEMORY);
	quotestring(name, canonname);
	snprintf(str, sizeof(str),
		 "SELECT TTL,RDTYPE,RDATA FROM \"%s\" WHERE "
		 "lower(NAME) = lower('%s')", dbi->table, canonname);
	isc_mem_put(ns_g_mctx, canonname, strlen(name) * 2 + 1);
	res = PQexec(dbi->conn, str);
	if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
		PQclear(res);
		return (ISC_R_FAILURE);
	}
	if (PQntuples(res) == 0) {
		PQclear(res);
		return (ISC_R_NOTFOUND);
	}

	for (i = 0; i < PQntuples(res); i++) {
		char *ttlstr = PQgetvalue(res, i, 0);
		char *type = PQgetvalue(res, i, 1);
		char *data = PQgetvalue(res, i, 2);
		dns_ttl_t ttl;
		char *endp;
		ttl = strtol(ttlstr, &endp, 10);
		if (*endp != '\0') {
			PQclear(res);
			return (DNS_R_BADTTL);
		}
		result = dns_sdb_putrr(lookup, type, ttl, data);
		if (result != ISC_R_SUCCESS) {
			PQclear(res);
			return (ISC_R_FAILURE);
		}
	}

	PQclear(res);
	return (ISC_R_SUCCESS);
}

/*
 * Issue an SQL query to return all nodes in the database and fill the
 * allnodes structure.
 */
static isc_result_t
pgsqldb_allnodes(const char *zone, void *dbdata, dns_sdballnodes_t *allnodes) {
	struct dbinfo *dbi = dbdata;
	PGresult *res;
	isc_result_t result;
	char str[1500];
	int i;

	UNUSED(zone);

	snprintf(str, sizeof(str),
		 "SELECT TTL,NAME,RDTYPE,RDATA FROM \"%s\" ORDER BY NAME",
		 dbi->table);
	res = PQexec(dbi->conn, str);
	if (!res || PQresultStatus(res) != PGRES_TUPLES_OK ) {
		PQclear(res);
		return (ISC_R_FAILURE);
	}
	if (PQntuples(res) == 0) {
		PQclear(res);
		return (ISC_R_NOTFOUND);
	}

	for (i = 0; i < PQntuples(res); i++) {
		char *ttlstr = PQgetvalue(res, i, 0);
		char *name = PQgetvalue(res, i, 1);
		char *type = PQgetvalue(res, i, 2);
		char *data = PQgetvalue(res, i, 3);
		dns_ttl_t ttl;
		char *endp;
		ttl = strtol(ttlstr, &endp, 10);
		if (*endp != '\0') {
			PQclear(res);
			return (DNS_R_BADTTL);
		}
		result = dns_sdb_putnamedrr(allnodes, name, type, ttl, data);
		if (result != ISC_R_SUCCESS) {
			PQclear(res);
			return (ISC_R_FAILURE);
		}
	}

	PQclear(res);
	return (ISC_R_SUCCESS);
}

/*
 * Create a connection to the database and save a copy of the table name.
 * Save these in dbdata.  argv[0] is the name of the database and
 * argv[1] is the name of the table.
 */
static isc_result_t
pgsqldb_create(const char *zone, int argc, char **argv,
	       void *driverdata, void **dbdata)
{
	struct dbinfo *dbi;

	UNUSED(zone);
	UNUSED(driverdata);

	if (argc < 2)
		return (ISC_R_FAILURE);

	dbi = isc_mem_get(ns_g_mctx, sizeof(struct dbinfo));
	if (dbi == NULL)
		return (ISC_R_NOMEMORY);
	dbi->table = isc_mem_strdup(ns_g_mctx, argv[1]);
	if (dbi->table == NULL) {
		isc_mem_put(ns_g_mctx, dbi, sizeof(struct dbinfo));
		return (ISC_R_NOMEMORY);
	}

	dbi->conn = PQsetdb(NULL, NULL, NULL, NULL, argv[0]);
	if (PQstatus(dbi->conn) == CONNECTION_BAD) {
		PQfinish(dbi->conn);
		isc_mem_free(ns_g_mctx, dbi->table);
		isc_mem_put(ns_g_mctx, dbi, sizeof(struct dbinfo));
		return (ISC_R_FAILURE);
	}

	*dbdata = dbi;
	return (ISC_R_SUCCESS);
}

/*
 * Close the connection to the database.
 */
static void
pgsqldb_destroy(const char *zone, void *driverdata, void **dbdata) {
	struct dbinfo *dbi = *dbdata;

	UNUSED(zone);
	UNUSED(driverdata);

	PQfinish(dbi->conn);
	isc_mem_free(ns_g_mctx, dbi->table);
	isc_mem_put(ns_g_mctx, dbi, sizeof(struct dbinfo));
}

/*
 * Since the SQL database corresponds to a zone, the authority data should
 * be returned by the lookup() function.  Therefore the authority() function
 * is NULL.
 */
static dns_sdbmethods_t pgsqldb_methods = {
	pgsqldb_lookup,
	NULL, /* authority */
	pgsqldb_allnodes,
	pgsqldb_create,
	pgsqldb_destroy
};

/*
 * Wrapper around dns_sdb_register().
 */
isc_result_t
pgsqldb_init(void) {
	unsigned int flags;
	flags = 0;
	return (dns_sdb_register("pgsql", &pgsqldb_methods, NULL, flags,
				 ns_g_mctx, &pgsqldb));
}

/*
 * Wrapper around dns_sdb_unregister().
 */
void
pgsqldb_clear(void) {
	if (pgsqldb != NULL)
		dns_sdb_unregister(&pgsqldb);
}
