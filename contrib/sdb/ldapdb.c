/*
 * Copyright (C) 2001 Stig Venaas
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/sdb.h>

#include <named/globals.h>

#include <ldap.h>
#include "ldapdb.h"

/*
 * A simple database driver for LDAP. Not production quality yet.
 */ 

static dns_sdbimplementation_t *ldapdb = NULL;

struct ldapdb_data {
	char *hostname;
	int portno;
	char *base;
	int defaultttl;
	LDAP *ld;
};

static isc_result_t
ldapdb_create(const char *zone, int argc, char **argv,
	      void *driverdata, void **dbdata)
{
	struct ldapdb_data *data;
	char *s;
	int defaultttl;
		
	UNUSED(zone);
	UNUSED(driverdata);

	if ((argc < 2)
	    || (argv[0] != strstr( argv[0], "ldap://"))
	    || ((defaultttl = atoi(argv[1])) < 1))
                return (ISC_R_FAILURE);
        data = isc_mem_get(ns_g_mctx, sizeof(struct ldapdb_data));
        if (data == NULL)
                return (ISC_R_NOMEMORY);
	data->hostname = isc_mem_strdup(ns_g_mctx, argv[0] + strlen("ldap://"));
	if (data->hostname == NULL) {
		isc_mem_put(ns_g_mctx, data, sizeof(struct ldapdb_data));
		return (ISC_R_NOMEMORY);
	}
	data->defaultttl = defaultttl;
	s = strchr(data->hostname, '/');
	if (s != NULL) {
		*s++ = '\0';
		data->base = *s != '\0' ? s : NULL;
	}
	s = strchr(data->hostname, ':');
	if (s != NULL) {
		*s++ = '\0';
		data->portno = atoi(s);
	} else
		data->portno = LDAP_PORT;
	data->ld = NULL;
	*dbdata = data;
	return (ISC_R_SUCCESS);
}

static void
ldapdb_destroy(const char *zone, void *driverdata, void **dbdata) {
	struct ldapdb_data *data = *dbdata;
	
        UNUSED(zone);
        UNUSED(driverdata);

	if (data == NULL)
		return;
	if (data->ld != NULL)
		ldap_unbind(data->ld);
	if (data->hostname != NULL)
		isc_mem_free(ns_g_mctx, data->hostname);
        isc_mem_put(ns_g_mctx, data, sizeof(struct ldapdb_data));
}

static void
ldapdb_bind(struct ldapdb_data *data)
{
	if (data->ld != NULL)
		ldap_unbind(data->ld);
	data->ld = ldap_open(data->hostname, data->portno);
	if (data->ld == NULL)
		return;
	if (ldap_simple_bind_s(data->ld, NULL, NULL) != LDAP_SUCCESS) {
		ldap_unbind(data->ld);
		data->ld = NULL;
	}
}

static isc_result_t
ldapdb_lookup(const char *zone, const char *name, void *dbdata,
	      dns_sdblookup_t *lookup)
{
        isc_result_t result = ISC_R_NOTFOUND;
	struct ldapdb_data *data = dbdata;
	LDAPMessage     *res, *e;
	char *fltr, *a, **vals;
	char type[64];
	BerElement *ptr;
	int i;
	
	UNUSED(zone);

	if (data->ld == NULL) {
		ldapdb_bind(data);
		if (data->ld == NULL)
			return (ISC_R_FAILURE);
	}
	fltr = isc_mem_get(ns_g_mctx, strlen(name) + strlen("(dc=)") + 1);
        if (fltr == NULL)
                return (ISC_R_NOMEMORY);
	strcpy(fltr, "(dc=");
	strcat(fltr, name);
	strcat(fltr, ")");
	if (ldap_search_s(data->ld, data->base, LDAP_SCOPE_ONELEVEL, fltr, NULL, 0, &res) != LDAP_SUCCESS) {
		ldapdb_bind(data);
		if (data->ld != NULL)
			ldap_search_s(data->ld, data->base, LDAP_SCOPE_ONELEVEL, fltr, NULL, 0, &res);
	}
	isc_mem_put(ns_g_mctx, fltr, strlen(fltr) + 1);
	if (data->ld == NULL)
		goto exit;
	
	for (e = ldap_first_entry(data->ld, res); e != NULL;
	     e = ldap_next_entry(data->ld, e)) {
		LDAP *ld = data->ld;
		int ttl = data->defaultttl;
		
		for (a = ldap_first_attribute(ld, e, &ptr); a != NULL;
		     a = ldap_next_attribute(ld, e, ptr)) {
			if (!strcmp(a, "dNSTTL")) {
				vals = ldap_get_values(ld, e, a);
				ttl = atoi(vals[0]);
				ldap_value_free(vals);
				ldap_memfree(a);
				break;
			}
			ldap_memfree(a);
		}
		for (a = ldap_first_attribute(ld, e, &ptr); a != NULL;
		     a = ldap_next_attribute(ld, e, ptr)) {
			char *s;
			
			for (s = a; *s; s++)
				*s = toupper(*s);
			s = strstr(a, "RECORD");
			if ((s == NULL) || (s == a)
			    || (s - a >= (signed int)sizeof(type))) {
				ldap_memfree(a);
				continue;
			}
			strncpy(type, a, s - a);
			type[s - a] = '\0';
			vals = ldap_get_values(ld, e, a);
			for (i=0; vals[i] != NULL; i++) {
				result = dns_sdb_putrr(lookup, type, ttl, vals[i]);
				if (result != ISC_R_SUCCESS) {
					ldap_value_free(vals);
					ldap_memfree(a);
					result = ISC_R_FAILURE;
					goto exit;
				}
			}
			ldap_value_free(vals);
			ldap_memfree(a);
		}
	}
 exit:
	ldap_msgfree(res);
	return (result);
}

static isc_result_t
ldapdb_allnodes(const char *zone, void *dbdata, dns_sdballnodes_t *allnodes) {
        isc_result_t result = ISC_R_NOTFOUND;
	struct ldapdb_data *data = dbdata;
	LDAPMessage     *res, *e;
	char type[64];
	char *a, **vals;
	BerElement *ptr;
	int i;

        UNUSED(zone);

	if (data->ld == NULL) {
		ldapdb_bind(data);
		if (data->ld == NULL)
			return (ISC_R_FAILURE);
	}

	if (ldap_search_s(data->ld, data->base, LDAP_SCOPE_ONELEVEL, "(objectclass=*)", NULL, 0, &res) != LDAP_SUCCESS) {
		ldapdb_bind(data);
		if (data->ld != NULL)
			ldap_search_s(data->ld, data->base, LDAP_SCOPE_ONELEVEL, "(objectclass=*)", NULL, 0, &res);
	}

	for (e = ldap_first_entry(data->ld, res); e != NULL;
	     e = ldap_next_entry(data->ld, e)) {
		LDAP *ld = data->ld;
		char *name = NULL;
		int ttl = data->defaultttl;
		
		for (a = ldap_first_attribute(ld, e, &ptr); a != NULL;
		     a = ldap_next_attribute(ld, e, ptr)) {
			if (!strcmp(a, "dNSTTL")) {
				vals = ldap_get_values(ld, e, a);
				ttl = atoi(vals[0]);
				ldap_value_free(vals);
			} else if (!strcmp(a, "dc")) {
				vals = ldap_get_values(ld, e, a);
				name = isc_mem_strdup(ns_g_mctx, vals[0]);
				ldap_value_free(vals);
			}
			ldap_memfree(a);
		}
		
		if (name == NULL)
			continue;
		
		for (a = ldap_first_attribute(ld, e, &ptr); a != NULL;
		     a = ldap_next_attribute(ld, e, ptr)) {
			char *s;

			for (s = a; *s; s++)
				*s = toupper(*s);
			s = strstr(a, "RECORD");
			if ((s == NULL) || (s == a)
			    || (s - a >= (signed int)sizeof(type))) {
				ldap_memfree(a);
				continue;
			}
			strncpy(type, a, s - a);
			type[s - a] = '\0';
			vals = ldap_get_values(ld, e, a);
			for (i=0; vals[i] != NULL; i++) {
				result = dns_sdb_putnamedrr(allnodes, name, type, ttl, vals[i]);
				if (result != ISC_R_SUCCESS) {
					ldap_value_free(vals);
					ldap_memfree(a);
					isc_mem_free(ns_g_mctx, name);
					result = ISC_R_FAILURE;
					goto exit;
				}
			}
			ldap_value_free(vals);
			ldap_memfree(a);
		}
		isc_mem_free(ns_g_mctx, name);
	}

 exit:
	ldap_msgfree(res);
	return (result);
}

static dns_sdbmethods_t ldapdb_methods = {
	ldapdb_lookup,
	NULL, /* authority */
	ldapdb_allnodes,
	ldapdb_create,
	ldapdb_destroy
};

/*
 * Wrapper around dns_sdb_register().
 */
isc_result_t
ldapdb_init(void) {
	unsigned int flags;
	flags = DNS_SDBFLAG_RELATIVEOWNER | DNS_SDBFLAG_RELATIVERDATA;
	return (dns_sdb_register("ldap", &ldapdb_methods, NULL, flags,
				 ns_g_mctx, &ldapdb));
}

/*
 * Wrapper around dns_sdb_unregister().
 */
void
ldapdb_clear(void) {
	if (ldapdb != NULL)
		dns_sdb_unregister(&ldapdb);
}
