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
#include <isc/thread.h>

#include <dns/sdb.h>

#include <named/globals.h>

#include <ldap.h>
#include "ldapdb.h"

/*
 * A simple database driver for LDAP. Not production quality yet
 */ 

static dns_sdbimplementation_t *ldapdb = NULL;

struct ldapdb_data {
	char *hostport;
	char *hostname;
	int portno;
	char *base;
	int defaultttl;
};

/* used by ldapdb_getconn */

struct ldapdb_entry {
	void *index;
	size_t size;
	void *data;
	struct ldapdb_entry *next;
};

static struct ldapdb_entry *ldapdb_find(struct ldapdb_entry *stack,
					const void *index, size_t size) {
	while (stack != NULL) {
		if (stack->size == size && !memcmp(stack->index, index, size))
			return stack;
		stack = stack->next;
	}
	return NULL;
}

static void ldapdb_insert(struct ldapdb_entry **stack,
			  struct ldapdb_entry *item) {
	item->next = *stack;
	*stack = item;
}

static void ldapdb_lock(int what) {
	static isc_mutex_t lock;

	switch (what) {
	case 0:
		isc_mutex_init(&lock);
		break;
	case 1:
		LOCK(&lock);
		break;
	case -1:
		UNLOCK(&lock);
		break;
	}
}

/* data == NULL means cleanup */
static LDAP **
ldapdb_getconn(struct ldapdb_data *data)
{
	static struct ldapdb_entry *allthreadsdata = NULL;
	struct ldapdb_entry *threaddata, *conndata;
	unsigned long threadid;

	if (data == NULL) {
		/* cleanup */
		/* lock out other threads */
		ldapdb_lock(1);
		while (allthreadsdata != NULL) {
			threaddata = allthreadsdata;
			free(threaddata->index);
			while (threaddata->data != NULL) {
				conndata = threaddata->data;
				free(conndata->index);
				if (conndata->data != NULL)
					ldap_unbind((LDAP *)conndata->data);
				threaddata->data = conndata->next;
				free(conndata);
			}
			allthreadsdata = threaddata->next;
			free(threaddata);
		}
		ldapdb_lock(-1);
		return (NULL);
	}

	/* look for connection data for current thread */
	threadid = isc_thread_self();
	threaddata = ldapdb_find(allthreadsdata, &threadid, sizeof(threadid));
	if (threaddata == NULL) {
		/* no data for this thread, create empty connection list */
		threaddata = malloc(sizeof(*threaddata));
		if (threaddata == NULL)
			return (NULL);
		threaddata->index = malloc(sizeof(threadid));
		if (threaddata->index == NULL) {
			free(threaddata);
			return (NULL);
		}
		*(unsigned long *)threaddata->index = threadid;
		threaddata->size = sizeof(threadid);
		threaddata->data = NULL;

		/* need to lock out other threads here */
		ldapdb_lock(1);
		ldapdb_insert(&allthreadsdata, threaddata);
		ldapdb_lock(-1);
	}

	/* threaddata points at the connection list for current thread */
	/* look for existing connection to our server */
	conndata = ldapdb_find((struct ldapdb_entry *)threaddata->data,
			       data->hostport, strlen(data->hostport));
	if (conndata == NULL) {
		/* no connection data structure for this server, create one */
		conndata = malloc(sizeof(*conndata));
		if (conndata == NULL)
			return (NULL);
		(char *)conndata->index = data->hostport;
		conndata->size = strlen(data->hostport);
		conndata->data = NULL;
		ldapdb_insert((struct ldapdb_entry **)&threaddata->data,
			      conndata);
	}

	return (LDAP **)&conndata->data;
}

/* callback routines */
static isc_result_t
ldapdb_create(const char *zone, int argc, char **argv,
	      void *driverdata, void **dbdata)
{
	struct ldapdb_data *data;
	char *s;
	int defaultttl;

	UNUSED(zone);
	UNUSED(driverdata);

	/* we assume that only one thread will call create at a time */
	/* want to do this only once for all instances */

	if ((argc < 2)
	    || (argv[0] != strstr( argv[0], "ldap://"))
	    || ((defaultttl = atoi(argv[1])) < 1))
                return (ISC_R_FAILURE);
        data = isc_mem_get(ns_g_mctx, sizeof(struct ldapdb_data));
        if (data == NULL)
                return (ISC_R_NOMEMORY);
	data->hostport = isc_mem_strdup(ns_g_mctx, argv[0] + strlen("ldap://"));
	if (data->hostport == NULL) {
		isc_mem_put(ns_g_mctx, data, sizeof(struct ldapdb_data));
		return (ISC_R_NOMEMORY);
	}
	data->defaultttl = defaultttl;
	s = strchr(data->hostport, '/');
	if (s != NULL) {
		*s++ = '\0';
		data->base = *s != '\0' ? s : NULL;
	}

	/* support URLs with literal IPv6 addresses */
	data->hostname = isc_mem_strdup(ns_g_mctx, data->hostport +
					(*data->hostport == '[' ? 1 : 0));
	if (data->hostname == NULL) {
		isc_mem_free(ns_g_mctx, data->hostport);
		isc_mem_put(ns_g_mctx, data, sizeof(struct ldapdb_data));
		return (ISC_R_NOMEMORY);
	}

	if (*data->hostport == '[' &&
	    (s = strchr(data->hostname, ']')) != NULL )
		*s++ = '\0';
	else
		s = data->hostname;
	s = strchr(s, ':');
	if (s != NULL) {
		*s++ = '\0';
		data->portno = atoi(s);
	} else
		data->portno = LDAP_PORT;

	*dbdata = data;
	return (ISC_R_SUCCESS);
}

static void
ldapdb_destroy(const char *zone, void *driverdata, void **dbdata) {
	struct ldapdb_data *data = *dbdata;
	
        UNUSED(zone);
        UNUSED(driverdata);

	if (data->hostport != NULL)
		isc_mem_free(ns_g_mctx, data->hostport);
	if (data->hostname != NULL)
		isc_mem_free(ns_g_mctx, data->hostname);
        isc_mem_put(ns_g_mctx, data, sizeof(struct ldapdb_data));
}

static void
ldapdb_bind(struct ldapdb_data *data, LDAP **ldp)
{
	if (*ldp != NULL)
		ldap_unbind(*ldp);
	*ldp = ldap_open(data->hostname, data->portno);
	if (*ldp == NULL)
		return;
	if (ldap_simple_bind_s(*ldp, NULL, NULL) != LDAP_SUCCESS) {
		ldap_unbind(*ldp);
		*ldp = NULL;
	}
}

static isc_result_t
ldapdb_lookup(const char *zone, const char *name, void *dbdata,
	      dns_sdblookup_t *lookup)
{
        isc_result_t result = ISC_R_NOTFOUND;
	struct ldapdb_data *data = dbdata;
	LDAP **ldp;
	LDAPMessage *res, *e;
	char *fltr, *a, **vals;
	char type[64];
	BerElement *ptr;
	int i;

	ldp = ldapdb_getconn(data);
	if (ldp == NULL)
		return (ISC_R_FAILURE);
	if (*ldp == NULL) {
		ldapdb_bind(data, ldp);
		if (*ldp == NULL)
			return (ISC_R_FAILURE);
	}
	fltr = isc_mem_get(ns_g_mctx, strlen(zone) + strlen(name) +
			   strlen("(&(zoneName=)(relativeDomainName=))") + 1);
        if (fltr == NULL)
                return (ISC_R_NOMEMORY);

	strcpy(fltr, "(&(zoneName=");
	strcat(fltr, zone);
	strcat(fltr, ")(relativeDomainName=");
	strcat(fltr, name);
	strcat(fltr, "))");

	if (ldap_search_s(*ldp, data->base, LDAP_SCOPE_SUBTREE, fltr, NULL, 0,
			  &res) != LDAP_SUCCESS) {
		ldapdb_bind(data, ldp);
		if (*ldp != NULL)
			ldap_search_s(*ldp, data->base, LDAP_SCOPE_SUBTREE,
				      fltr, NULL, 0, &res);
	}

	isc_mem_put(ns_g_mctx, fltr, strlen(fltr) + 1);

	if (*ldp == NULL)
		goto exit;
	
	for (e = ldap_first_entry(*ldp, res); e != NULL;
	     e = ldap_next_entry(*ldp, e)) {
		LDAP *ld = *ldp;
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
				result = dns_sdb_putrr(lookup, type, ttl,
						       vals[i]);
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
ldapdb_allnodes(const char *zone, void *dbdata,
		dns_sdballnodes_t *allnodes) {
        isc_result_t result = ISC_R_NOTFOUND;
	struct ldapdb_data *data = dbdata;
	LDAP **ldp;
	LDAPMessage     *res, *e;
	char type[64];
	char *fltr, *a, **vals;
	BerElement *ptr;
	int i;

	ldp = ldapdb_getconn(data);
	if (ldp == NULL)
		return (ISC_R_FAILURE);
	if (*ldp == NULL) {
		ldapdb_bind(data, ldp);
		if (*ldp == NULL)
			return (ISC_R_FAILURE);
	}

	fltr = isc_mem_get(ns_g_mctx, strlen(zone) + strlen("(zoneName=)") + 1);
        if (fltr == NULL)
                return (ISC_R_NOMEMORY);

	strcpy(fltr, "(zoneName=");
	strcat(fltr, zone);
	strcat(fltr, ")");

	if (ldap_search_s(*ldp, data->base, LDAP_SCOPE_SUBTREE, fltr, NULL, 0,
			  &res) != LDAP_SUCCESS) {
		ldapdb_bind(data, ldp);
		if (*ldp != NULL)
			ldap_search_s(*ldp, data->base, LDAP_SCOPE_SUBTREE,
				      fltr, NULL, 0, &res);
	}

	isc_mem_put(ns_g_mctx, fltr, strlen(fltr) + 1);

	for (e = ldap_first_entry(*ldp, res); e != NULL;
	     e = ldap_next_entry(*ldp, e)) {
		LDAP *ld = *ldp;
		char *name = NULL;
		int ttl = data->defaultttl;
		
		for (a = ldap_first_attribute(ld, e, &ptr); a != NULL;
		     a = ldap_next_attribute(ld, e, ptr)) {
			if (!strcmp(a, "dNSTTL")) {
				vals = ldap_get_values(ld, e, a);
				ttl = atoi(vals[0]);
				ldap_value_free(vals);
			} else if (!strcmp(a, "relativeDomainName")) {
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
				result = dns_sdb_putnamedrr(allnodes, name,
							    type, ttl, vals[i]);
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

/* Wrapper around dns_sdb_register() */
isc_result_t
ldapdb_init(void) {
	unsigned int flags =
		DNS_SDBFLAG_RELATIVEOWNER |
		DNS_SDBFLAG_RELATIVERDATA |
		DNS_SDBFLAG_THREADSAFE;

	ldapdb_lock(0);
	return (dns_sdb_register("ldap", &ldapdb_methods, NULL, flags,
				 ns_g_mctx, &ldapdb));
}

/* Wrapper around dns_sdb_unregister() */
void
ldapdb_clear(void) {
	if (ldapdb != NULL) {
		/* clean up thread data */
		ldapdb_getconn(NULL);
		dns_sdb_unregister(&ldapdb);
	}
}
