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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>
#include <dns/sdb.h>
#include <dns/types.h>

struct dns_sdbimplementation {
	const dns_sdbmethods_t *methods;
	void *driverdata;
	unsigned int flags;
	isc_mem_t *mctx;
	isc_mutex_t driverlock;
	dns_dbimplementation_t *dbimp;
};

struct dns_sdb {
	/* Unlocked */
	dns_db_t common;
	char *zone;
	dns_sdbimplementation_t *implementation;
	void *dbdata;
};

struct dns_sdblookup {
	/* Unlocked */
	unsigned int magic;
	dns_sdb_t *sdb;
	ISC_LIST(dns_rdatalist_t) lists;
	ISC_LIST(isc_buffer_t) buffers;
	dns_name_t *name;
	ISC_LINK(dns_sdblookup_t) link;
	dns_rdatacallbacks_t callbacks;

	/* Atomic */
	isc_refcount_t references;
};

typedef struct dns_sdblookup dns_sdbnode_t;

typedef struct sdb_rdatasetiter {
	dns_rdatasetiter_t common;
	dns_rdatalist_t *current;
} sdb_rdatasetiter_t;

#define SDB_MAGIC ISC_MAGIC('S', 'D', 'B', '-')

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define VALID_SDB(sdb) ((sdb) != NULL && (sdb)->common.impmagic == SDB_MAGIC)

#define SDBLOOKUP_MAGIC	      ISC_MAGIC('S', 'D', 'B', 'L')
#define VALID_SDBLOOKUP(sdbl) ISC_MAGIC_VALID(sdbl, SDBLOOKUP_MAGIC)
#define VALID_SDBNODE(sdbn)   VALID_SDBLOOKUP(sdbn)

/* These values are taken from RFC1537 */
#define SDB_DEFAULT_REFRESH 28800U  /* 8 hours */
#define SDB_DEFAULT_RETRY   7200U   /* 2 hours */
#define SDB_DEFAULT_EXPIRE  604800U /* 7 days */
#define SDB_DEFAULT_MINIMUM 86400U  /* 1 day */

/* This is a reasonable value */
#define SDB_DEFAULT_TTL (60 * 60 * 24)

static int dummy;

static isc_result_t
create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
       void *driverarg, dns_db_t **dbp);

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset);

static isc_result_t
createnode(dns_sdb_t *sdb, dns_sdbnode_t **nodep);

static void
destroynode(dns_sdbnode_t *node);

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp);

static void
list_tordataset(dns_rdatalist_t *rdatalist, dns_db_t *db, dns_dbnode_t *node,
		dns_rdataset_t *rdataset);

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

/*
 * Functions used by implementors of simple databases
 */
isc_result_t
dns_sdb_register(const char *drivername, const dns_sdbmethods_t *methods,
		 void *driverdata, unsigned int flags, isc_mem_t *mctx,
		 dns_sdbimplementation_t **sdbimp) {
	dns_sdbimplementation_t *imp = NULL;
	isc_result_t result;

	REQUIRE(drivername != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(methods->lookup != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(sdbimp != NULL && *sdbimp == NULL);
	REQUIRE((flags & ~DNS_SDBFLAG_DNS64) == 0);

	imp = isc_mem_get(mctx, sizeof(dns_sdbimplementation_t));
	imp->methods = methods;
	imp->driverdata = driverdata;
	imp->flags = flags;
	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	isc_mutex_init(&imp->driverlock);

	imp->dbimp = NULL;
	result = dns_db_register(drivername, create, imp, mctx, &imp->dbimp);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_mutex;
	}
	*sdbimp = imp;

	return (ISC_R_SUCCESS);

cleanup_mutex:
	isc_mutex_destroy(&imp->driverlock);
	isc_mem_put(mctx, imp, sizeof(dns_sdbimplementation_t));
	return (result);
}

void
dns_sdb_unregister(dns_sdbimplementation_t **sdbimp) {
	dns_sdbimplementation_t *imp = NULL;

	REQUIRE(sdbimp != NULL && *sdbimp != NULL);

	imp = *sdbimp;
	*sdbimp = NULL;
	dns_db_unregister(&imp->dbimp);
	isc_mutex_destroy(&imp->driverlock);

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(dns_sdbimplementation_t));
}

static unsigned int
initial_size(unsigned int len) {
	unsigned int size;

	for (size = 1024; size < (64 * 1024); size *= 2) {
		if (len < size) {
			return (size);
		}
	}
	return (65535);
}

isc_result_t
dns_sdb_putrdata(dns_sdblookup_t *lookup, dns_rdatatype_t typeval,
		 dns_ttl_t ttl, const unsigned char *rdatap,
		 unsigned int rdlen) {
	dns_rdatalist_t *rdatalist = NULL;
	dns_rdata_t *rdata = NULL;
	isc_buffer_t *rdatabuf = NULL;
	isc_mem_t *mctx = NULL;
	isc_region_t region;

	mctx = lookup->sdb->common.mctx;

	rdatalist = ISC_LIST_HEAD(lookup->lists);
	while (rdatalist != NULL) {
		if (rdatalist->type == typeval) {
			break;
		}
		rdatalist = ISC_LIST_NEXT(rdatalist, link);
	}

	if (rdatalist == NULL) {
		rdatalist = isc_mem_get(mctx, sizeof(dns_rdatalist_t));
		dns_rdatalist_init(rdatalist);
		rdatalist->rdclass = lookup->sdb->common.rdclass;
		rdatalist->type = typeval;
		rdatalist->ttl = ttl;
		ISC_LIST_APPEND(lookup->lists, rdatalist, link);
	} else if (rdatalist->ttl != ttl) {
		return (DNS_R_BADTTL);
	}

	rdata = isc_mem_get(mctx, sizeof(dns_rdata_t));

	isc_buffer_allocate(mctx, &rdatabuf, rdlen);
	DE_CONST(rdatap, region.base);
	region.length = rdlen;
	isc_buffer_copyregion(rdatabuf, &region);
	isc_buffer_usedregion(rdatabuf, &region);
	dns_rdata_init(rdata);
	dns_rdata_fromregion(rdata, rdatalist->rdclass, rdatalist->type,
			     &region);
	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	ISC_LIST_APPEND(lookup->buffers, rdatabuf, link);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_sdb_putrr(dns_sdblookup_t *lookup, const char *type, dns_ttl_t ttl,
	      const char *data) {
	unsigned int datalen;
	dns_rdatatype_t typeval;
	isc_textregion_t r;
	isc_lex_t *lex = NULL;
	isc_result_t result;
	unsigned char *p = NULL;
	unsigned int size = 0; /* Init to suppress compiler warning */
	isc_mem_t *mctx = NULL;
	const dns_name_t *origin = NULL;
	isc_buffer_t b;
	isc_buffer_t rb;

	REQUIRE(VALID_SDBLOOKUP(lookup));
	REQUIRE(type != NULL);
	REQUIRE(data != NULL);

	mctx = lookup->sdb->common.mctx;

	DE_CONST(type, r.base);
	r.length = strlen(type);
	result = dns_rdatatype_fromtext(&typeval, &r);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	origin = &lookup->sdb->common.origin;

	isc_lex_create(mctx, 64, &lex);

	datalen = strlen(data);
	size = initial_size(datalen);
	do {
		isc_buffer_constinit(&b, data, datalen);
		isc_buffer_add(&b, datalen);
		result = isc_lex_openbuffer(lex, &b);
		if (result != ISC_R_SUCCESS) {
			goto failure;
		}

		if (size >= 65535) {
			size = 65535;
		}
		p = isc_mem_get(mctx, size);
		isc_buffer_init(&rb, p, size);
		result = dns_rdata_fromtext(NULL, lookup->sdb->common.rdclass,
					    typeval, lex, origin, 0, mctx, &rb,
					    &lookup->callbacks);
		if (result != ISC_R_NOSPACE) {
			break;
		}

		/*
		 * Is the RR too big?
		 */
		if (size >= 65535) {
			break;
		}
		isc_mem_put(mctx, p, size);
		p = NULL;
		size *= 2;
	} while (result == ISC_R_NOSPACE);

	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	result = dns_sdb_putrdata(lookup, typeval, ttl, isc_buffer_base(&rb),
				  isc_buffer_usedlength(&rb));
failure:
	if (p != NULL) {
		isc_mem_put(mctx, p, size);
	}
	if (lex != NULL) {
		isc_lex_destroy(&lex);
	}

	return (result);
}

isc_result_t
dns_sdb_putsoa(dns_sdblookup_t *lookup, const char *mname, const char *rname,
	       uint32_t serial) {
	char str[2 * DNS_NAME_MAXTEXT + 5 * (sizeof("2147483647")) + 7];
	int n;

	REQUIRE(mname != NULL);
	REQUIRE(rname != NULL);

	n = snprintf(str, sizeof(str), "%s %s %u %u %u %u %u", mname, rname,
		     serial, SDB_DEFAULT_REFRESH, SDB_DEFAULT_RETRY,
		     SDB_DEFAULT_EXPIRE, SDB_DEFAULT_MINIMUM);
	if (n >= (int)sizeof(str) || n < 0) {
		return (ISC_R_NOSPACE);
	}
	return (dns_sdb_putrr(lookup, "SOA", SDB_DEFAULT_TTL, str));
}

/*
 * DB routines
 */

static void
destroy(dns_db_t *db) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbimplementation_t *imp = sdb->implementation;

	isc_refcount_destroy(&sdb->common.references);

	if (imp != NULL && imp->methods->destroy != NULL) {
		LOCK(&sdb->implementation->driverlock);
		imp->methods->destroy(sdb->zone, imp->driverdata, &sdb->dbdata);
		UNLOCK(&sdb->implementation->driverlock);
	}

	isc_mem_free(sdb->common.mctx, sdb->zone);

	sdb->common.magic = 0;
	sdb->common.impmagic = 0;

	dns_name_free(&sdb->common.origin, sdb->common.mctx);

	isc_mem_putanddetach(&sdb->common.mctx, sdb, sizeof(dns_sdb_t));
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	REQUIRE(versionp != NULL && *versionp == NULL);

	UNUSED(db);

	*versionp = (void *)&dummy;
	return;
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp) {
	REQUIRE(source != NULL && source == (void *)&dummy);
	REQUIRE(targetp != NULL && *targetp == NULL);

	UNUSED(db);
	*targetp = source;
	return;
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, bool commit) {
	REQUIRE(versionp != NULL && *versionp == (void *)&dummy);
	REQUIRE(!commit);

	UNUSED(db);
	UNUSED(commit);

	*versionp = NULL;
}

static isc_result_t
createnode(dns_sdb_t *sdb, dns_sdbnode_t **nodep) {
	dns_sdbnode_t *node = NULL;

	node = isc_mem_get(sdb->common.mctx, sizeof(dns_sdbnode_t));

	node->sdb = NULL;
	dns_db_attach((dns_db_t *)sdb, (dns_db_t **)&node->sdb);
	ISC_LIST_INIT(node->lists);
	ISC_LIST_INIT(node->buffers);
	ISC_LINK_INIT(node, link);
	node->name = NULL;
	dns_rdatacallbacks_init(&node->callbacks);

	isc_refcount_init(&node->references, 1);

	node->magic = SDBLOOKUP_MAGIC;

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static void
destroynode(dns_sdbnode_t *node) {
	dns_rdatalist_t *list = NULL;
	dns_rdata_t *rdata = NULL;
	isc_buffer_t *b = NULL;
	dns_sdb_t *sdb = NULL;
	isc_mem_t *mctx = NULL;

	sdb = node->sdb;
	mctx = sdb->common.mctx;

	while (!ISC_LIST_EMPTY(node->lists)) {
		list = ISC_LIST_HEAD(node->lists);
		while (!ISC_LIST_EMPTY(list->rdata)) {
			rdata = ISC_LIST_HEAD(list->rdata);
			ISC_LIST_UNLINK(list->rdata, rdata, link);
			isc_mem_put(mctx, rdata, sizeof(dns_rdata_t));
		}
		ISC_LIST_UNLINK(node->lists, list, link);
		isc_mem_put(mctx, list, sizeof(dns_rdatalist_t));
	}

	while (!ISC_LIST_EMPTY(node->buffers)) {
		b = ISC_LIST_HEAD(node->buffers);
		ISC_LIST_UNLINK(node->buffers, b, link);
		isc_buffer_free(&b);
	}

	if (node->name != NULL) {
		dns_name_free(node->name, mctx);
		isc_mem_put(mctx, node->name, sizeof(dns_name_t));
	}

	node->magic = 0;
	isc_mem_put(mctx, node, sizeof(dns_sdbnode_t));
	dns_db_detach((dns_db_t **)(void *)&sdb);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = NULL;
	isc_result_t result;
	dns_sdbimplementation_t *imp = NULL;
	dns_name_t relname;
	dns_name_t *name = NULL;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	imp = sdb->implementation;
	dns_name_init(&relname, NULL);
	name = &relname;

	result = createnode(sdb, &node);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	LOCK(&sdb->implementation->driverlock);
	result = imp->methods->lookup(&sdb->common.origin, name, sdb->dbdata,
				      node, NULL, NULL);
	UNLOCK(&sdb->implementation->driverlock);
	if (result != ISC_R_SUCCESS &&
	    !(result == ISC_R_NOTFOUND && imp->methods->authority != NULL))
	{
		destroynode(node);
		return (result);
	}

	if (imp->methods->authority != NULL) {
		LOCK(&sdb->implementation->driverlock);
		result = imp->methods->authority(sdb->zone, sdb->dbdata, node);
		UNLOCK(&sdb->implementation->driverlock);
		if (result != ISC_R_SUCCESS) {
			destroynode(node);
			return (result);
		}
	}

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
findnodeext(dns_db_t *db, const dns_name_t *name, bool create,
	    dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	    dns_dbnode_t **nodep) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = NULL;
	isc_result_t result;
	bool isorigin;
	dns_sdbimplementation_t *imp = NULL;
	dns_name_t relname;
	unsigned int labels;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	UNUSED(name);
	UNUSED(create);

	imp = sdb->implementation;

	isorigin = dns_name_equal(name, &sdb->common.origin);

	labels = dns_name_countlabels(name) - dns_name_countlabels(&db->origin);
	dns_name_init(&relname, NULL);
	dns_name_getlabelsequence(name, 0, labels, &relname);
	name = &relname;

	result = createnode(sdb, &node);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	LOCK(&sdb->implementation->driverlock);
	result = imp->methods->lookup(&sdb->common.origin, name, sdb->dbdata,
				      node, methods, clientinfo);
	UNLOCK(&sdb->implementation->driverlock);
	if (result != ISC_R_SUCCESS && !(result == ISC_R_NOTFOUND && isorigin &&
					 imp->methods->authority != NULL))
	{
		destroynode(node);
		return (result);
	}

	if (isorigin && imp->methods->authority != NULL) {
		LOCK(&sdb->implementation->driverlock);
		result = imp->methods->authority(sdb->zone, sdb->dbdata, node);
		UNLOCK(&sdb->implementation->driverlock);
		if (result != ISC_R_SUCCESS) {
			destroynode(node);
			return (result);
		}
	}

	*nodep = node;
	return (ISC_R_SUCCESS);
}

static isc_result_t
findext(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	dns_dbnode_t **nodep, dns_name_t *foundname,
	dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_dbnode_t *node = NULL;
	dns_fixedname_t fname;
	dns_rdataset_t xrdataset;
	dns_name_t *xname = NULL;
	unsigned int nlabels, olabels;
	isc_result_t result;
	unsigned int i;
	unsigned int flags;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(nodep == NULL || *nodep == NULL);
	REQUIRE(version == NULL || version == (void *)&dummy);

	UNUSED(options);

	if (!dns_name_issubdomain(name, &db->origin)) {
		return (DNS_R_NXDOMAIN);
	}

	olabels = dns_name_countlabels(&db->origin);
	nlabels = dns_name_countlabels(name);

	xname = dns_fixedname_initname(&fname);

	if (rdataset == NULL) {
		dns_rdataset_init(&xrdataset);
		rdataset = &xrdataset;
	}

	result = DNS_R_NXDOMAIN;
	flags = sdb->implementation->flags;
	i = (flags & DNS_SDBFLAG_DNS64) != 0 ? nlabels : olabels;
	for (; i <= nlabels; i++) {
		/*
		 * Look up the next label.
		 */
		dns_name_getlabelsequence(name, nlabels - i, i, xname);
		result = findnodeext(db, xname, false, methods, clientinfo,
				     &node);
		if (result == ISC_R_NOTFOUND) {
			/*
			 * No data at zone apex?
			 */
			if (i == olabels) {
				return (DNS_R_BADDB);
			}
			result = DNS_R_NXDOMAIN;
			continue;
		}
		if (result != ISC_R_SUCCESS) {
			return (result);
		}

		/*
		 * DNS64 zone's don't have DNAME or NS records.
		 */
		if ((flags & DNS_SDBFLAG_DNS64) != 0) {
			goto skip;
		}

		/*
		 * DNS64 zone's don't have DNAME or NS records.
		 */
		if ((flags & DNS_SDBFLAG_DNS64) != 0) {
			goto skip;
		}

		/*
		 * Look for a DNAME at the current label, unless this is
		 * the qname.
		 */
		if (i < nlabels) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_dname, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_DNAME;
				break;
			}
		}

		/*
		 * Look for an NS at the current label, unless this is the
		 * origin or glue is ok.
		 */
		if (i != olabels && (options & DNS_DBFIND_GLUEOK) == 0) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_ns, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				if (i == nlabels && type == dns_rdatatype_any) {
					result = DNS_R_ZONECUT;
					dns_rdataset_disassociate(rdataset);
					if (sigrdataset != NULL &&
					    dns_rdataset_isassociated(
						    sigrdataset))
					{
						dns_rdataset_disassociate(
							sigrdataset);
					}
				} else {
					result = DNS_R_DELEGATION;
				}
				break;
			}
		}

		/*
		 * If the current name is not the qname, add another label
		 * and try again.
		 */
		if (i < nlabels) {
			destroynode(node);
			node = NULL;
			continue;
		}

	skip:
		/*
		 * If we're looking for ANY, we're done.
		 */
		if (type == dns_rdatatype_any) {
			result = ISC_R_SUCCESS;
			break;
		}

		/*
		 * Look for the qtype.
		 */
		result = findrdataset(db, node, version, type, 0, now, rdataset,
				      sigrdataset);
		if (result == ISC_R_SUCCESS) {
			break;
		}

		/*
		 * Look for a CNAME
		 */
		if (type != dns_rdatatype_cname) {
			result = findrdataset(db, node, version,
					      dns_rdatatype_cname, 0, now,
					      rdataset, sigrdataset);
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_CNAME;
				break;
			}
		}

		result = DNS_R_NXRRSET;
		break;
	}

	if (rdataset == &xrdataset && dns_rdataset_isassociated(rdataset)) {
		dns_rdataset_disassociate(rdataset);
	}

	if (foundname != NULL) {
		dns_name_copy(xname, foundname);
	}

	if (nodep != NULL) {
		*nodep = node;
	} else if (node != NULL) {
		detachnode(db, &node);
	}

	return (result);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = (dns_sdbnode_t *)source;

	REQUIRE(VALID_SDB(sdb));

	UNUSED(sdb);

	isc_refcount_increment(&node->references);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	dns_sdb_t *sdb = (dns_sdb_t *)db;
	dns_sdbnode_t *node = NULL;

	REQUIRE(VALID_SDB(sdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	UNUSED(sdb);

	node = (dns_sdbnode_t *)(*targetp);

	*targetp = NULL;

	if (isc_refcount_decrement(&node->references) == 1) {
		destroynode(node);
	}
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	REQUIRE(VALID_SDBNODE(node));

	dns_rdatalist_t *list = NULL;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)node;

	UNUSED(db);
	UNUSED(version);
	UNUSED(covers);
	UNUSED(now);
	UNUSED(sigrdataset);

	if (type == dns_rdatatype_rrsig) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	list = ISC_LIST_HEAD(sdbnode->lists);
	while (list != NULL) {
		if (list->type == type) {
			break;
		}
		list = ISC_LIST_NEXT(list, link);
	}
	if (list == NULL) {
		return (ISC_R_NOTFOUND);
	}

	list_tordataset(list, db, node, rdataset);

	return (ISC_R_SUCCESS);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     unsigned int options, isc_stdtime_t now,
	     dns_rdatasetiter_t **iteratorp) {
	sdb_rdatasetiter_t *iterator = NULL;

	REQUIRE(version == NULL || version == &dummy);

	UNUSED(version);
	UNUSED(now);

	iterator = isc_mem_get(db->mctx, sizeof(sdb_rdatasetiter_t));

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = NULL;
	attachnode(db, node, &iterator->common.node);
	iterator->common.version = version;
	iterator->common.options = options;
	iterator->common.now = now;

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

static bool
ispersistent(dns_db_t *db) {
	UNUSED(db);
	return (true);
}

static dns_dbmethods_t sdb_methods = {
	.destroy = destroy,
	.currentversion = currentversion,
	.attachversion = attachversion,
	.closeversion = closeversion,
	.attachnode = attachnode,
	.detachnode = detachnode,
	.findrdataset = findrdataset,
	.allrdatasets = allrdatasets,
	.ispersistent = ispersistent,
	.getoriginnode = getoriginnode,
	.findnodeext = findnodeext,
	.findext = findext,
};

static isc_result_t
create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
       void *driverarg, dns_db_t **dbp) {
	dns_sdb_t *sdb = NULL;
	isc_result_t result;
	char zonestr[DNS_NAME_MAXTEXT + 1];
	isc_buffer_t b;
	dns_sdbimplementation_t *imp = NULL;

	REQUIRE(driverarg != NULL);

	imp = driverarg;

	if (type != dns_dbtype_zone) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	sdb = isc_mem_get(mctx, sizeof(*sdb));
	*sdb = (dns_sdb_t){
		.common = { .methods = &sdb_methods, .rdclass = rdclass },
		.implementation = imp,
	};

	dns_name_init(&sdb->common.origin, NULL);

	isc_mem_attach(mctx, &sdb->common.mctx);

	result = dns_name_dupwithoffsets(origin, mctx, &sdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_lock;
	}

	isc_buffer_init(&b, zonestr, sizeof(zonestr));
	result = dns_name_totext(origin, true, &b);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_origin;
	}
	isc_buffer_putuint8(&b, 0);

	sdb->zone = isc_mem_strdup(mctx, zonestr);

	if (imp->methods->create != NULL) {
		LOCK(&sdb->implementation->driverlock);
		result = imp->methods->create(sdb->zone, argc, argv,
					      imp->driverdata, &sdb->dbdata);
		UNLOCK(&sdb->implementation->driverlock);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_zonestr;
		}
	}

	isc_refcount_init(&sdb->common.references, 1);

	sdb->common.magic = DNS_DB_MAGIC;
	sdb->common.impmagic = SDB_MAGIC;

	*dbp = (dns_db_t *)sdb;

	return (ISC_R_SUCCESS);

cleanup_zonestr:
	isc_mem_free(mctx, sdb->zone);
cleanup_origin:
	dns_name_free(&sdb->common.origin, mctx);
cleanup_lock:
	isc_mem_putanddetach(&mctx, sdb, sizeof(dns_sdb_t));

	return (result);
}

/*
 * Rdataset Methods
 */

static void
disassociate(dns_rdataset_t *rdataset) {
	dns_dbnode_t *node = rdataset->private5;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)node;
	dns_db_t *db = (dns_db_t *)sdbnode->sdb;

	detachnode(db, &node);
	dns_rdatalist_disassociate(rdataset);
}

static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	dns_dbnode_t *node = source->private5;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)node;
	dns_db_t *db = (dns_db_t *)sdbnode->sdb;
	dns_dbnode_t *tempdb = NULL;

	dns_rdatalist_clone(source, target);
	attachnode(db, node, &tempdb);
	source->private5 = tempdb;
}

static dns_rdatasetmethods_t sdb_rdataset_methods = {
	.disassociate = disassociate,
	.first = dns_rdatalist_first,
	.next = dns_rdatalist_next,
	.current = dns_rdatalist_current,
	.clone = rdataset_clone,
	.count = dns_rdatalist_count,
	.addnoqname = dns_rdatalist_addnoqname,
	.getnoqname = dns_rdatalist_getnoqname,
};

static void
list_tordataset(dns_rdatalist_t *rdatalist, dns_db_t *db, dns_dbnode_t *node,
		dns_rdataset_t *rdataset) {
	/*
	 * The sdb rdataset is an rdatalist with some additions.
	 *	- private1 & private2 are used by the rdatalist.
	 *	- private3 & private 4 are unused.
	 *	- private5 is the node.
	 */

	dns_rdatalist_tordataset(rdatalist, rdataset);

	rdataset->methods = &sdb_rdataset_methods;
	dns_db_attachnode(db, node, &rdataset->private5);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)(*iteratorp);
	detachnode(sdbiterator->common.db, &sdbiterator->common.node);
	isc_mem_put(sdbiterator->common.db->mctx, sdbiterator,
		    sizeof(sdb_rdatasetiter_t));
	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;
	dns_sdbnode_t *sdbnode = (dns_sdbnode_t *)iterator->node;

	if (ISC_LIST_EMPTY(sdbnode->lists)) {
		return (ISC_R_NOMORE);
	}
	sdbiterator->current = ISC_LIST_HEAD(sdbnode->lists);
	return (ISC_R_SUCCESS);
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;

	sdbiterator->current = ISC_LIST_NEXT(sdbiterator->current, link);
	if (sdbiterator->current == NULL) {
		return (ISC_R_NOMORE);
	} else {
		return (ISC_R_SUCCESS);
	}
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset) {
	sdb_rdatasetiter_t *sdbiterator = (sdb_rdatasetiter_t *)iterator;

	list_tordataset(sdbiterator->current, iterator->db, iterator->node,
			rdataset);
}
