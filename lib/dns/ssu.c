/*
 * $Id: ssu.c,v 1.2 2000/02/14 21:09:16 bwelling Exp $
 * Principal Author: Brian Wellington
 */

#include <config.h>

#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/list.h>
#include <isc/magic.h>
#include <isc/result.h>
#include <isc/types.h>

#include <dns/name.h>
#include <dns/ssu.h>

#define SSUMAGIC		0x53535554 /* SSUT */
#define VALID_SSUTABLE(table)	ISC_MAGIC_VALID((table), SSUMAGIC)

typedef struct dns_ssurule dns_ssurule_t;

struct dns_ssurule {
	isc_boolean_t grant;	/* is this a grant or a deny? */
	isc_boolean_t self;	/* lets a key modify its own name */
	dns_name_t *identity;	/* the identity to match - NULL for any */
	dns_name_t *name;	/* the name being updated - NULL for any */
	unsigned int ntypes;	/* number of data types covered */
	dns_rdatatype_t *types;	/* the data types.  Can include ANY, */
				/* defaults to all but SIG,SOA,NS if NULL*/
	ISC_LINK(dns_ssurule_t) link;
};

struct dns_ssutable {
	isc_uint32_t magic;
	isc_mem_t *mctx;
	ISC_LIST(dns_ssurule_t) rules;
};

isc_result_t
dns_ssutable_create(isc_mem_t *mctx, dns_ssutable_t **table) {
	REQUIRE(table != NULL && *table == NULL);
	REQUIRE(mctx != NULL);

	*table = isc_mem_get(mctx, sizeof(dns_ssutable_t));
	if (*table == NULL)
		return (ISC_R_NOMEMORY);

	(*table)->mctx = mctx;
	ISC_LIST_INIT((*table)->rules);
	(*table)->magic = SSUMAGIC;
	return (ISC_R_SUCCESS);
}

void
dns_ssutable_destroy(dns_ssutable_t **table) {
	isc_mem_t *mctx;

	REQUIRE(table != NULL);
	REQUIRE(VALID_SSUTABLE(*table));

	mctx = (*table)->mctx;
	while (!ISC_LIST_EMPTY((*table)->rules)) {
		dns_ssurule_t *rule = ISC_LIST_HEAD((*table)->rules);
		if (rule->identity != NULL) {
			dns_name_free(rule->identity, mctx);
			isc_mem_put(mctx, rule->identity, sizeof(dns_name_t));
		}
		if (rule->name != NULL) {
			dns_name_free(rule->name, mctx);
			isc_mem_put(mctx, rule->name, sizeof(dns_name_t));
		}
		if (rule->types != NULL)
			isc_mem_put(mctx, rule->types,
				    rule->ntypes * sizeof(dns_rdatatype_t));
		ISC_LIST_UNLINK((*table)->rules, rule, link);
		isc_mem_put(mctx, rule, sizeof(dns_ssurule_t));
	}
	(*table)->magic = 0;
	isc_mem_put(mctx, *table, sizeof(dns_ssutable_t));
	*table = NULL;
}

isc_result_t
dns_ssutable_addrule(dns_ssutable_t *table, isc_boolean_t grant,
		     dns_name_t *identity, dns_name_t *name, isc_boolean_t self,
		     unsigned int ntypes, dns_rdatatype_t *types)
{
	dns_ssurule_t *rule;
	isc_mem_t *mctx;
	isc_result_t result;

	REQUIRE(VALID_SSUTABLE(table));
	REQUIRE(identity == NULL || dns_name_isabsolute(identity));
	REQUIRE(name == NULL || dns_name_isabsolute(name));
	if (self == ISC_TRUE)
		REQUIRE(name == NULL);
	if (ntypes > 0)
		REQUIRE(types != NULL);

	mctx = table->mctx;
	rule = isc_mem_get(mctx, sizeof(dns_ssurule_t));
	if (rule == NULL)
		return (ISC_R_NOMEMORY);

	rule->identity = NULL;
	rule->name = NULL;
	rule->types = NULL;

	rule->grant = grant;

	if (identity != NULL) {
		rule->identity = isc_mem_get(mctx, sizeof(dns_name_t));
		if (rule->identity == NULL) {
			result = ISC_R_NOMEMORY;
			goto failure;
		}
		dns_name_init(rule->identity, NULL);
		result = dns_name_dup(identity, mctx, rule->identity);
		if (result != ISC_R_SUCCESS)
			goto failure;
	}
	else
		rule->identity = NULL;

	if (name != NULL) {
		rule->name = isc_mem_get(mctx, sizeof(dns_name_t));
		if (rule->name == NULL) {
			result = ISC_R_NOMEMORY;
			goto failure;
		}
		dns_name_init(rule->name, NULL);
		result = dns_name_dup(name, mctx, rule->name);
		if (result != ISC_R_SUCCESS)
			goto failure;
	}
	else
		rule->name = NULL;

	rule->self = self;

	rule->ntypes = ntypes;
	if (ntypes > 0) {
		rule->types = isc_mem_get(mctx,
					  ntypes * sizeof(dns_rdatatype_t));
		if (rule->types == NULL) {
			result = ISC_R_NOMEMORY;
			goto failure;
		}
		memcpy(rule->types, types, ntypes * sizeof(dns_rdatatype_t));
	}
	else
		rule->types = NULL;

	ISC_LIST_APPEND(table->rules, rule, link);

	return (ISC_R_SUCCESS);

 failure:
	if (rule->identity != NULL) {
		if (dns_name_dynamic(rule->identity))
			dns_name_free(rule->identity, mctx);
		isc_mem_put(mctx, rule->identity, sizeof(dns_name_t));
	}
	if (rule->name != NULL) {
		if (dns_name_dynamic(rule->name))
			dns_name_free(rule->name, mctx);
		isc_mem_put(mctx, rule->name, sizeof(dns_name_t));
	}
	if (rule->types != NULL)
		isc_mem_put(mctx, rule->types,
			    ntypes * sizeof(dns_rdatatype_t));
	isc_mem_put(mctx, rule, sizeof(dns_ssurule_t));

	return (result);
}

static inline isc_boolean_t
isusertype(dns_rdatatype_t type) {
	return (type != dns_rdatatype_ns &&
		type != dns_rdatatype_soa &&
		type != dns_rdatatype_sig);
}

isc_boolean_t
dns_ssutable_checkrules(dns_ssutable_t *table, dns_name_t *signer,
			dns_name_t *name, dns_rdatatype_t type)
{
	dns_ssurule_t *rule;
	unsigned int i;

	REQUIRE(VALID_SSUTABLE(table));
	REQUIRE(signer == NULL || dns_name_isabsolute(signer));
	REQUIRE(dns_name_isabsolute(name));

	if (signer == NULL)
		return (ISC_FALSE);
	rule = ISC_LIST_HEAD(table->rules);
		rule = ISC_LIST_NEXT(rule, link);
	for (rule = ISC_LIST_HEAD(table->rules);
	     rule != NULL;
	     rule = ISC_LIST_NEXT(rule, link))
	{
		if (rule->self && !dns_name_equal(signer, name))
			continue;
		if (rule->identity != NULL) {
			if (dns_name_iswildcard(rule->identity)) {
				if (!dns_name_matcheswildcard(signer,
							      rule->identity))
					continue;
			}
			else {
				if (!dns_name_equal(signer, rule->identity))
					continue;
			}
		}
		if (rule->name != NULL) {
			if (dns_name_iswildcard(rule->name)) {
				if (!dns_name_matcheswildcard(name, rule->name))
					continue;
			}
			else {
				if (!dns_name_equal(name, rule->name))
					continue;
			}
		}
		if (rule->ntypes == 0) {
			if (!isusertype(type))
				continue;
		}
		else {
			for (i = 0; i < rule->ntypes; i++) {
				if (rule->types[i] == dns_rdatatype_any ||
				    rule->types[i] == type)
					break;
			}
			if (i == rule->ntypes)
				continue;
		}
		return (rule->grant);
	}

	return (ISC_FALSE);
}
