/*
 * Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file */

#include <config.h>

#include <isc/log.h>
#include <isc/mem.h>
#include <isc/rwlock.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/nta.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rbt.h>
#include <dns/result.h>

static void
nta_detach(isc_mem_t *mctx, dns_nta_t **ntap) {
	unsigned int refs;
	dns_nta_t *nta = *ntap;

	REQUIRE(VALID_NTA(nta));

	*ntap = NULL;
	isc_refcount_decrement(&nta->refcount, &refs);
	if (refs == 0) {
		isc_refcount_destroy(&nta->refcount);
		isc_mem_put(mctx, nta, sizeof(dns_nta_t));
	}
}

static void
free_nta(void *data, void *arg) {
	dns_nta_t *nta = (dns_nta_t *) data;
	isc_mem_t *mctx = (isc_mem_t *) arg;

	nta_detach(mctx, &nta);
}

isc_result_t
dns_ntatable_create(isc_mem_t *mctx, dns_ntatable_t **ntatablep) {
	dns_ntatable_t *ntatable;
	isc_result_t result;

	/*
	 * Create an NTA table.
	 */

	REQUIRE(ntatablep != NULL && *ntatablep == NULL);

	ntatable = isc_mem_get(mctx, sizeof(*ntatable));
	if (ntatable == NULL)
		return (ISC_R_NOMEMORY);

	ntatable->table = NULL;
	result = dns_rbt_create(mctx, free_nta, mctx, &ntatable->table);
	if (result != ISC_R_SUCCESS)
		goto cleanup_ntatable;

	result = isc_rwlock_init(&ntatable->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup_rbt;

	ntatable->mctx = NULL;
	isc_mem_attach(mctx, &ntatable->mctx);
	ntatable->references = 1;
	ntatable->magic = NTATABLE_MAGIC;
	*ntatablep = ntatable;

	return (ISC_R_SUCCESS);

   cleanup_rbt:
	dns_rbt_destroy(&ntatable->table);

   cleanup_ntatable:
	isc_mem_put(mctx, ntatable, sizeof(*ntatable));

	return (result);
}

void
dns_ntatable_attach(dns_ntatable_t *source, dns_ntatable_t **targetp) {
	REQUIRE(VALID_NTATABLE(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	RWLOCK(&source->rwlock, isc_rwlocktype_write);

	INSIST(source->references > 0);
	source->references++;
	INSIST(source->references != 0);

	RWUNLOCK(&source->rwlock, isc_rwlocktype_write);

	*targetp = source;
}

void
dns_ntatable_detach(dns_ntatable_t **ntatablep) {
	isc_boolean_t destroy = ISC_FALSE;
	dns_ntatable_t *ntatable;

	REQUIRE(ntatablep != NULL && VALID_NTATABLE(*ntatablep));

	ntatable = *ntatablep;
	*ntatablep = NULL;

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);
	INSIST(ntatable->references > 0);
	ntatable->references--;
	if (ntatable->references == 0)
		destroy = ISC_TRUE;
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	if (destroy) {
		dns_rbt_destroy(&ntatable->table);
		isc_rwlock_destroy(&ntatable->rwlock);
		ntatable->magic = 0;
		isc_mem_putanddetach(&ntatable->mctx,
				     ntatable, sizeof(*ntatable));
	}
}

isc_result_t
dns_ntatable_add(dns_ntatable_t *ntatable, dns_name_t *name,
		 isc_uint32_t expiry)
{
	isc_result_t result;
	dns_nta_t *nta = NULL;
	dns_rbtnode_t *node;

	REQUIRE(VALID_NTATABLE(ntatable));

	result = dns_nta_create(ntatable->mctx, &nta);
	if (result != ISC_R_SUCCESS)
		return (result);

	nta->expiry = expiry;

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	node = NULL;
	result = dns_rbt_addnode(ntatable->table, name, &node);
	if (result == ISC_R_SUCCESS) {
		node->data = nta;
		nta = NULL;
	} else if (result == ISC_R_EXISTS) {
		dns_nta_t *n = node->data;
		if (n == NULL) {
			node->data = nta;
			nta = NULL;
		} else {
			n->expiry = nta->expiry;
			nta_detach(ntatable->mctx, &nta);
		}
		result = ISC_R_SUCCESS;
	}

	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	if (nta != NULL)
		nta_detach(ntatable->mctx, &nta);

	return (result);
}

/*
 * Caller must hold a write lock on rwlock.
 */
static isc_result_t
delete(dns_ntatable_t *ntatable, dns_name_t *name) {
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	REQUIRE(VALID_NTATABLE(ntatable));
	REQUIRE(name != NULL);

	result = dns_rbt_findnode(ntatable->table, name, NULL, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == ISC_R_SUCCESS) {
		if (node->data != NULL)
			result = dns_rbt_deletenode(ntatable->table,
						    node, ISC_FALSE);
		else
			result = ISC_R_NOTFOUND;
	} else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;

	return (result);
}

isc_result_t
dns_ntatable_delete(dns_ntatable_t *ntatable, dns_name_t *name) {
	isc_result_t result;

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_write);
	result = delete(ntatable, name);
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_boolean_t
dns_ntatable_covered(dns_ntatable_t *ntatable, isc_stdtime_t now,
		     dns_name_t *name, dns_name_t *anchor)
{
	isc_result_t result;
	dns_fixedname_t fn;
	dns_rbtnode_t *node;
	dns_name_t *foundname;
	dns_nta_t *nta = NULL;
	isc_boolean_t answer = ISC_FALSE;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	REQUIRE(ntatable == NULL || VALID_NTATABLE(ntatable));
	REQUIRE(dns_name_isabsolute(name));

	if (ntatable == NULL)
		return (ISC_FALSE);

	dns_fixedname_init(&fn);
	foundname = dns_fixedname_name(&fn);

 relock:
	RWLOCK(&ntatable->rwlock, locktype);
 again:
	node = NULL;
	result = dns_rbt_findnode(ntatable->table, name, foundname, &node, NULL,
				  DNS_RBTFIND_NOOPTIONS, NULL, NULL);
	if (result == DNS_R_PARTIALMATCH) {
		if (dns_name_issubdomain(foundname, anchor))
			result = ISC_R_SUCCESS;
	}
	if (result == ISC_R_SUCCESS) {
		nta = (dns_nta_t *) node->data;
		answer = ISC_TF(nta->expiry > now);
	}

	/* Deal with expired NTA */
	if (result == ISC_R_SUCCESS && !answer) {
		char nb[DNS_NAME_FORMATSIZE];

		if (locktype == isc_rwlocktype_read) {
			RWUNLOCK(&ntatable->rwlock, locktype);
			locktype = isc_rwlocktype_write;
			goto relock;
		}

		dns_name_format(foundname, nb, sizeof(nb));
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
			      DNS_LOGMODULE_NTA, ISC_LOG_INFO,
			      "deleting expired NTA at %s", nb);

		result = delete(ntatable, foundname);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DNSSEC,
				      DNS_LOGMODULE_NTA, ISC_LOG_INFO,
				      "deleting NTA failed: %s",
				      isc_result_totext(result));
		}
		goto again;
	}
	RWUNLOCK(&ntatable->rwlock, locktype);

	return (answer);
}

isc_result_t
dns_ntatable_dump(dns_ntatable_t *ntatable, FILE *fp) {
	isc_result_t result;
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;

	REQUIRE(VALID_NTATABLE(ntatable));

	RWLOCK(&ntatable->rwlock, isc_rwlocktype_read);
	dns_rbtnodechain_init(&chain, ntatable->mctx);
	result = dns_rbtnodechain_first(&chain, ntatable->table, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN)
		goto cleanup;
	for (;;) {
		dns_rbtnodechain_current(&chain, NULL, NULL, &node);
		if (node->data != NULL) {
			dns_nta_t *n = (dns_nta_t *) node->data;
			char nbuf[DNS_NAME_FORMATSIZE], tbuf[80];
			dns_name_t name;
			isc_time_t t;

			dns_name_init(&name, NULL);
			dns_rbt_namefromnode(node, &name);
			dns_name_format(&name, nbuf, sizeof(nbuf));
			isc_time_set(&t, n->expiry, 0);
			isc_time_formattimestamp(&t, tbuf, sizeof(tbuf));
			fprintf(fp, "%s : expiry %s\n", nbuf, tbuf);
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN) {
			if (result == ISC_R_NOMORE)
				result = ISC_R_SUCCESS;
			break;
		}
	}

   cleanup:
	dns_rbtnodechain_invalidate(&chain);
	RWUNLOCK(&ntatable->rwlock, isc_rwlocktype_read);
	return (result);
}

isc_result_t
dns_nta_create(isc_mem_t *mctx, dns_nta_t **target) {
	isc_result_t result;
	dns_nta_t *nta = NULL;

	REQUIRE(target != NULL && *target == NULL);

	nta = isc_mem_get(mctx, sizeof(dns_nta_t));
	if (nta == NULL)
		return (ISC_R_NOMEMORY);

	nta->expiry = 0;

	result = isc_refcount_init(&nta->refcount, 1);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, nta, sizeof(nta));
		return (result);
	}

	nta->magic = NTA_MAGIC;

	*target = nta;
	return (ISC_R_SUCCESS);
}
