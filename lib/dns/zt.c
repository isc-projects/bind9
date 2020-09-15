/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */


/*! \file */

#include <config.h>

#include <inttypes.h>
#include <stdbool.h>

#include <isc/file.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/name.h>
#include <dns/rbt.h>
#include <dns/rdataclass.h>
#include <dns/result.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zt.h>

struct dns_zt {
	/* Unlocked. */
	unsigned int		magic;
	isc_mem_t		*mctx;
	dns_rdataclass_t	rdclass;
	isc_rwlock_t		rwlock;
	dns_zt_allloaded_t	loaddone;
	void *			loaddone_arg;
	isc_refcount_t		references;

	/* Locked by lock. */
	bool			flush;
	unsigned int		loads_pending;
	dns_rbt_t		*table;
};

#define ZTMAGIC			ISC_MAGIC('Z', 'T', 'b', 'l')
#define VALID_ZT(zt) 		ISC_MAGIC_VALID(zt, ZTMAGIC)

struct zt_load_params {
	dns_zt_zoneloaded_t dl;
	bool newonly;
	struct dns_zt* zt;
};

static void
auto_detach(void *, void *);

static isc_result_t
load(dns_zone_t *zone, void *uap);

static isc_result_t
asyncload(dns_zone_t *zone, void *callback);

static isc_result_t
loadnew(dns_zone_t *zone, void *uap);

static isc_result_t
freezezones(dns_zone_t *zone, void *uap);

static isc_result_t
doneloading(dns_zt_t *zt, dns_zone_t *zone, isc_task_t *task);

isc_result_t
dns_zt_create(isc_mem_t *mctx, dns_rdataclass_t rdclass, dns_zt_t **ztp) {
	dns_zt_t *zt;
	isc_result_t result;

	REQUIRE(ztp != NULL && *ztp == NULL);

	zt = isc_mem_get(mctx, sizeof(*zt));
	if (zt == NULL)
		return (ISC_R_NOMEMORY);

	zt->table = NULL;
	result = dns_rbt_create(mctx, auto_detach, zt, &zt->table);
	if (result != ISC_R_SUCCESS)
		goto cleanup_zt;

	result = isc_rwlock_init(&zt->rwlock, 0, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup_rbt;

	zt->mctx = NULL;
	isc_mem_attach(mctx, &zt->mctx);
	isc_refcount_init(&zt->references, 1);
	zt->flush = false;
	zt->rdclass = rdclass;
	zt->magic = ZTMAGIC;
	zt->loaddone = NULL;
	zt->loaddone_arg = NULL;
	zt->loads_pending = 0;
	*ztp = zt;

	return (ISC_R_SUCCESS);

   cleanup_rbt:
	dns_rbt_destroy(&zt->table);

   cleanup_zt:
	isc_mem_put(mctx, zt, sizeof(*zt));

	return (result);
}

isc_result_t
dns_zt_mount(dns_zt_t *zt, dns_zone_t *zone) {
	isc_result_t result;
	dns_zone_t *dummy = NULL;
	dns_name_t *name;

	REQUIRE(VALID_ZT(zt));

	name = dns_zone_getorigin(zone);

	RWLOCK(&zt->rwlock, isc_rwlocktype_write);

	result = dns_rbt_addname(zt->table, name, zone);
	if (result == ISC_R_SUCCESS)
		dns_zone_attach(zone, &dummy);

	RWUNLOCK(&zt->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_zt_unmount(dns_zt_t *zt, dns_zone_t *zone) {
	isc_result_t result;
	dns_name_t *name;

	REQUIRE(VALID_ZT(zt));

	name = dns_zone_getorigin(zone);

	RWLOCK(&zt->rwlock, isc_rwlocktype_write);

	result = dns_rbt_deletename(zt->table, name, false);

	RWUNLOCK(&zt->rwlock, isc_rwlocktype_write);

	return (result);
}

isc_result_t
dns_zt_find(dns_zt_t *zt, const dns_name_t *name, unsigned int options,
	    dns_name_t *foundname, dns_zone_t **zonep)
{
	isc_result_t result;
	dns_zone_t *dummy = NULL;
	unsigned int rbtoptions = 0;

	REQUIRE(VALID_ZT(zt));

	if ((options & DNS_ZTFIND_NOEXACT) != 0)
		rbtoptions |= DNS_RBTFIND_NOEXACT;

	RWLOCK(&zt->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(zt->table, name, rbtoptions, foundname,
				  (void **) (void*)&dummy);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH)
		dns_zone_attach(dummy, zonep);

	RWUNLOCK(&zt->rwlock, isc_rwlocktype_read);

	return (result);
}

void
dns_zt_attach(dns_zt_t *zt, dns_zt_t **ztp) {

	REQUIRE(VALID_ZT(zt));
	REQUIRE(ztp != NULL && *ztp == NULL);

	isc_refcount_increment(&zt->references, NULL);

	*ztp = zt;
}

static isc_result_t
flush(dns_zone_t *zone, void *uap) {
	UNUSED(uap);
	return (dns_zone_flush(zone));
}

static void
zt_destroy(dns_zt_t *zt) {
	if (zt->flush) {
		(void)dns_zt_apply(zt, false, flush, NULL);
	}
	isc_refcount_destroy(&zt->references);
	dns_rbt_destroy(&zt->table);
	isc_rwlock_destroy(&zt->rwlock);
	zt->magic = 0;
	isc_mem_putanddetach(&zt->mctx, zt, sizeof(*zt));
}

static void
zt_flushanddetach(dns_zt_t **ztp, bool need_flush) {
	unsigned int refs;
	dns_zt_t *zt;

	REQUIRE(ztp != NULL && VALID_ZT(*ztp));

	zt = *ztp;
	*ztp = NULL;

	if (need_flush) {
		RWLOCK(&zt->rwlock, isc_rwlocktype_write);
		zt->flush = true;
		RWUNLOCK(&zt->rwlock, isc_rwlocktype_write);
	}

	isc_refcount_decrement(&zt->references, &refs);
	if (refs == 0) {
		zt_destroy(zt);
	}
}

void
dns_zt_flushanddetach(dns_zt_t **ztp) {
	zt_flushanddetach(ztp, true);
}

void
dns_zt_detach(dns_zt_t **ztp) {
	zt_flushanddetach(ztp, false);
}

isc_result_t
dns_zt_load(dns_zt_t *zt, bool stop) {
	isc_result_t result;

	REQUIRE(VALID_ZT(zt));

	RWLOCK(&zt->rwlock, isc_rwlocktype_read);
	result = dns_zt_apply(zt, stop, load, NULL);
	RWUNLOCK(&zt->rwlock, isc_rwlocktype_read);
	return (result);
}

static isc_result_t
load(dns_zone_t *zone, void *uap) {
	isc_result_t result;
	UNUSED(uap);

	result = dns_zone_load(zone);
	if (result == DNS_R_CONTINUE || result == DNS_R_UPTODATE)
		result = ISC_R_SUCCESS;

	return (result);
}

isc_result_t
dns_zt_asyncload(dns_zt_t *zt, dns_zt_allloaded_t alldone, void *arg) {
	return (dns_zt_asyncload2(zt, alldone, arg, false));
}

isc_result_t
dns_zt_asyncload2(dns_zt_t *zt, dns_zt_allloaded_t alldone, void *arg,
		  bool newonly)
{
	isc_result_t result;
	struct zt_load_params params;
	int pending;

	params.dl = doneloading;
	params.newonly = newonly;
	params.zt = zt;

	REQUIRE(VALID_ZT(zt));

	RWLOCK(&zt->rwlock, isc_rwlocktype_write);

	INSIST(zt->loads_pending == 0);
	/*
	 * Prevent loads_pending going to zero while kicking off the loads.
	 */
	zt->loads_pending++;
	result = dns_zt_apply2(zt, false, NULL, asyncload, &params);
	pending = --zt->loads_pending;
	if (pending != 0) {
		zt->loaddone = alldone;
		zt->loaddone_arg = arg;
	}
	RWUNLOCK(&zt->rwlock, isc_rwlocktype_write);

	if (pending == 0)
		alldone(arg);

	return (result);
}

/*
 * Initiates asynchronous loading of zone 'zone'.  'callback' is a
 * pointer to a function which will be used to inform the caller when
 * the zone loading is complete.
 */
static isc_result_t
asyncload(dns_zone_t *zone, void *paramsv) {
	isc_result_t result;
	struct zt_load_params * params = (struct zt_load_params*) paramsv;

	dns_zt_t *zt;

	REQUIRE(zone != NULL);
	zt = params->zt;
	INSIST(VALID_ZT(zt));

	isc_refcount_increment(&zt->references, NULL);
	zt->loads_pending++;

	result = dns_zone_asyncload2(zone, *params->dl, zt, params->newonly);
	if (result != ISC_R_SUCCESS) {
		unsigned int refs;
		zt->loads_pending--;
		isc_refcount_decrement(&zt->references, &refs);
		INSIST(refs > 0);
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_zt_loadnew(dns_zt_t *zt, bool stop) {
	isc_result_t result;

	REQUIRE(VALID_ZT(zt));

	RWLOCK(&zt->rwlock, isc_rwlocktype_read);
	result = dns_zt_apply(zt, stop, loadnew, NULL);
	RWUNLOCK(&zt->rwlock, isc_rwlocktype_read);
	return (result);
}

static isc_result_t
loadnew(dns_zone_t *zone, void *uap) {
	isc_result_t result;
	UNUSED(uap);

	result = dns_zone_loadnew(zone);
	if (result == DNS_R_CONTINUE || result == DNS_R_UPTODATE ||
	    result == DNS_R_DYNAMIC)
		result = ISC_R_SUCCESS;
	return (result);
}

isc_result_t
dns_zt_freezezones(dns_zt_t *zt, bool freeze) {
	isc_result_t result, tresult;

	REQUIRE(VALID_ZT(zt));

	RWLOCK(&zt->rwlock, isc_rwlocktype_read);
	result = dns_zt_apply2(zt, false, &tresult, freezezones, &freeze);
	RWUNLOCK(&zt->rwlock, isc_rwlocktype_read);
	if (tresult == ISC_R_NOTFOUND)
		tresult = ISC_R_SUCCESS;
	return ((result == ISC_R_SUCCESS) ? tresult : result);
}

static isc_result_t
freezezones(dns_zone_t *zone, void *uap) {
	bool freeze = *(bool *)uap;
	bool frozen;
	isc_result_t result = ISC_R_SUCCESS;
	char classstr[DNS_RDATACLASS_FORMATSIZE];
	char zonename[DNS_NAME_FORMATSIZE];
	dns_zone_t *raw = NULL;
	dns_view_t *view;
	const char *vname;
	const char *sep;
	int level;

	dns_zone_getraw(zone, &raw);
	if (raw != NULL)
		zone = raw;
	if (dns_zone_gettype(zone) != dns_zone_master) {
		if (raw != NULL)
			dns_zone_detach(&raw);
		return (ISC_R_SUCCESS);
	}
	if (!dns_zone_isdynamic(zone, true)) {
		if (raw != NULL)
			dns_zone_detach(&raw);
		return (ISC_R_SUCCESS);
	}

	frozen = dns_zone_getupdatedisabled(zone);
	if (freeze) {
		if (frozen)
			result = DNS_R_FROZEN;
		if (result == ISC_R_SUCCESS)
			result = dns_zone_flush(zone);
		if (result == ISC_R_SUCCESS)
			dns_zone_setupdatedisabled(zone, freeze);
	} else {
		if (frozen) {
			result = dns_zone_loadandthaw(zone);
			if (result == DNS_R_CONTINUE ||
			    result == DNS_R_UPTODATE)
				result = ISC_R_SUCCESS;
		}
	}
	view = dns_zone_getview(zone);
	if (strcmp(view->name, "_bind") == 0 ||
	    strcmp(view->name, "_default") == 0)
	{
		vname = "";
		sep = "";
	} else {
		vname = view->name;
		sep = " ";
	}
	dns_rdataclass_format(dns_zone_getclass(zone), classstr,
			      sizeof(classstr));
	dns_name_format(dns_zone_getorigin(zone), zonename, sizeof(zonename));
	level = (result != ISC_R_SUCCESS) ? ISC_LOG_ERROR : ISC_LOG_DEBUG(1);
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_ZONE,
		      level, "%s zone '%s/%s'%s%s: %s",
		      freeze ? "freezing" : "thawing",
		      zonename, classstr, sep, vname,
		      isc_result_totext(result));
	if (raw != NULL)
		dns_zone_detach(&raw);
	return (result);
}

void
dns_zt_setviewcommit(dns_zt_t *zt) {
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	isc_result_t result;

	REQUIRE(VALID_ZT(zt));

	dns_rbtnodechain_init(&chain, zt->mctx);

	result = dns_rbtnodechain_first(&chain, zt->table, NULL, NULL);
	while (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		result = dns_rbtnodechain_current(&chain, NULL, NULL,
						  &node);
		if (result == ISC_R_SUCCESS && node->data != NULL) {
			dns_zone_setviewcommit(node->data);
		}

		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}

	dns_rbtnodechain_invalidate(&chain);
}

void
dns_zt_setviewrevert(dns_zt_t *zt) {
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	isc_result_t result;

	REQUIRE(VALID_ZT(zt));

	dns_rbtnodechain_init(&chain, zt->mctx);

	result = dns_rbtnodechain_first(&chain, zt->table, NULL, NULL);
	while (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		result = dns_rbtnodechain_current(&chain, NULL, NULL,
						  &node);
		if (result == ISC_R_SUCCESS && node->data != NULL) {
			dns_zone_setviewrevert(node->data);
		}

		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}

	dns_rbtnodechain_invalidate(&chain);
}

isc_result_t
dns_zt_apply(dns_zt_t *zt, bool stop,
	     isc_result_t (*action)(dns_zone_t *, void *), void *uap)
{
	return (dns_zt_apply2(zt, stop, NULL, action, uap));
}

isc_result_t
dns_zt_apply2(dns_zt_t *zt, bool stop, isc_result_t *sub,
	      isc_result_t (*action)(dns_zone_t *, void *), void *uap)
{
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	isc_result_t result, tresult = ISC_R_SUCCESS;
	dns_zone_t *zone;

	REQUIRE(VALID_ZT(zt));
	REQUIRE(action != NULL);

	dns_rbtnodechain_init(&chain, zt->mctx);
	result = dns_rbtnodechain_first(&chain, zt->table, NULL, NULL);
	if (result == ISC_R_NOTFOUND) {
		/*
		 * The tree is empty.
		 */
		tresult = result;
		result = ISC_R_NOMORE;
	}
	while (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		result = dns_rbtnodechain_current(&chain, NULL, NULL,
						  &node);
		if (result == ISC_R_SUCCESS) {
			zone = node->data;
			if (zone != NULL)
				result = (action)(zone, uap);
			if (result != ISC_R_SUCCESS && stop) {
				tresult = result;
				goto cleanup;	/* don't break */
			} else if (result != ISC_R_SUCCESS &&
				   tresult == ISC_R_SUCCESS)
				tresult = result;
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;

 cleanup:
	dns_rbtnodechain_invalidate(&chain);
	if (sub != NULL)
		*sub = tresult;

	return (result);
}

/*
 * Decrement the loads_pending counter; when counter reaches
 * zero, call the loaddone callback that was initially set by
 * dns_zt_asyncload().
 */
static isc_result_t
doneloading(dns_zt_t *zt, dns_zone_t *zone, isc_task_t *task) {
	unsigned int refs;
	dns_zt_allloaded_t alldone = NULL;
	void *arg = NULL;

	UNUSED(zone);
	UNUSED(task);

	REQUIRE(VALID_ZT(zt));

	RWLOCK(&zt->rwlock, isc_rwlocktype_write);
	INSIST(zt->loads_pending != 0);
	zt->loads_pending--;
	if (zt->loads_pending == 0) {
		alldone = zt->loaddone;
		arg = zt->loaddone_arg;
		zt->loaddone = NULL;
		zt->loaddone_arg = NULL;
	}
	RWUNLOCK(&zt->rwlock, isc_rwlocktype_write);

	if (alldone != NULL)
		alldone(arg);

	isc_refcount_decrement(&zt->references, &refs);
	if (refs == 0) {
		zt_destroy(zt);
	}

	return (ISC_R_SUCCESS);
}

/***
 *** Private
 ***/

static void
auto_detach(void *data, void *arg) {
	dns_zone_t *zone = data;

	UNUSED(arg);
	dns_zone_detach(&zone);
}
