/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
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

#include <isc/hex.h>
#include <isc/mem.h>
#include <isc/parseint.h>
#include <isc/result.h>
#include <isc/sha2.h>
#include <isc/task.h>

#include <dns/catz.h>
#include <dns/dbiterator.h>
#include <dns/events.h>
#include <dns/rdatasetiter.h>
#include <dns/view.h>
#include <dns/zone.h>


/*%
 * Single member zone in a catalog
 */
struct dns_catz_entry {
	dns_name_t		name;
	dns_catz_options_t	opts;
	isc_refcount_t		refs;
};

/*%
 * Catalog zone
 */
struct dns_catz_zone {
	dns_name_t		name;
	dns_catz_zones_t	*catzs;
	dns_rdata_t		soa;
	/* key in entries is 'mhash', not domain name! */
	isc_ht_t		*entries;
	/*
	 * defoptions are taken from named.conf
	 * zoneoptions are global options from zone
	 */
	dns_catz_options_t	defoptions;
	dns_catz_options_t	zoneoptions;
	isc_time_t		lastupdated;
	isc_boolean_t		updatepending;
	isc_uint32_t		version;

	dns_db_t		*db;
	dns_dbversion_t		*dbversion;

	isc_timer_t		*updatetimer;
	isc_event_t		updateevent;

	isc_boolean_t		active;

	isc_refcount_t		refs;
};

/*%
 * Collection of catalog zones for a view
 */
struct dns_catz_zones {
	isc_ht_t			*zones;
	isc_mem_t			*mctx;
	isc_refcount_t			refs;
	isc_mutex_t			lock;
	dns_catz_zonemodmethods_t	*zmm;
	isc_taskmgr_t			*taskmgr;
	isc_timermgr_t			*timermgr;
	dns_view_t			*view;
	isc_task_t			*updater;
};

void
dns_catz_options_init(dns_catz_options_t *options) {
	options->masters.addrs = NULL;
	options->masters.dscps = NULL;
	options->masters.keys = NULL;
	options->masters.count = 0;

	options->in_memory = ISC_FALSE;
	options->min_update_interval = 5;
	options->zonedir = NULL;
}

void
dns_catz_options_free(dns_catz_options_t *options, isc_mem_t *mctx) {
	if (options->masters.count > 0)
		dns_ipkeylist_clear(mctx, &options->masters);
	if (options->zonedir != NULL) {
		isc_mem_free(mctx, options->zonedir);
		options->zonedir = NULL;
	}
}

isc_result_t
dns_catz_options_copy(isc_mem_t *mctx, const dns_catz_options_t *src,
		      dns_catz_options_t *dst)
{
	/* TODO error handling */
	REQUIRE(dst != NULL);
	REQUIRE(dst->masters.count == 0);

	if (src->masters.count != 0)
		dns_ipkeylist_copy(mctx, &src->masters, &dst->masters);

	if (dst->zonedir != NULL) {
		isc_mem_free(mctx, dst->zonedir);
		dst->zonedir = NULL;
	}

	if (src->zonedir != NULL)
		dst->zonedir = isc_mem_strdup(mctx, src->zonedir);

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_catz_options_setdefault(isc_mem_t *mctx, const dns_catz_options_t *defaults,
			    dns_catz_options_t *opts)
{
	if (opts->masters.count == 0)
		dns_catz_options_copy(mctx, defaults, opts);
	else if (defaults->zonedir != NULL)
		opts->zonedir = isc_mem_strdup(mctx, defaults->zonedir);

	/* This option is always taken from config, so it's always 'default' */
	opts->in_memory = defaults->in_memory;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_catz_entry_new(isc_mem_t *mctx, const dns_name_t *domain,
		   dns_catz_entry_t **nentryp)
{
	dns_catz_entry_t *nentry;
	isc_result_t result;

	REQUIRE(nentryp != NULL && *nentryp == NULL);
	REQUIRE(domain != NULL);

	nentry = isc_mem_get(mctx, sizeof(dns_catz_entry_t));
	if (nentry == NULL)
		return (ISC_R_NOMEMORY);

	dns_name_init(&nentry->name, NULL);
	result = dns_name_dup(domain, mctx, &nentry->name);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	dns_catz_options_init(&nentry->opts);
	isc_refcount_init(&nentry->refs, 1);
	*nentryp = nentry;
	return (ISC_R_SUCCESS);

cleanup:
	isc_mem_put(mctx, nentry, sizeof(dns_catz_entry_t));
	return (result);
}

dns_name_t *
dns_catz_entry_getname(dns_catz_entry_t *entry) {
	return (&entry->name);
}

isc_result_t
dns_catz_entry_copy(dns_catz_zone_t *zone, const dns_catz_entry_t *entry,
		    dns_catz_entry_t **nentryp)
{
	isc_result_t result;
	dns_catz_entry_t *nentry = NULL;

	result = dns_catz_entry_new(zone->catzs->mctx, &entry->name, &nentry);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_catz_options_copy(zone->catzs->mctx, &entry->opts,
				       &nentry->opts);
	if (result != ISC_R_SUCCESS)
		dns_catz_entry_detach(zone, &nentry);

	*nentryp = nentry;
	return (result);
}

void
dns_catz_entry_attach(dns_catz_entry_t *entry, dns_catz_entry_t **entryp) {
	REQUIRE(entryp != NULL && *entryp == NULL);
	isc_refcount_increment(&entry->refs, NULL);
	*entryp = entry;
}

void
dns_catz_entry_detach(dns_catz_zone_t *zone, dns_catz_entry_t **entryp) {
	dns_catz_entry_t *entry;
	isc_mem_t *mctx;
	unsigned int refs;

	REQUIRE(entryp != NULL && *entryp != NULL);

	entry = *entryp;
	*entryp = NULL;

	mctx = zone->catzs->mctx;

	isc_refcount_decrement(&entry->refs, &refs);
	if (refs == 0) {
		dns_catz_options_free(&entry->opts, mctx);
		dns_name_free(&entry->name, mctx);
		isc_refcount_destroy(&entry->refs);
		isc_mem_put(mctx, entry, sizeof(dns_catz_entry_t));
	}
}

isc_boolean_t
dns_catz_entry_validate(const dns_catz_entry_t *entry) {
	UNUSED(entry);

	return (ISC_TRUE);
}

isc_boolean_t
dns_catz_entry_cmp(const dns_catz_entry_t *ea, const dns_catz_entry_t *eb) {
	if (ea->opts.masters.count != eb->opts.masters.count)
		return (ISC_FALSE);

	if (memcmp(ea->opts.masters.addrs, eb->opts.masters.addrs,
		   ea->opts.masters.count * sizeof(isc_sockaddr_t)))
		return (ISC_FALSE);

	/* xxxwpk TODO compare dscps/keys! */
	return (ISC_TRUE);
}

dns_name_t *
dns_catz_zone_getname(dns_catz_zone_t *zone) {
	REQUIRE(zone != NULL);

	return (&zone->name);
}

dns_catz_options_t *
dns_catz_zone_getdefoptions(dns_catz_zone_t *zone) {
	REQUIRE(zone != NULL);

	return (&zone->defoptions);
}

void
dns_catz_zone_resetdefoptions(dns_catz_zone_t *zone) {
	REQUIRE(zone != NULL);

	dns_catz_options_free(&zone->defoptions, zone->catzs->mctx);
	dns_catz_options_init(&zone->defoptions);
}

static isc_result_t
newzonewalk(void *udata, const unsigned char *key, isc_uint32_t keysize,
	    void *data)
{
	isc_result_t result;
	dns_catz_zone_t *zone = udata;
	dns_catz_entry_t *nentry = (dns_catz_entry_t *) data;
	dns_catz_entry_t *oentry;
	char cznamebuf[DNS_NAME_FORMATSIZE];
	char znamebuf[DNS_NAME_FORMATSIZE];
	isc_buffer_t czname;
	isc_buffer_t zname;

	REQUIRE(zone != NULL);
	REQUIRE(zone->catzs->view != NULL);

	dns_catz_options_setdefault(zone->catzs->mctx, &zone->zoneoptions,
				    &nentry->opts);
	isc_buffer_init(&czname, cznamebuf, DNS_NAME_FORMATSIZE);
	isc_buffer_init(&zname, znamebuf, DNS_NAME_FORMATSIZE);
	dns_name_totext(&zone->name, ISC_TRUE, &czname);
	isc_buffer_putuint8(&czname, 0);
	dns_name_totext(&nentry->name, ISC_TRUE, &zname);
	isc_buffer_putuint8(&zname, 0);

	result = isc_ht_find(zone->entries, key, keysize, (void **) &oentry);
	if (result != ISC_R_SUCCESS) {
		result = zone->catzs->zmm->addzone(nentry, zone,
						   zone->catzs->view,
						   zone->catzs->taskmgr,
						   zone->catzs->zmm->udata);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_INFO,
			      "catz: adding zone '%s' from catalog '%s' - %s",
			      znamebuf, cznamebuf, isc_result_totext(result));
		return (ISC_R_SUCCESS);
	}

	if (dns_catz_entry_cmp(oentry, nentry) != ISC_TRUE) {
		result = zone->catzs->zmm->modzone(nentry, zone,
						   zone->catzs->view,
						   zone->catzs->taskmgr,
						   zone->catzs->zmm->udata);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_INFO,
			      "catz: modifying zone '%s' from catalog "
			      "'%s' - %s",
			      znamebuf, cznamebuf,
			      isc_result_totext(result));
	}

	dns_catz_entry_detach(zone, &oentry);
	result = isc_ht_delete(zone->entries, key, keysize);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	return (ISC_R_SUCCESS);
}

static isc_result_t
oldzonewalk(void *udata, const unsigned char *key, isc_uint32_t keysize,
	    void *data)
{
	isc_result_t result;
	dns_catz_zone_t *zone = udata;
	dns_catz_entry_t *entry = (dns_catz_entry_t *) data;
	char cznamebuf[DNS_NAME_FORMATSIZE];
	char znamebuf[DNS_NAME_FORMATSIZE];
	isc_buffer_t czname;
	isc_buffer_t zname;

	UNUSED(key);
	UNUSED(keysize);

	REQUIRE(zone != NULL);
	REQUIRE(zone->catzs->view != NULL);

	isc_buffer_init(&czname, cznamebuf, DNS_NAME_MAXTEXT);
	isc_buffer_init(&zname, znamebuf, DNS_NAME_MAXTEXT);
	dns_name_totext(&zone->name, ISC_TRUE, &czname);
	isc_buffer_putuint8(&czname, 0);
	dns_name_totext(&entry->name, ISC_TRUE, &zname);
	isc_buffer_putuint8(&czname, 0);
	result = zone->catzs->zmm->delzone(entry, zone, zone->catzs->view,
				  zone->catzs->taskmgr,
				  zone->catzs->zmm->udata);
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_MASTER, ISC_LOG_INFO,
		      "catz: deleting zone '%s' from catalog '%s' - %s",
		      znamebuf, cznamebuf, isc_result_totext(result));
	dns_catz_entry_detach(zone, &entry);

	return (ISC_R_EXISTS);
}

isc_result_t
dns_catz_zones_merge(dns_catz_zone_t *target, dns_catz_zone_t *newzone) {
	isc_result_t result;

	REQUIRE(target != NULL);
	REQUIRE(newzone != NULL);

	/* TODO verify the new zone first! */

	/* Copy zoneoptions from newzone into target. */
	dns_catz_options_free(&target->zoneoptions, target->catzs->mctx);
	dns_catz_options_copy(target->catzs->mctx, &newzone->zoneoptions,
			      &target->zoneoptions);
	dns_catz_options_setdefault(target->catzs->mctx, &target->defoptions,
				    &target->zoneoptions);

	/*
	 * first - walk the new zone and find all nodes that are not in the
	 * old zone, or are in both zones and are modified
	 */
	result = isc_ht_walk(newzone->entries, newzonewalk, target);
	/* newzonewalk always returns ISC_R_SUCCESS */
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	/*
	 * then - walk the old zone; only deleted entries should remain
	 * return (ISC_R_SUCCESS);
	 */
	result = isc_ht_walk(target->entries, oldzonewalk, target);
	/*
	 * oldzonewalk always returns ISC_R_EXISTS, so walk should return
	 * ISC_R_SUCCESS
	 */
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	/* at this moment target->entries has to be be empty */
	INSIST(isc_ht_count(target->entries) == 0);
	isc_ht_destroy(&target->entries);

	target->entries = newzone->entries;
	newzone->entries = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_catz_new_zones(dns_catz_zones_t **catzsp, dns_catz_zonemodmethods_t *zmm,
		   isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
		   isc_timermgr_t *timermgr)
{
	dns_catz_zones_t *new_zones;
	isc_result_t result;

	REQUIRE(catzsp != NULL && *catzsp == NULL);
	REQUIRE(zmm != NULL);

	new_zones = isc_mem_get(mctx, sizeof(*new_zones));
	if (new_zones == NULL)
		return (ISC_R_NOMEMORY);
	memset(new_zones, 0, sizeof(*new_zones));

	result = isc_mutex_init(&new_zones->lock);
	if (result != ISC_R_SUCCESS)
		goto cleanup_newzones;

	result = isc_refcount_init(&new_zones->refs, 1);
	if (result != ISC_R_SUCCESS)
		goto cleanup_mutex;

	result = isc_ht_init(&new_zones->zones, mctx, 4);
	if (result != ISC_R_SUCCESS)
		goto cleanup_refcount;

	isc_mem_attach(mctx, &new_zones->mctx);
	new_zones->zmm = zmm;
	new_zones->timermgr = timermgr;
	new_zones->taskmgr = taskmgr;

	result = isc_task_create(taskmgr, 0, &new_zones->updater);
	if (result != ISC_R_SUCCESS)
		goto cleanup_ht;

	*catzsp = new_zones;
	return (ISC_R_SUCCESS);

  cleanup_ht:
	isc_ht_destroy(&new_zones->zones);
  cleanup_refcount:
	isc_refcount_destroy(&new_zones->refs);
  cleanup_mutex:
	isc_mutex_destroy(&new_zones->lock);
  cleanup_newzones:
	isc_mem_put(mctx, new_zones, sizeof(*new_zones));

	return (result);
}

void
dns_catz_catzs_set_view(dns_catz_zones_t *catzs, dns_view_t *view) {
	REQUIRE(catzs != NULL);
	REQUIRE(view != NULL);
	/* either it's a new one or it's being reconfigured */
	REQUIRE(catzs->view == NULL || !strcmp(catzs->view->name, view->name));
	catzs->view = view;
}

isc_result_t
dns_catz_new_zone(dns_catz_zones_t *catzs, dns_catz_zone_t **zonep,
		  const dns_name_t *name) {
	isc_result_t result;
	dns_catz_zone_t *new_zone;

	REQUIRE(zonep != NULL && *zonep == NULL);

	new_zone = isc_mem_get(catzs->mctx, sizeof(*new_zone));
	if (new_zone == NULL)
		return (ISC_R_NOMEMORY);

	memset(new_zone, 0, sizeof(*new_zone));

	dns_name_init(&new_zone->name, NULL);

	result = dns_name_dup(name, catzs->mctx, &new_zone->name);
	if (result != ISC_R_SUCCESS)
		goto cleanup_newzone;

	result = isc_ht_init(&new_zone->entries, catzs->mctx, 4);
	if (result != ISC_R_SUCCESS)
		goto cleanup_name;

	new_zone->updatetimer = NULL;
	result = isc_timer_create(catzs->timermgr, isc_timertype_inactive,
				  NULL, NULL, catzs->updater,
				  dns_catz_update_taskaction,
				  new_zone, &new_zone->updatetimer);
	if (result != ISC_R_SUCCESS)
		goto cleanup_ht;

	isc_time_settoepoch(&new_zone->lastupdated);
	new_zone->updatepending = ISC_FALSE;
	new_zone->db = NULL;
	new_zone->dbversion = NULL;
	new_zone->catzs = catzs;
	dns_catz_options_init(&new_zone->defoptions);
	dns_catz_options_init(&new_zone->zoneoptions);
	new_zone->active = ISC_TRUE;
	new_zone->version = (isc_uint32_t)(-1);
	isc_refcount_init(&new_zone->refs, 1);

	*zonep = new_zone;

	return (ISC_R_SUCCESS);

  cleanup_ht:
	isc_ht_destroy(&new_zone->entries);
  cleanup_name:
	dns_name_free(&new_zone->name, catzs->mctx);
  cleanup_newzone:
	isc_mem_put(catzs->mctx, new_zone, sizeof(*new_zone));

	return (result);
}

isc_result_t
dns_catz_add_zone(dns_catz_zones_t *catzs, const dns_name_t *name,
		  dns_catz_zone_t **zonep)
{
	dns_catz_zone_t *new_zone = NULL;
	isc_result_t result;

	REQUIRE(catzs != NULL);
	REQUIRE(name != NULL);
	REQUIRE(zonep != NULL && *zonep == NULL);

	LOCK(&catzs->lock);

	result = dns_catz_new_zone(catzs, &new_zone, name);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = isc_ht_add(catzs->zones, new_zone->name.ndata,
			    new_zone->name.length, new_zone);
	if (result != ISC_R_SUCCESS) {
		dns_catz_zone_detach(&new_zone);
		if (result != ISC_R_EXISTS)
			goto cleanup;
	}

	if (result == ISC_R_EXISTS) {
		result = isc_ht_find(catzs->zones, name->ndata,
				     name->length, (void **) &new_zone);
		INSIST(result == ISC_R_SUCCESS && !new_zone->active);
		new_zone->active = ISC_TRUE;
	}

	*zonep = new_zone;

 cleanup:
	UNLOCK(&catzs->lock);

	return (result);
}

dns_catz_zone_t *
dns_catz_get_zone(dns_catz_zones_t *catzs, const dns_name_t *name) {
	isc_result_t result;
	dns_catz_zone_t *found;

	result = isc_ht_find(catzs->zones, name->ndata, name->length,
			     (void **) &found);
	if (result != ISC_R_SUCCESS)
		return (NULL);

	return (found);
}

void
dns_catz_catzs_attach(dns_catz_zones_t *catzs, dns_catz_zones_t **catzsp) {
	REQUIRE(catzsp != NULL && *catzsp == NULL);

	isc_refcount_increment(&catzs->refs, NULL);
	*catzsp = catzs;
}

static isc_result_t
freewalk(void *udata, const unsigned char *key, isc_uint32_t keysize,
	 void *data)
{
	dns_catz_zone_t *zone = (dns_catz_zone_t *) udata;
	dns_catz_entry_t *entry = (dns_catz_entry_t *) data;

	UNUSED(key);
	UNUSED(keysize);

	dns_catz_entry_detach(zone, &entry);

	return (ISC_R_EXISTS);
}

void
dns_catz_zone_attach(dns_catz_zone_t *zone, dns_catz_zone_t **zonep) {
	REQUIRE(zonep != NULL && *zonep == NULL);
	isc_refcount_increment(&zone->refs, NULL);
	*zonep = zone;
}

void
dns_catz_zone_detach(dns_catz_zone_t **zonep) {
	dns_catz_zone_t *zone;
	isc_mem_t *mctx;
	unsigned int refs;

	REQUIRE(zonep != NULL && *zonep != NULL);

	zone = *zonep;
	*zonep = NULL;
	isc_refcount_decrement(&zone->refs, &refs);
	if (refs == 0) {
		if (zone->entries != NULL) {
			isc_result_t result;

			/*
			 * freewalk always returns ISC_R_EXISTS, triggering
			 * isc_ht_walk to delete the node.  If isc_ht_walk
			 * returns an error, it is a critical condition
			 */
			result = isc_ht_walk(zone->entries, freewalk, zone);
			INSIST(result == ISC_R_SUCCESS);

			/* the hashtable has to be empty now */
			INSIST(isc_ht_count(zone->entries) == 0);
			isc_ht_destroy(&zone->entries);
		}
		mctx = zone->catzs->mctx;
		isc_timer_detach(&zone->updatetimer);
		isc_refcount_destroy(&zone->refs);
		dns_name_free(&zone->name, mctx);
		dns_catz_options_free(&zone->defoptions, mctx);
		dns_catz_options_free(&zone->zoneoptions, mctx);
		zone->catzs = NULL;
		isc_mem_put(mctx, zone, sizeof(dns_catz_zone_t));
	}
}

static isc_result_t
catzsfreewalk(void *udata, const unsigned char *key, isc_uint32_t keysize,
	      void *data)
{
	dns_catz_zones_t *catzs = (dns_catz_zones_t *) udata;
	dns_catz_zone_t *zone = (dns_catz_zone_t *) data;

	UNUSED(key);
	UNUSED(keysize);
	UNUSED(catzs);

	dns_catz_zone_detach(&zone);

	return (ISC_R_EXISTS);
}

void
dns_catz_catzs_detach(dns_catz_zones_t ** catzsp) {
	dns_catz_zones_t *catzs;
	isc_result_t result;
	unsigned int refs;

	REQUIRE(catzsp != NULL);
	catzs = *catzsp;
	REQUIRE(catzs != NULL);

	*catzsp = NULL;
	isc_refcount_decrement(&catzs->refs, &refs);

	if (refs == 0) {
		DESTROYLOCK(&catzs->lock);
		if (catzs->zones != NULL) {
			result = isc_ht_walk(catzs->zones, catzsfreewalk,
					     catzs);
			INSIST(result == ISC_R_SUCCESS);
			INSIST(isc_ht_count(catzs->zones) == 0);
			isc_ht_destroy(&catzs->zones);
		}
		isc_refcount_destroy(&catzs->refs);
		isc_task_destroy(&catzs->updater);
		isc_mem_putanddetach(&catzs->mctx, catzs, sizeof(*catzs));
	}
}

typedef enum {
	CATZ_OPT_NONE,
	CATZ_OPT_ZONES,
	CATZ_OPT_MASTERS,
	CATZ_OPT_ALLOW_QUERY,
	CATZ_OPT_ALLOW_TRANSFER,
	CATZ_OPT_VERSION,
} catz_opt_t;

static isc_boolean_t
catz_opt_cmp(const dns_label_t *option, const char *opt) {
	unsigned int l = strlen(opt);
	if (option->length - 1 == l &&
	    memcmp(opt, option->base + 1, l - 1) == 0)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

static catz_opt_t
catz_get_option(const dns_label_t *option) {
	if (catz_opt_cmp(option, "zones"))
		return (CATZ_OPT_ZONES);
	else if (catz_opt_cmp(option, "masters"))
		return (CATZ_OPT_MASTERS);
	else if (catz_opt_cmp(option, "allow-query"))
		return (CATZ_OPT_ALLOW_QUERY);
	else if (catz_opt_cmp(option, "allow-transfer"))
		return (CATZ_OPT_ALLOW_TRANSFER);
	else if (catz_opt_cmp(option, "version"))
		return (CATZ_OPT_VERSION);
	else
		return (CATZ_OPT_NONE);
}

static isc_result_t
catz_process_global_list(dns_catz_zone_t *zone, catz_opt_t opt,
			 dns_rdataset_t *value, dns_label_t *mhash)
{
	isc_result_t result;
	dns_rdata_t rdata;
	dns_rdata_ptr_t ptr;
	dns_catz_entry_t *entry = NULL;
	dns_name_t emptyname;

	REQUIRE(zone != NULL);
	REQUIRE(DNS_RDATASET_VALID(value));
	REQUIRE(mhash != NULL);

	dns_name_init(&emptyname, NULL);
	switch (opt) {
	case CATZ_OPT_ZONES:
		if (value->rdclass != dns_rdataclass_in ||
		    value->type != dns_rdatatype_ptr) {
			break;
		}

		/*
		 * We only take -first- value, as mhash must be
		 * different
		 */
		result = dns_rdataset_first(value);
		if (result != ISC_R_SUCCESS)
			break;

		dns_rdata_init(&rdata);
		dns_rdataset_current(value, &rdata);

		result = dns_rdata_tostruct(&rdata, &ptr, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		result = isc_ht_find(zone->entries, mhash->base,
				     mhash->length, (void **) &entry);
		if (result == ISC_R_SUCCESS) {
			if (dns_name_countlabels(&entry->name) != 0) {
				/* we have a duplicate */
				dns_rdata_freestruct(&ptr);
				return (ISC_R_FAILURE);
			} else {
				result = dns_name_dup(&ptr.ptr,
						      zone->catzs->mctx,
						      &entry->name);
				if (result != ISC_R_SUCCESS) {
					dns_rdata_freestruct(&ptr);
					return (result);
				}
			}
		} else {
			result = dns_catz_entry_new(zone->catzs->mctx, &ptr.ptr,
						    &entry);
			if (result != ISC_R_SUCCESS) {
				dns_rdata_freestruct(&ptr);
				return (result);
			}

			result = isc_ht_add(zone->entries, mhash->base,
					    mhash->length, entry);
			if (result != ISC_R_SUCCESS) {
				dns_rdata_freestruct(&ptr);
				dns_catz_entry_detach(zone, &entry);
				return (result);
			}
		}

		dns_rdata_freestruct(&ptr);
		break;
	default:
		return (ISC_R_FAILURE);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
catz_process_version(dns_catz_zone_t *zone, dns_rdataset_t *value) {
	isc_result_t result;
	dns_rdata_t rdata;
	dns_rdata_txt_t rdatatxt;
	dns_rdata_txt_string_t rdatastr;
	isc_uint32_t tversion;
	char t[16];

	REQUIRE(zone != NULL);
	REQUIRE(DNS_RDATASET_VALID(value));

	if (value->rdclass != dns_rdataclass_in ||
	    value->type != dns_rdatatype_txt)
		return (ISC_R_FAILURE);

	result = dns_rdataset_first(value);
	if (result != ISC_R_SUCCESS)
		return (result);

	dns_rdata_init(&rdata);
	dns_rdataset_current(value, &rdata);

	result = dns_rdata_tostruct(&rdata, &rdatatxt, NULL);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_rdata_txt_first(&rdatatxt);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_rdata_txt_current(&rdatatxt, &rdatastr);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	result = dns_rdata_txt_next(&rdatatxt);
	if (result != ISC_R_NOMORE) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	if (rdatastr.length > 15) {
		result = ISC_R_BADNUMBER;
		goto cleanup;
	}
	memcpy(t, rdatastr.data, rdatastr.length);
	t[rdatastr.length] = 0;
	result = isc_parse_uint32(&tversion, t, 10);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	zone->version = tversion;
	result = ISC_R_SUCCESS;

cleanup:
	dns_rdata_freestruct(&rdatatxt);
	return (result);
}

static isc_result_t
catz_process_ipkl(dns_catz_zone_t *zone, dns_ipkeylist_t *ipkl,
		  dns_rdataset_t *value)
{
	isc_result_t result;
	dns_rdata_t rdata;
	dns_rdata_in_a_t rdata_a;
	unsigned int rcount;

	REQUIRE(zone != NULL);
	REQUIRE(ipkl != NULL);
	REQUIRE(DNS_RDATASET_VALID(value));
	REQUIRE(dns_rdataset_isassociated(value));

	if (value->rdclass != dns_rdataclass_in ||
	    value->type != dns_rdatatype_a)
		return (ISC_R_FAILURE);

	rcount = dns_rdataset_count(value);

	ipkl->addrs = isc_mem_reallocate(zone->catzs->mctx, ipkl->addrs,
					 (rcount * sizeof(isc_sockaddr_t)));
	if (ipkl->addrs == NULL)
		return (ISC_R_NOMEMORY);

	ipkl->keys = isc_mem_reallocate(zone->catzs->mctx, ipkl->keys,
					(rcount * sizeof(dns_name_t *)));
	if (ipkl->keys == NULL) {
		isc_mem_free(zone->catzs->mctx, ipkl->addrs);
		return (ISC_R_NOMEMORY);
	}

	for (result = dns_rdataset_first(value);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(value))
	{
		dns_rdata_init(&rdata);
		dns_rdataset_current(value, &rdata);

		result = dns_rdata_tostruct(&rdata, &rdata_a, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		/*
		 * port 0 == take the default
		 */
		isc_sockaddr_fromin(&ipkl->addrs[ipkl->count],
				    &rdata_a.in_addr, 0);
		ipkl->keys[ipkl->count] = NULL;
		ipkl->count++;
		dns_rdata_freestruct(&rdata_a);
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
catz_process_suboption(dns_catz_zone_t *zone, dns_label_t *mhash,
		       catz_opt_t subopt, dns_rdataset_t *value)
{
	isc_result_t result;
	dns_catz_entry_t *entry = NULL;

	REQUIRE(zone != NULL);
	REQUIRE(mhash != NULL);
	REQUIRE(DNS_RDATASET_VALID(value));

	/*
	 * we're adding this entry now, in case the option is invalid we'll get
	 * rid of in verification phase
	 */
	result = isc_ht_find(zone->entries, mhash->base,
			     mhash->length, (void **) &entry);
	if (result != ISC_R_SUCCESS) {
		result = dns_catz_entry_new(zone->catzs->mctx, NULL, &entry);
		if (result != ISC_R_SUCCESS)
			return (result);
		result = isc_ht_add(zone->entries, mhash->base, mhash->length,
				    entry);
		if (result != ISC_R_SUCCESS) {
			dns_catz_entry_detach(zone, &entry);
			return (result);
		}
	}

	switch (subopt) {
	case CATZ_OPT_MASTERS:
		return (catz_process_ipkl(zone, &entry->opts.masters, value));
		break;
	case CATZ_OPT_ALLOW_QUERY:
#if 0
		return (process_apl(zone, &entry->opts))
#endif
	case CATZ_OPT_ALLOW_TRANSFER:
	default:
		return (ISC_R_FAILURE);
	}

	return (ISC_R_FAILURE);
}

static isc_result_t
catz_process_global_option(dns_catz_zone_t *zone, catz_opt_t option,
			   dns_rdataset_t *value)
{
	REQUIRE(zone != NULL);
	REQUIRE(DNS_RDATASET_VALID(value));

	switch (option) {
	case CATZ_OPT_MASTERS:
		return (catz_process_ipkl(zone, &zone->zoneoptions.masters,
					  value));
		break;
	case CATZ_OPT_VERSION:
		return (catz_process_version(zone, value));
		break;
	case CATZ_OPT_ALLOW_QUERY:
#if 0
		return (process_apl(zone, &entry->opts))
#endif
	case CATZ_OPT_ALLOW_TRANSFER:
	default:
		return (ISC_R_FAILURE);
	}
	return (ISC_R_FAILURE);
}

static isc_result_t
catz_process_value(dns_catz_zone_t *zone, dns_name_t *value,
		   dns_rdataset_t *rdataset)
{
	dns_label_t suboption, option, mhash;
	catz_opt_t opt, subopt;

	REQUIRE(zone != NULL);
	REQUIRE(value != NULL);
	REQUIRE(DNS_RDATASET_VALID(rdataset));

	switch (value->labels) {
	case 1:
		/* Catalog zone-wide option */
		dns_name_getlabel(value, 0, &option);
		opt = catz_get_option(&option);
		return (catz_process_global_option(zone, opt, rdataset));

	case 2:
		/* Global list (eg. 'zones') */
		dns_name_getlabel(value, 0, &mhash);
		dns_name_getlabel(value, 1, &option);
		opt = catz_get_option(&option);
		return (catz_process_global_list(zone, opt, rdataset, &mhash));

	case 3:
		/* Zone option */
		dns_name_getlabel(value, 0, &suboption);
		dns_name_getlabel(value, 1, &mhash);
		dns_name_getlabel(value, 2, &option);
		opt = catz_get_option(&option);
		subopt = catz_get_option(&suboption);
		if (opt == CATZ_OPT_ZONES)
			return (catz_process_suboption(zone, &mhash, subopt,
						       rdataset));
		break;

	default:
		break;
	}

	return (ISC_R_FAILURE);
}

isc_result_t
dns_catz_update_process(dns_catz_zones_t *catzs, dns_catz_zone_t *zone,
			dns_name_t *src_name, dns_rdataset_t *rdataset)
{
	isc_result_t result;
	int order;
	unsigned int nlabels;
	dns_namereln_t nrres;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_soa_t soa;
	dns_name_t prefix;

	REQUIRE(catzs != NULL);
	REQUIRE(zone != NULL);

	nrres = dns_name_fullcompare(src_name, &zone->name, &order, &nlabels);
	if (nrres == dns_namereln_equal) {
		if (rdataset->type == dns_rdatatype_soa) {
			result = dns_rdataset_first(rdataset);
			if (result != ISC_R_SUCCESS)
				return (result);

			dns_rdataset_current(rdataset, &rdata);
			result = dns_rdata_tostruct(&rdata, &soa, NULL);
			RUNTIME_CHECK(result == ISC_R_SUCCESS);

			/*
			 * xxxwpk TODO do we want to save something from SOA?
			 */
			return (result);

		} else if (rdataset->type == dns_rdatatype_ns) {
			return (ISC_R_SUCCESS);
		} else {
			return (ISC_R_UNEXPECTED);
		}
	} else if (nrres != dns_namereln_subdomain) {
		return (ISC_R_UNEXPECTED);
	}

	dns_name_init(&prefix, NULL);
	dns_name_split(src_name, zone->name.labels, &prefix, NULL);
	result = catz_process_value(zone, &prefix, rdataset);

	return (result);
}

isc_result_t
dns_catz_generate_masterfilename(dns_catz_zone_t *zone, dns_catz_entry_t *entry,
				 isc_buffer_t **buffer)
{
	isc_buffer_t *tbuf = NULL;
	isc_sha256_t sha256;
	isc_region_t r;
	isc_result_t result;
	size_t rlen;

	REQUIRE(zone != NULL);
	REQUIRE(entry != NULL);
	REQUIRE(buffer != NULL && *buffer != NULL);

	result = isc_buffer_allocate(zone->catzs->mctx, &tbuf,
				     strlen(zone->catzs->view->name) +
				     2 * DNS_NAME_FORMATSIZE + 2);
	if (result != ISC_R_SUCCESS)
		return (result);
	INSIST(tbuf != NULL);

	isc_buffer_putstr(tbuf, zone->catzs->view->name);
	isc_buffer_putstr(tbuf, "_");
	result = dns_name_totext(&zone->name, ISC_TRUE, tbuf);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	isc_buffer_putstr(tbuf, "_");
	result = dns_name_totext(&entry->name, ISC_TRUE, tbuf);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/* __catz__<digest>.db */
	rlen = ISC_SHA256_DIGESTSTRINGLENGTH + 12;

	/* optionally prepend with <zonedir>/ */
	if (entry->opts.zonedir != NULL)
		rlen += strlen(entry->opts.zonedir) + 1;

	result = isc_buffer_reserve(buffer, rlen);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	if (entry->opts.zonedir != NULL) {
		isc_buffer_putstr(*buffer, entry->opts.zonedir);
		isc_buffer_putstr(*buffer, "/");
	}

	isc_buffer_usedregion(tbuf, &r);
	isc_buffer_putstr(*buffer, "__catz__");
	if (tbuf->used > ISC_SHA256_DIGESTSTRINGLENGTH) {
		isc_sha256_init(&sha256);
		isc_sha256_update(&sha256, r.base, r.length);
		/* we can do that because digest string < 2*DNS_NAME */
		isc_sha256_end(&sha256, (char *) r.base);
		isc_buffer_putstr(*buffer, (char *) r.base);
	} else {
		isc_buffer_copyregion(*buffer, &r);
	}

	isc_buffer_putstr(*buffer, ".db");
	result = ISC_R_SUCCESS;

cleanup:
	if (tbuf != NULL)
		isc_buffer_free(&tbuf);
	return (result);
}

isc_result_t
dns_catz_generate_zonecfg(dns_catz_zone_t *zone, dns_catz_entry_t *entry,
			  isc_buffer_t **buf)
{
	/* We have to generate a text buffer with regular zone config:
	 * zone foo.bar {
	 * 	type slave;
	 * 	masters { ip1 port1; ip2 port2; };
	 * }
	 */
	isc_buffer_t *buffer = NULL;
	isc_result_t result;
	isc_uint32_t i;
	isc_netaddr_t netaddr;

	REQUIRE(zone != NULL);
	REQUIRE(entry != NULL);
	REQUIRE(buf != NULL && *buf == NULL);

	/*
	 * The buffer will be reallocated if something won't fit,
	 * ISC_BUFFER_INC seems like a good start.
	 */
	result = isc_buffer_allocate(zone->catzs->mctx, &buffer,
				     ISC_BUFFER_INCR);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	isc_buffer_setautorealloc(buffer, ISC_TRUE);
	isc_buffer_putstr(buffer, "zone ");
	dns_name_totext(&entry->name, ISC_TRUE, buffer);
	isc_buffer_putstr(buffer, " { type slave; masters { ");
	for (i = 0; i < entry->opts.masters.count; i++) {
		/* TODO port and DSCP */
		isc_netaddr_fromsockaddr(&netaddr,
					 &entry->opts.masters.addrs[i]);
		isc_buffer_reserve(&buffer, INET6_ADDRSTRLEN);
		result = isc_netaddr_totext(&netaddr, buffer);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		if (entry->opts.masters.keys[i] != NULL) {
			isc_buffer_putstr(buffer, " key ");
			result = dns_name_totext(entry->opts.masters.keys[i],
						 ISC_TRUE, buffer);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
		}
		isc_buffer_putstr(buffer, "; ");
	}
	isc_buffer_putstr(buffer, "};");
	if (entry->opts.in_memory == ISC_FALSE) {
		isc_buffer_putstr(buffer, "file \"");
		result = dns_catz_generate_masterfilename(zone, entry, &buffer);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		isc_buffer_putstr(buffer, "\";");

	}
	isc_buffer_putstr(buffer, "};");

	*buf = buffer;
	return (ISC_R_SUCCESS);

cleanup:
	if (buffer)
		isc_buffer_free(&buffer);
	return (result);
}


void
dns_catz_update_taskaction(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	dns_catz_zone_t * zone;
	(void) task;

	REQUIRE(event != NULL);
	zone = event->ev_arg;
	REQUIRE(zone != NULL);

	LOCK(&zone->catzs->lock);
	zone->updatepending = ISC_FALSE;
	dns_catz_update_from_db(zone->db, zone->catzs);
	dns_db_detach(&zone->db);
	isc_timer_reset(zone->updatetimer, isc_timertype_inactive,
			NULL, NULL, ISC_TRUE);
	isc_event_free(&event);
	result = isc_time_now(&zone->lastupdated);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	UNLOCK(&zone->catzs->lock);
}

isc_result_t
dns_catz_dbupdate_callback(dns_db_t *db, void *fn_arg) {
	dns_catz_zones_t *catzs;
	dns_catz_zone_t *zone = NULL;
	isc_time_t now;
	isc_uint64_t tdiff;
	isc_result_t result = ISC_R_SUCCESS;
	isc_region_t r;

	REQUIRE(DNS_DB_VALID(db));
	REQUIRE(fn_arg != NULL);
	catzs = (dns_catz_zones_t*) fn_arg;

	dns_name_toregion(&db->origin, &r);

	LOCK(&catzs->lock);
	result = isc_ht_find(catzs->zones, r.base, r.length, (void **) &zone);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	if (zone->updatepending == ISC_FALSE) {
		zone->updatepending = ISC_TRUE;
		isc_time_now(&now);
		tdiff = isc_time_microdiff(&now, &zone->lastupdated)/1000000;
		if (tdiff < zone->defoptions.min_update_interval) {
			isc_interval_t interval;

			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_MASTER, ISC_LOG_INFO,
				      "catz: new zone version came too soon, "
				      "deferring update");
			isc_interval_set(&interval,
					 5 - (unsigned int)tdiff, 0);
			dns_db_attach(db, &zone->db);
			dns_db_currentversion(db, &zone->dbversion);
			result = isc_timer_reset(zone->updatetimer,
						 isc_timertype_once,
						 NULL, &interval, ISC_TRUE);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
		} else {
			isc_event_t *event;

			dns_db_attach(db, &zone->db);
			dns_db_currentversion(db, &zone->dbversion);
			ISC_EVENT_INIT(&zone->updateevent,
				       sizeof(zone->updateevent), 0, NULL,
				       DNS_EVENT_CATZUPDATED,
				       dns_catz_update_taskaction,
				       zone, zone, NULL, NULL);
			event = &zone->updateevent;
			isc_task_send(catzs->updater, &event);
		}
	} else {
		INSIST(db == zone->db);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_DEBUG(3),
			      "catz: update already queued");
		dns_db_closeversion(zone->db, &zone->dbversion, ISC_FALSE);
		dns_db_currentversion(zone->db, &zone->dbversion);
	}

  cleanup:
	UNLOCK(&catzs->lock);

	return (result);
}

void
dns_catz_update_from_db(dns_db_t *db, dns_catz_zones_t *catzs) {
	dns_catz_zone_t *oldzone = NULL, *newzone = NULL;
	isc_result_t result;
	isc_region_t r;
	dns_dbnode_t *node = NULL;
	dns_dbiterator_t *it = NULL;
	dns_fixedname_t fixname;
	dns_name_t *name;
	dns_rdatasetiter_t *rdsiter = NULL;
	dns_rdataset_t rdataset;
	char bname[DNS_NAME_FORMATSIZE];
	isc_buffer_t ibname;
	isc_uint32_t vers;

	REQUIRE(DNS_DB_VALID(db));
	REQUIRE(catzs != NULL);

	/*
	 * Create a new catz in the same context as current catz
	 */
	dns_name_toregion(&db->origin, &r);
	result = isc_ht_find(catzs->zones, r.base, r.length, (void **)&oldzone);
	if (result != ISC_R_SUCCESS) {
		/* this can happen if we remove the zone in the meantime */
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
			      "catz: zone '%s' not in config",
			      bname);
		return;
	}

	isc_buffer_init(&ibname, bname, DNS_NAME_FORMATSIZE);
	result = dns_name_totext(&db->origin, ISC_TRUE, &ibname);
	INSIST(result == ISC_R_SUCCESS);

	result = dns_db_getsoaserial(db, oldzone->dbversion, &vers);
	if (result != ISC_R_SUCCESS) {
		/* A zone without SOA record?!? */
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
			      "catz: zone '%s' has no SOA record (%s)",
			      bname, isc_result_totext(result));
		return;
	}

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_MASTER, ISC_LOG_INFO,
		      "catz: updating catalog zone '%s' with serial %d",
		      bname, vers);

	result = dns_catz_new_zone(catzs, &newzone, &db->origin);
	if (result != ISC_R_SUCCESS) {
		dns_db_closeversion(db, &oldzone->dbversion, ISC_FALSE);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
			      "catz: failed to create new zone - %s",
			      isc_result_totext(result));
		return;
	}

	result = dns_db_createiterator(db, DNS_DB_NONSEC3, &it);
	if (result != ISC_R_SUCCESS) {
		dns_catz_zone_detach(&newzone);
		dns_db_closeversion(db, &oldzone->dbversion, ISC_FALSE);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
			      "catz: failed to create DB iterator - %s",
			      isc_result_totext(result));
		return;
	}

	dns_fixedname_init(&fixname);
	name = dns_fixedname_name(&fixname);

	/*
	 * Iterate over database to fill the new zone
	 */
	result = dns_dbiterator_first(it);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
			      "catz: failed to get db iterator - %s",
			      isc_result_totext(result));
	}

	while (result == ISC_R_SUCCESS) {
		result = dns_dbiterator_current(it, &node, name);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
				      "catz: failed to get db iterator - %s",
				      isc_result_totext(result));
			break;
		}

		result = dns_db_allrdatasets(db, node, oldzone->dbversion, 0,
					  &rdsiter);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_MASTER, ISC_LOG_ERROR,
				      "catz: failed to fetch rrdatasets - %s",
				      isc_result_totext(result));
			dns_db_detachnode(db, &node);
			break;
		}

		dns_rdataset_init(&rdataset);
		result = dns_rdatasetiter_first(rdsiter);
		while (result == ISC_R_SUCCESS) {
			dns_rdatasetiter_current(rdsiter, &rdataset);
			result = dns_catz_update_process(catzs, newzone, name,
							 &rdataset);
			if (result != ISC_R_SUCCESS) {
				char cname[DNS_NAME_FORMATSIZE];
				dns_name_format(name, cname,
						DNS_NAME_FORMATSIZE);
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
					      DNS_LOGMODULE_MASTER,
					      ISC_LOG_WARNING,
					      "catz: unknown record in catalog "
					      "zone - %s (%s) - ignoring",
					      cname,
					      isc_result_totext(result));
			}
			dns_rdataset_disassociate(&rdataset);
			if (result != ISC_R_SUCCESS) {
				break;
			}

			result = dns_rdatasetiter_next(rdsiter);
		}

		dns_rdatasetiter_destroy(&rdsiter);

		dns_db_detachnode(db, &node);
		result = dns_dbiterator_next(it);
	}

	dns_dbiterator_destroy(&it);
	dns_db_closeversion(db, &oldzone->dbversion, ISC_FALSE);
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_MASTER, ISC_LOG_DEBUG(3),
		      "catz: update_from_db: iteration finished");

	/*
	 * Finally merge new zone into old zone
	 */
	result = dns_catz_zones_merge(oldzone, newzone);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER,
			      ISC_LOG_ERROR,
			      "catz: failed merging zones: %s",
			      isc_result_totext(result));

		return;
	}

	dns_catz_zone_detach(&newzone);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_MASTER, ISC_LOG_DEBUG(3),
		      "catz: update_from_db: new zone merged");
}


static isc_result_t
resetactivebitwalk(void *udata, const unsigned char *key, isc_uint32_t keysize,
		   void *data)
{
	dns_catz_zone_t *zone = (dns_catz_zone_t *) data;

	UNUSED(udata);
	UNUSED(key);
	UNUSED(keysize);

	zone->active = ISC_FALSE;
	return (ISC_R_SUCCESS);
}


void
dns_catz_prereconfig(dns_catz_zones_t *catzs) {
	isc_ht_walk(catzs->zones, resetactivebitwalk, NULL);
}

static isc_result_t
postreconfigwalk(void *udata, const unsigned char *key, isc_uint32_t keysize,
		 void *data)
{
	isc_result_t result;
	dns_catz_zone_t *newzone = NULL;
	dns_catz_zones_t *catzs = (dns_catz_zones_t *) udata;
	dns_catz_zone_t *zone = (dns_catz_zone_t *) data;

	UNUSED(key);
	UNUSED(keysize);

	REQUIRE(catzs != NULL);
	REQUIRE(zone != NULL);

	if (zone->active == ISC_FALSE) {
		char cname[DNS_NAME_FORMATSIZE];
		dns_name_format(&zone->name, cname, DNS_NAME_FORMATSIZE);
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_MASTER,
			      ISC_LOG_WARNING,
			      "catz: removing catalog zone %s", cname);

		/* Merge the old zone with an empty one to remove all members */
		result = dns_catz_new_zone(catzs, &newzone, &zone->name);
		INSIST(result == ISC_R_SUCCESS);
		dns_catz_zones_merge(zone, newzone);
		dns_catz_zone_detach(&newzone);

		/* Make sure that we have an empty catalog zone */
		INSIST(isc_ht_count(zone->entries) == 0);

		dns_catz_zone_detach(&zone);
		return (ISC_R_EXISTS);
	}

	return (ISC_R_SUCCESS);
}


void
dns_catz_postreconfig(dns_catz_zones_t *catzs) {
	isc_ht_walk(catzs->zones, postreconfigwalk, catzs);
}

isc_result_t
dns_catz_get_iterator(dns_catz_zone_t *catz, isc_ht_iter_t **itp) {
	return (isc_ht_iter_create(catz->entries, itp));
}
