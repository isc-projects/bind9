/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0 AND ISC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Copyright (C) 2002 Stichting NLnet, Netherlands, stichting@nlnet.nl.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND STICHTING NLNET
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * STICHTING NLNET BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The development of Dynamically Loadable Zones (DLZ) for Bind 9 was
 * conceived and contributed by Rob Butler.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ROB BUTLER
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * ROB BUTLER BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file */

/***
 *** Imports
 ***/

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/random.h>
#include <isc/rwlock.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dlz.h>
#include <dns/fixedname.h>
#include <dns/master.h>
#include <dns/ssu.h>
#include <dns/zone.h>

#include "dlz_p.h"

/***
 *** Supported DLZ DB Implementations Registry
 ***/

static ISC_LIST(dns_dlzimplementation_t) dlz_implementations;
static isc_rwlock_t dlz_implock;

void
dns__dlz_initialize(void) {
	isc_rwlock_init(&dlz_implock);
	ISC_LIST_INIT(dlz_implementations);
}

void
dns__dlz_shutdown(void) {
	isc_rwlock_destroy(&dlz_implock);
}

/*%
 * Searches the dlz_implementations list for a driver matching name.
 */
static dns_dlzimplementation_t *
dlz_impfind(const char *name) {
	ISC_LIST_FOREACH (dlz_implementations, imp, link) {
		if (strcasecmp(name, imp->name) == 0) {
			return imp;
		}
	}
	return NULL;
}

/***
 *** Basic DLZ Methods
 ***/

isc_result_t
dns_dlzallowzonexfr(dns_view_t *view, const dns_name_t *name,
		    const isc_sockaddr_t *clientaddr, dns_db_t **dbp) {
	isc_result_t result = ISC_R_NOTFOUND;
	dns_dlzallowzonexfr_t allowzonexfr;

	/*
	 * Performs checks to make sure data is as we expect it to be.
	 */
	REQUIRE(name != NULL);
	REQUIRE(dbp != NULL && *dbp == NULL);

	/*
	 * Find a driver in which the zone exists and transfer is supported
	 */
	ISC_LIST_FOREACH (view->dlz_searched, dlzdb, link) {
		REQUIRE(DNS_DLZ_VALID(dlzdb));

		allowzonexfr = dlzdb->implementation->methods->allowzonexfr;
		result = (*allowzonexfr)(dlzdb->implementation->driverarg,
					 dlzdb->dbdata, dlzdb->mctx,
					 view->rdclass, name, clientaddr, dbp);

		/*
		 * In these cases, we found the right database. Non-success
		 * result codes indicate the zone might not transfer.
		 */
		switch (result) {
		case ISC_R_SUCCESS:
		case ISC_R_NOPERM:
		case ISC_R_DEFAULT:
			return result;
		default:
			break;
		}
	}

	if (result == ISC_R_NOTIMPLEMENTED) {
		result = ISC_R_NOTFOUND;
	}

	return result;
}

isc_result_t
dns_dlzcreate(isc_mem_t *mctx, const char *dlzname, const char *drivername,
	      unsigned int argc, char *argv[], dns_dlzdb_t **dbp) {
	dns_dlzimplementation_t *impinfo;
	isc_result_t result;
	dns_dlzdb_t *db = NULL;

	/*
	 * Performs checks to make sure data is as we expect it to be.
	 */
	REQUIRE(dbp != NULL && *dbp == NULL);
	REQUIRE(dlzname != NULL);
	REQUIRE(drivername != NULL);
	REQUIRE(mctx != NULL);

	/* write log message */
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ, ISC_LOG_INFO,
		      "Loading '%s' using driver %s", dlzname, drivername);

	/* lock the dlz_implementations list so we can search it. */
	RWLOCK(&dlz_implock, isc_rwlocktype_read);

	/* search for the driver implementation	 */
	impinfo = dlz_impfind(drivername);
	if (impinfo == NULL) {
		RWUNLOCK(&dlz_implock, isc_rwlocktype_read);

		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
			      ISC_LOG_ERROR,
			      "unsupported DLZ database driver '%s'."
			      "  %s not loaded.",
			      drivername, dlzname);

		return ISC_R_NOTFOUND;
	}

	/* Allocate memory to hold the DLZ database driver */
	db = isc_mem_get(mctx, sizeof(*db));
	*db = (dns_dlzdb_t){
		.implementation = impinfo,
	};

	ISC_LINK_INIT(db, link);
	if (dlzname != NULL) {
		db->dlzname = isc_mem_strdup(mctx, dlzname);
	}

	/* Create a new database using implementation 'drivername'. */
	result = ((impinfo->methods->create)(mctx, dlzname, argc, argv,
					     impinfo->driverarg, &db->dbdata));

	RWUNLOCK(&dlz_implock, isc_rwlocktype_read);
	/* mark the DLZ driver as valid */
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	db->magic = DNS_DLZ_MAGIC;
	isc_mem_attach(mctx, &db->mctx);
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(2), "DLZ driver loaded successfully.");
	*dbp = db;
	return ISC_R_SUCCESS;
failure:
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_ERROR, "DLZ driver failed to load.");

	/* impinfo->methods->create failed. */
	isc_mem_free(mctx, db->dlzname);
	isc_mem_put(mctx, db, sizeof(*db));
	return result;
}

void
dns_dlzdestroy(dns_dlzdb_t **dbp) {
	dns_dlzdestroy_t destroy;
	dns_dlzdb_t *db;

	/* Write debugging message to log */
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(2), "Unloading DLZ driver.");

	/*
	 * Perform checks to make sure data is as we expect it to be.
	 */
	REQUIRE(dbp != NULL && DNS_DLZ_VALID(*dbp));

	db = *dbp;
	*dbp = NULL;

	if (db->ssutable != NULL) {
		dns_ssutable_detach(&db->ssutable);
	}

	/* call the drivers destroy method */
	if (db->dlzname != NULL) {
		isc_mem_free(db->mctx, db->dlzname);
	}
	destroy = db->implementation->methods->destroy;
	(*destroy)(db->implementation->driverarg, db->dbdata);
	/* return memory and detach */
	isc_mem_putanddetach(&db->mctx, db, sizeof(*db));
}

/*%
 * Registers a DLZ driver.  This basically just adds the dlz
 * driver to the list of available drivers in the dlz_implementations list.
 */
isc_result_t
dns_dlzregister(const char *drivername, const dns_dlzmethods_t *methods,
		void *driverarg, isc_mem_t *mctx,
		dns_dlzimplementation_t **dlzimp) {
	dns_dlzimplementation_t *dlz_imp;

	/* Write debugging message to log */
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(2), "Registering DLZ driver '%s'",
		      drivername);

	/*
	 * Performs checks to make sure data is as we expect it to be.
	 */
	REQUIRE(drivername != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(methods->create != NULL);
	REQUIRE(methods->destroy != NULL);
	REQUIRE(methods->findzone != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(dlzimp != NULL && *dlzimp == NULL);

	/* lock the dlz_implementations list so we can modify it. */
	RWLOCK(&dlz_implock, isc_rwlocktype_write);

	/*
	 * check that another already registered driver isn't using
	 * the same name
	 */
	dlz_imp = dlz_impfind(drivername);
	if (dlz_imp != NULL) {
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
			      ISC_LOG_DEBUG(2),
			      "DLZ Driver '%s' already registered", drivername);
		RWUNLOCK(&dlz_implock, isc_rwlocktype_write);
		return ISC_R_EXISTS;
	}

	/*
	 * Allocate memory for a dlz_implementation object.  Error if
	 * we cannot.
	 */
	dlz_imp = isc_mem_get(mctx, sizeof(*dlz_imp));
	*dlz_imp = (dns_dlzimplementation_t){
		.name = drivername,
		.methods = methods,
		.driverarg = driverarg,
	};

	/* attach the new dlz_implementation object to a memory context */
	isc_mem_attach(mctx, &dlz_imp->mctx);

	/*
	 * prepare the dlz_implementation object to be put in a list,
	 * and append it to the list
	 */
	ISC_LINK_INIT(dlz_imp, link);
	ISC_LIST_APPEND(dlz_implementations, dlz_imp, link);

	/* Unlock the dlz_implementations list.	 */
	RWUNLOCK(&dlz_implock, isc_rwlocktype_write);

	/* Pass back the dlz_implementation that we created. */
	*dlzimp = dlz_imp;

	return ISC_R_SUCCESS;
}

/*%
 * Tokenize the string "s" into whitespace-separated words,
 * return the number of words in '*argcp' and an array
 * of pointers to the words in '*argvp'.  The caller
 * must free the array using isc_mem_put().  The string
 * is modified in-place.
 */
isc_result_t
dns_dlzstrtoargv(isc_mem_t *mctx, char *s, unsigned int *argcp, char ***argvp) {
	return isc_commandline_strtoargv(mctx, s, argcp, argvp, 0);
}

/*%
 * Unregisters a DLZ driver.  This basically just removes the dlz
 * driver from the list of available drivers in the dlz_implementations list.
 */
void
dns_dlzunregister(dns_dlzimplementation_t **dlzimp) {
	dns_dlzimplementation_t *dlz_imp;

	/* Write debugging message to log */
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(2), "Unregistering DLZ driver.");

	/*
	 * Performs checks to make sure data is as we expect it to be.
	 */
	REQUIRE(dlzimp != NULL && *dlzimp != NULL);

	dlz_imp = *dlzimp;

	/* lock the dlz_implementations list so we can modify it. */
	RWLOCK(&dlz_implock, isc_rwlocktype_write);

	/* remove the dlz_implementation object from the list */
	ISC_LIST_UNLINK(dlz_implementations, dlz_imp, link);

	/*
	 * Return the memory back to the available memory pool and
	 * remove it from the memory context.
	 */
	isc_mem_putanddetach(&dlz_imp->mctx, dlz_imp, sizeof(*dlz_imp));

	/* Unlock the dlz_implementations list. */
	RWUNLOCK(&dlz_implock, isc_rwlocktype_write);
}

/*
 * Create a writeable DLZ zone. This can be called by DLZ drivers
 * during configure() to create a zone that can be updated. The zone
 * type is set to dns_zone_dlz, which is equivalent to a primary zone
 *
 * This function uses a callback setup in dns_dlzconfigure() to call
 * into the server zone code to setup the remaining pieces of server
 * specific functionality on the zone
 */
isc_result_t
dns_dlz_writeablezone(dns_view_t *view, dns_dlzdb_t *dlzdb,
		      const char *zone_name) {
	dns_zone_t *zone = NULL;
	dns_zone_t *dupzone = NULL;
	isc_result_t result;
	isc_buffer_t buffer;
	dns_fixedname_t fixorigin;
	dns_name_t *origin;

	REQUIRE(DNS_DLZ_VALID(dlzdb));

	REQUIRE(dlzdb->configure_callback != NULL);

	isc_buffer_constinit(&buffer, zone_name, strlen(zone_name));
	isc_buffer_add(&buffer, strlen(zone_name));
	dns_fixedname_init(&fixorigin);
	result = dns_name_fromtext(dns_fixedname_name(&fixorigin), &buffer,
				   dns_rootname, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	origin = dns_fixedname_name(&fixorigin);

	if (!dlzdb->search) {
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
			      ISC_LOG_WARNING,
			      "DLZ %s has 'search no;', but attempted to "
			      "register writeable zone %s.",
			      dlzdb->dlzname, zone_name);
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	/* See if the zone already exists */
	result = dns_view_findzone(view, origin, DNS_ZTFIND_EXACT, &dupzone);
	if (result == ISC_R_SUCCESS) {
		dns_zone_detach(&dupzone);
		result = ISC_R_EXISTS;
		goto cleanup;
	}
	INSIST(dupzone == NULL);

	/* Create it */
	dns_zone_create(&zone, view->mctx, 0);
	dns_zone_setorigin(zone, origin);
	dns_zone_setview(zone, view);

	dns_zone_setadded(zone, true);

	if (dlzdb->ssutable == NULL) {
		dns_ssutable_createdlz(dlzdb->mctx, &dlzdb->ssutable, dlzdb);
	}
	dns_zone_setssutable(zone, dlzdb->ssutable);

	result = dlzdb->configure_callback(view, dlzdb, zone);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = dns_view_addzone(view, zone);

cleanup:
	if (zone != NULL) {
		dns_zone_detach(&zone);
	}

	return result;
}

/*%
 * Configure a DLZ driver. This is optional, and if supplied gives
 * the backend an opportunity to configure parameters related to DLZ.
 */
isc_result_t
dns_dlzconfigure(dns_view_t *view, dns_dlzdb_t *dlzdb,
		 dlzconfigure_callback_t callback) {
	dns_dlzimplementation_t *impl;
	isc_result_t result;

	REQUIRE(DNS_DLZ_VALID(dlzdb));
	REQUIRE(dlzdb->implementation != NULL);

	impl = dlzdb->implementation;

	if (impl->methods->configure == NULL) {
		return ISC_R_SUCCESS;
	}

	dlzdb->configure_callback = callback;

	result = impl->methods->configure(impl->driverarg, dlzdb->dbdata, view,
					  dlzdb);
	return result;
}

bool
dns_dlz_ssumatch(dns_dlzdb_t *dlzdatabase, const dns_name_t *signer,
		 const dns_name_t *name, const isc_netaddr_t *tcpaddr,
		 dns_rdatatype_t type, const dst_key_t *key) {
	dns_dlzimplementation_t *impl;
	bool r;

	REQUIRE(dlzdatabase != NULL);
	REQUIRE(dlzdatabase->implementation != NULL);
	REQUIRE(dlzdatabase->implementation->methods != NULL);
	impl = dlzdatabase->implementation;

	if (impl->methods->ssumatch == NULL) {
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
			      ISC_LOG_INFO,
			      "No ssumatch method for DLZ database");
		return false;
	}

	r = impl->methods->ssumatch(signer, name, tcpaddr, type, key,
				    impl->driverarg, dlzdatabase->dbdata);
	return r;
}
