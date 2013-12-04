/*
 * Copyright (C) 2013  Internet Systems Consortium, Inc. ("ISC")
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

#include <isc/util.h>

#include <named/log.h>
#include <named/geoip.h>

#include <dns/geoip.h>

#ifdef HAVE_GEOIP
static dns_geoip_databases_t geoip_table = {
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static void
init_geoip_db(GeoIP **dbp, GeoIPDBTypes edition,
	      GeoIPOptions method, const char *name)
{
	char *info;
	GeoIP *db;

	REQUIRE(dbp != NULL);

	db = *dbp;

	if (db != NULL) {
		GeoIP_delete(db);
		db = *dbp = NULL;
	}

	if (! GeoIP_db_avail(edition)) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP %s DB not available", name);
		return;
	}

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		NS_LOGMODULE_SERVER, ISC_LOG_INFO,
		"initializing GeoIP %s DB", name);

	db = GeoIP_open_type(edition, method);
	if (db == NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			"failed to initialize GeoIP %s DB; "
			"geoip matches using this database will fail",
			name);
		return;
	}

	info = GeoIP_database_info(db);
	if (info != NULL)
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			      "%s", info);

	*dbp = db;
}

static GeoIPDBTypes
choose_rev(GeoIPDBTypes primary, GeoIPDBTypes secondary, const char *name) {
	if (GeoIP_db_avail(primary))
		return (primary);
	if (GeoIP_db_avail(secondary))
		return (secondary);
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		NS_LOGMODULE_SERVER, ISC_LOG_INFO,
		"GeoIP %s DB: neither revision available", name);
	return (0);
}
#endif /* HAVE_GEOIP */

void
ns_geoip_init(void) {
#ifndef HAVE_GEOIP
	return;
#else
	if (ns_g_geoip == NULL)
		ns_g_geoip = &geoip_table;
#endif
}

void
ns_geoip_load(char *dir) {
#ifndef HAVE_GEOIP

	UNUSED(dir);

	return;
#else
	GeoIPOptions method;
	GeoIPDBTypes edition;

#ifdef _WIN32
	method = GEOIP_STANDARD;
#else
	method = GEOIP_MMAP_CACHE;
#endif

	ns_geoip_init();
	if (dir != NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			      "using \"%s\" as GeoIP directory", dir);
		GeoIP_setup_custom_directory(dir);
	}

	init_geoip_db(&ns_g_geoip->country_v4, GEOIP_COUNTRY_EDITION,
		      method, "Country (IPv4)");
#ifdef HAVE_GEOIP_V6
	init_geoip_db(&ns_g_geoip->country_v6, GEOIP_COUNTRY_EDITION_V6,
		      method, "Country (IPv6)");
#endif

	edition = choose_rev(GEOIP_CITY_EDITION_REV0,
			     GEOIP_CITY_EDITION_REV1, "City (IPv4)");
	if (edition != 0)
		init_geoip_db(&ns_g_geoip->city_v4, edition,
			      method, "City (IPv4)");
#if defined(HAVE_GEOIP_V6) && defined(HAVE_GEOIP_CITY_V6)
	edition = choose_rev(GEOIP_CITY_EDITION_REV0_V6,
			     GEOIP_CITY_EDITION_REV1_V6, "City (IPv6)");
	if (edition != 0)
		init_geoip_db(&ns_g_geoip->city_v6, edition,
			      method, "City (IPv6)");
#endif


	edition = choose_rev(GEOIP_REGION_EDITION_REV0,
			     GEOIP_REGION_EDITION_REV1, "Region");
	if (edition != 0)
		init_geoip_db(&ns_g_geoip->region, edition, method, "Region");

	init_geoip_db(&ns_g_geoip->isp, GEOIP_ISP_EDITION,
		      method, "ISP");
	init_geoip_db(&ns_g_geoip->org, GEOIP_ORG_EDITION,
		      method, "Org");
	init_geoip_db(&ns_g_geoip->as, GEOIP_ASNUM_EDITION,
		      method, "AS");
	init_geoip_db(&ns_g_geoip->domain, GEOIP_DOMAIN_EDITION,
		      method, "Domain");
	init_geoip_db(&ns_g_geoip->netspeed, GEOIP_NETSPEED_EDITION,
		      method, "NetSpeed");
#endif /* HAVE_GEOIP */
}
