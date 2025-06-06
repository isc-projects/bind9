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

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/master.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/rootns.h>
#include <dns/view.h>

/*
 * Also update 'upcoming' when updating 'root_ns'.
 */
static char root_ns[] =
	";\n"
	"; Internet Root Nameservers\n"
	";\n"
	"$TTL 518400\n"
	".                       518400  IN      NS      A.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      B.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      C.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      D.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      E.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      F.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      G.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      H.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      I.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      J.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      K.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      L.ROOT-SERVERS.NET.\n"
	".                       518400  IN      NS      M.ROOT-SERVERS.NET.\n"
	"A.ROOT-SERVERS.NET.     3600000 IN      A       198.41.0.4\n"
	"A.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:503:BA3E::2:30\n"
	"B.ROOT-SERVERS.NET.     3600000 IN      A       170.247.170.2\n"
	"B.ROOT-SERVERS.NET.     3600000 IN      AAAA    2801:1b8:10::b\n"
	"C.ROOT-SERVERS.NET.     3600000 IN      A       192.33.4.12\n"
	"C.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:2::c\n"
	"D.ROOT-SERVERS.NET.     3600000 IN      A       199.7.91.13\n"
	"D.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:2d::d\n"
	"E.ROOT-SERVERS.NET.     3600000 IN      A       192.203.230.10\n"
	"E.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:a8::e\n"
	"F.ROOT-SERVERS.NET.     3600000 IN      A       192.5.5.241\n"
	"F.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:2F::F\n"
	"G.ROOT-SERVERS.NET.     3600000 IN      A       192.112.36.4\n"
	"G.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:12::d0d\n"
	"H.ROOT-SERVERS.NET.     3600000 IN      A       198.97.190.53\n"
	"H.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:1::53\n"
	"I.ROOT-SERVERS.NET.     3600000 IN      A       192.36.148.17\n"
	"I.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:7fe::53\n"
	"J.ROOT-SERVERS.NET.     3600000 IN      A       192.58.128.30\n"
	"J.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:503:C27::2:30\n"
	"K.ROOT-SERVERS.NET.     3600000 IN      A       193.0.14.129\n"
	"K.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:7FD::1\n"
	"L.ROOT-SERVERS.NET.     3600000 IN      A       199.7.83.42\n"
	"L.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:500:9f::42\n"
	"M.ROOT-SERVERS.NET.     3600000 IN      A       202.12.27.33\n"
	"M.ROOT-SERVERS.NET.     3600000 IN      AAAA    2001:DC3::35\n";

static unsigned char b_data[] = "\001b\014root-servers\003net";

static struct upcoming {
	const dns_name_t name;
	dns_rdatatype_t type;
	isc_stdtime_t time;
} upcoming[] = { {
			 .name = DNS_NAME_INITABSOLUTE(b_data),
			 .type = dns_rdatatype_a,
			 .time = 1701086400 /* November 27 2023, 12:00 UTC */
		 },
		 {
			 .name = DNS_NAME_INITABSOLUTE(b_data),
			 .type = dns_rdatatype_aaaa,
			 .time = 1701086400 /* November 27 2023, 12:00 UTC */
		 } };

static isc_result_t
in_rootns(dns_rdataset_t *rootns, dns_name_t *name) {
	isc_result_t result;
	dns_rdata_ns_t ns;

	if (!dns_rdataset_isassociated(rootns)) {
		return ISC_R_NOTFOUND;
	}

	DNS_RDATASET_FOREACH (rootns) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(rootns, &rdata);
		result = dns_rdata_tostruct(&rdata, &ns, NULL);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
		if (dns_name_compare(name, &ns.name) == 0) {
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

static isc_result_t
check_node(dns_rdataset_t *rootns, dns_name_t *name,
	   dns_rdatasetiter_t *rdsiter) {
	DNS_RDATASETITER_FOREACH (rdsiter) {
		dns_rdataset_t rdataset = DNS_RDATASET_INIT;
		dns_rdatasetiter_current(rdsiter, &rdataset);
		dns_rdatatype_t type = rdataset.type;
		dns_rdataset_disassociate(&rdataset);

		switch (type) {
		case dns_rdatatype_a:
		case dns_rdatatype_aaaa:
			return in_rootns(rootns, name);
		case dns_rdatatype_ns:
			if (dns_name_compare(name, dns_rootname) == 0) {
				return ISC_R_SUCCESS;
			}
			FALLTHROUGH;
		default:
			return ISC_R_FAILURE;
		}
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
check_hints(dns_db_t *db) {
	isc_result_t result;
	dns_rdataset_t rootns;
	dns_dbiterator_t *dbiter = NULL;
	dns_dbnode_t *node = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fixname;
	dns_name_t *name;
	dns_rdatasetiter_t *rdsiter = NULL;

	name = dns_fixedname_initname(&fixname);

	dns_rdataset_init(&rootns);
	(void)dns_db_find(db, dns_rootname, NULL, dns_rdatatype_ns, 0, now,
			  NULL, name, &rootns, NULL);
	result = dns_db_createiterator(db, 0, &dbiter);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	DNS_DBITERATOR_FOREACH (dbiter) {
		result = dns_dbiterator_current(dbiter, &node, name);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		result = dns_db_allrdatasets(db, node, NULL, 0, now, &rdsiter);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		result = check_node(&rootns, name, rdsiter);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		dns_rdatasetiter_destroy(&rdsiter);
		dns_db_detachnode(db, &node);
	}

cleanup:
	if (dns_rdataset_isassociated(&rootns)) {
		dns_rdataset_disassociate(&rootns);
	}
	if (rdsiter != NULL) {
		dns_rdatasetiter_destroy(&rdsiter);
	}
	if (node != NULL) {
		dns_db_detachnode(db, &node);
	}
	if (dbiter != NULL) {
		dns_dbiterator_destroy(&dbiter);
	}
	return result;
}

isc_result_t
dns_rootns_create(isc_mem_t *mctx, dns_rdataclass_t rdclass,
		  const char *filename, dns_db_t **target) {
	isc_result_t result, eresult;
	isc_buffer_t source;
	unsigned int len;
	dns_rdatacallbacks_t callbacks;
	dns_db_t *db = NULL;

	REQUIRE(target != NULL && *target == NULL);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, dns_rootname,
			       dns_dbtype_zone, rdclass, 0, NULL, &db);
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	len = strlen(root_ns);
	isc_buffer_init(&source, root_ns, len);
	isc_buffer_add(&source, len);

	dns_rdatacallbacks_init(&callbacks);
	result = dns_db_beginload(db, &callbacks);
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}
	if (filename != NULL) {
		/*
		 * Load the hints from the specified filename.
		 */
		result = dns_master_loadfile(filename, &db->origin, &db->origin,
					     db->rdclass, DNS_MASTER_HINT, 0,
					     &callbacks, NULL, NULL, db->mctx,
					     dns_masterformat_text, 0);
	} else if (rdclass == dns_rdataclass_in) {
		/*
		 * Default to using the Internet root servers.
		 */
		result = dns_master_loadbuffer(
			&source, &db->origin, &db->origin, db->rdclass,
			DNS_MASTER_HINT, &callbacks, db->mctx);
	} else {
		result = ISC_R_NOTFOUND;
	}
	eresult = dns_db_endload(db, &callbacks);
	if (result == ISC_R_SUCCESS || result == DNS_R_SEENINCLUDE) {
		result = eresult;
	}
	if (result != ISC_R_SUCCESS && result != DNS_R_SEENINCLUDE) {
		goto failure;
	}
	if (check_hints(db) != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_WARNING, "extra data in root hints '%s'",
			      (filename != NULL) ? filename : "<BUILT-IN>");
	}
	*target = db;
	return ISC_R_SUCCESS;

failure:
	isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
		      ISC_LOG_ERROR,
		      "could not configure root hints from "
		      "'%s': %s",
		      (filename != NULL) ? filename : "<BUILT-IN>",
		      isc_result_totext(result));

	if (db != NULL) {
		dns_db_detach(&db);
	}

	return result;
}

static void
report(dns_view_t *view, dns_name_t *name, bool missing, dns_rdata_t *rdata) {
	const char *viewname = "", *sep = "";
	char namebuf[DNS_NAME_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];
	char databuf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:123.123.123.123")];
	isc_buffer_t buffer;
	isc_result_t result;

	if (strcmp(view->name, "_bind") != 0 &&
	    strcmp(view->name, "_default") != 0)
	{
		viewname = view->name;
		sep = ": view ";
	}

	dns_name_format(name, namebuf, sizeof(namebuf));
	dns_rdatatype_format(rdata->type, typebuf, sizeof(typebuf));
	isc_buffer_init(&buffer, databuf, sizeof(databuf) - 1);
	result = dns_rdata_totext(rdata, NULL, &buffer);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	databuf[isc_buffer_usedlength(&buffer)] = '\0';

	if (missing) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_WARNING,
			      "checkhints%s%s: %s/%s (%s) missing from hints",
			      sep, viewname, namebuf, typebuf, databuf);
	} else {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_WARNING,
			      "checkhints%s%s: %s/%s (%s) extra record "
			      "in hints",
			      sep, viewname, namebuf, typebuf, databuf);
	}
}

static bool
inrrset(dns_rdataset_t *rrset, dns_rdata_t *rdata) {
	DNS_RDATASET_FOREACH (rrset) {
		dns_rdata_t current = DNS_RDATA_INIT;
		dns_rdataset_current(rrset, &current);
		if (dns_rdata_compare(rdata, &current) == 0) {
			return true;
		}
	}
	return false;
}

static bool
changing(const dns_name_t *name, dns_rdatatype_t type, isc_stdtime_t now) {
	for (size_t i = 0; i < ARRAY_SIZE(upcoming); i++) {
		if (upcoming[i].time > now && upcoming[i].type == type &&
		    dns_name_equal(&upcoming[i].name, name))
		{
			return true;
		}
	}
	return false;
}

/*
 * Check that the address RRsets match.
 *
 * Note we don't complain about missing glue records.
 */

static void
check_address_records(dns_view_t *view, dns_db_t *hints, dns_db_t *db,
		      dns_name_t *name, isc_stdtime_t now) {
	isc_result_t hresult, rresult;
	dns_rdataset_t hintrrset, rootrrset;
	dns_name_t *foundname;
	dns_fixedname_t fixed;

	dns_rdataset_init(&hintrrset);
	dns_rdataset_init(&rootrrset);
	foundname = dns_fixedname_initname(&fixed);

	hresult = dns_db_find(hints, name, NULL, dns_rdatatype_a, 0, now, NULL,
			      foundname, &hintrrset, NULL);
	rresult = dns_db_find(db, name, NULL, dns_rdatatype_a,
			      DNS_DBFIND_GLUEOK, now, NULL, foundname,
			      &rootrrset, NULL);
	if (hresult == ISC_R_SUCCESS &&
	    (rresult == ISC_R_SUCCESS || rresult == DNS_R_GLUE))
	{
		DNS_RDATASET_FOREACH (&rootrrset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&rootrrset, &rdata);
			if (!inrrset(&hintrrset, &rdata) &&
			    !changing(name, dns_rdatatype_a, now))
			{
				report(view, name, true, &rdata);
			}
		}
		DNS_RDATASET_FOREACH (&hintrrset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&hintrrset, &rdata);
			if (!inrrset(&rootrrset, &rdata) &&
			    !changing(name, dns_rdatatype_a, now))
			{
				report(view, name, false, &rdata);
			}
		}
	}
	if (hresult == ISC_R_NOTFOUND &&
	    (rresult == ISC_R_SUCCESS || rresult == DNS_R_GLUE))
	{
		DNS_RDATASET_FOREACH (&rootrrset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&rootrrset, &rdata);
			report(view, name, true, &rdata);
		}
	}
	if (dns_rdataset_isassociated(&rootrrset)) {
		dns_rdataset_disassociate(&rootrrset);
	}
	if (dns_rdataset_isassociated(&hintrrset)) {
		dns_rdataset_disassociate(&hintrrset);
	}

	/*
	 * Check AAAA records.
	 */
	hresult = dns_db_find(hints, name, NULL, dns_rdatatype_aaaa, 0, now,
			      NULL, foundname, &hintrrset, NULL);
	rresult = dns_db_find(db, name, NULL, dns_rdatatype_aaaa,
			      DNS_DBFIND_GLUEOK, now, NULL, foundname,
			      &rootrrset, NULL);
	if (hresult == ISC_R_SUCCESS &&
	    (rresult == ISC_R_SUCCESS || rresult == DNS_R_GLUE))
	{
		DNS_RDATASET_FOREACH (&rootrrset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&rootrrset, &rdata);
			if (!inrrset(&hintrrset, &rdata) &&
			    !changing(name, dns_rdatatype_aaaa, now))
			{
				report(view, name, true, &rdata);
			}
		}
		DNS_RDATASET_FOREACH (&hintrrset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&hintrrset, &rdata);
			if (!inrrset(&rootrrset, &rdata) &&
			    !changing(name, dns_rdatatype_aaaa, now))
			{
				report(view, name, false, &rdata);
			}
		}
	}
	if (hresult == ISC_R_NOTFOUND &&
	    (rresult == ISC_R_SUCCESS || rresult == DNS_R_GLUE))
	{
		DNS_RDATASET_FOREACH (&rootrrset) {
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&rootrrset, &rdata);
			report(view, name, true, &rdata);
		}
	}
	if (dns_rdataset_isassociated(&rootrrset)) {
		dns_rdataset_disassociate(&rootrrset);
	}
	if (dns_rdataset_isassociated(&hintrrset)) {
		dns_rdataset_disassociate(&hintrrset);
	}
}

void
dns_root_checkhints(dns_view_t *view, dns_db_t *hints, dns_db_t *db) {
	isc_result_t result;
	dns_rdata_ns_t ns;
	dns_rdataset_t hintns, rootns;
	const char *viewname = "", *sep = "";
	isc_stdtime_t now = isc_stdtime_now();
	dns_name_t *name;
	dns_fixedname_t fixed;

	REQUIRE(hints != NULL);
	REQUIRE(db != NULL);
	REQUIRE(view != NULL);

	if (strcmp(view->name, "_bind") != 0 &&
	    strcmp(view->name, "_default") != 0)
	{
		viewname = view->name;
		sep = ": view ";
	}

	dns_rdataset_init(&hintns);
	dns_rdataset_init(&rootns);
	name = dns_fixedname_initname(&fixed);

	result = dns_db_find(hints, dns_rootname, NULL, dns_rdatatype_ns, 0,
			     now, NULL, name, &hintns, NULL);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_WARNING,
			      "checkhints%s%s: unable to get root NS rrset "
			      "from hints: %s",
			      sep, viewname, isc_result_totext(result));
		goto cleanup;
	}

	result = dns_db_find(db, dns_rootname, NULL, dns_rdatatype_ns, 0, now,
			     NULL, name, &rootns, NULL);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_WARNING,
			      "checkhints%s%s: unable to get root NS rrset "
			      "from cache: %s",
			      sep, viewname, isc_result_totext(result));
		goto cleanup;
	}

	/*
	 * Look for missing root NS names.
	 */
	DNS_RDATASET_FOREACH (&rootns) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(&rootns, &rdata);
		result = dns_rdata_tostruct(&rdata, &ns, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		result = in_rootns(&hintns, &ns.name);
		if (result != ISC_R_SUCCESS) {
			char namebuf[DNS_NAME_FORMATSIZE];
			/* missing from hints */
			dns_name_format(&ns.name, namebuf, sizeof(namebuf));
			isc_log_write(DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_HINTS, ISC_LOG_WARNING,
				      "checkhints%s%s: unable to find root "
				      "NS '%s' in hints",
				      sep, viewname, namebuf);
		} else {
			check_address_records(view, hints, db, &ns.name, now);
		}
	}

	/*
	 * Look for extra root NS names.
	 */
	DNS_RDATASET_FOREACH (&hintns) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(&hintns, &rdata);
		result = dns_rdata_tostruct(&rdata, &ns, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		result = in_rootns(&rootns, &ns.name);
		if (result != ISC_R_SUCCESS) {
			char namebuf[DNS_NAME_FORMATSIZE];
			/* extra entry in hints */
			dns_name_format(&ns.name, namebuf, sizeof(namebuf));
			isc_log_write(DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_HINTS, ISC_LOG_WARNING,
				      "checkhints%s%s: extra NS '%s' in hints",
				      sep, viewname, namebuf);
		}
	}

cleanup:
	if (dns_rdataset_isassociated(&rootns)) {
		dns_rdataset_disassociate(&rootns);
	}
	if (dns_rdataset_isassociated(&hintns)) {
		dns_rdataset_disassociate(&hintns);
	}
}
