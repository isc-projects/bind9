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

static char root_ns[] =
	";       This file holds the information on root name servers needed "
	"to \n"
	";       initialize cache of Internet domain name servers\n"
	";       (e.g. reference this file in the \"cache  .  <file>\"\n"
	";       configuration file of BIND domain name servers). \n"
	"; \n"
	";       This file is made available by InterNIC \n"
	";       under anonymous FTP as\n"
	";           file                /domain/named.cache \n"
	";           on server           FTP.INTERNIC.NET\n"
	";       -OR-                    RS.INTERNIC.NET\n"
	";\n"
	";       last update:     May 21, 2026\n"
	";       related version of root zone:     2026052101\n"
	"; \n"
	"; FORMERLY NS.INTERNIC.NET \n"
	";\n"
	".                        3600000      NS    A.ROOT-SERVERS.NET.\n"
	"A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4\n"
	"A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30\n"
	"; \n"
	"; FORMERLY NS1.ISI.EDU \n"
	";\n"
	".                        3600000      NS    B.ROOT-SERVERS.NET.\n"
	"B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2\n"
	"B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b\n"
	"; \n"
	"; FORMERLY C.PSI.NET \n"
	";\n"
	".                        3600000      NS    C.ROOT-SERVERS.NET.\n"
	"C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12\n"
	"C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::c\n"
	"; \n"
	"; FORMERLY TERP.UMD.EDU \n"
	";\n"
	".                        3600000      NS    D.ROOT-SERVERS.NET.\n"
	"D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13\n"
	"D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2d::d\n"
	"; \n"
	"; FORMERLY NS.NASA.GOV\n"
	";\n"
	".                        3600000      NS    E.ROOT-SERVERS.NET.\n"
	"E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10\n"
	"E.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:a8::e\n"
	"; \n"
	"; FORMERLY NS.ISC.ORG\n"
	";\n"
	".                        3600000      NS    F.ROOT-SERVERS.NET.\n"
	"F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241\n"
	"F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2f::f\n"
	"; \n"
	"; FORMERLY NS.NIC.DDN.MIL\n"
	";\n"
	".                        3600000      NS    G.ROOT-SERVERS.NET.\n"
	"G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4\n"
	"G.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:12::d0d\n"
	"; \n"
	"; FORMERLY AOS.ARL.ARMY.MIL\n"
	";\n"
	".                        3600000      NS    H.ROOT-SERVERS.NET.\n"
	"H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53\n"
	"H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::53\n"
	"; \n"
	"; FORMERLY NIC.NORDU.NET\n"
	";\n"
	".                        3600000      NS    I.ROOT-SERVERS.NET.\n"
	"I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17\n"
	"I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fe::53\n"
	"; \n"
	"; OPERATED BY VERISIGN, INC.\n"
	";\n"
	".                        3600000      NS    J.ROOT-SERVERS.NET.\n"
	"J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30\n"
	"J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:c27::2:30\n"
	"; \n"
	"; OPERATED BY RIPE NCC\n"
	";\n"
	".                        3600000      NS    K.ROOT-SERVERS.NET.\n"
	"K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129\n"
	"K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fd::1\n"
	"; \n"
	"; OPERATED BY ICANN\n"
	";\n"
	".                        3600000      NS    L.ROOT-SERVERS.NET.\n"
	"L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42\n"
	"L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42\n"
	"; \n"
	"; OPERATED BY WIDE\n"
	";\n"
	".                        3600000      NS    M.ROOT-SERVERS.NET.\n"
	"M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33\n"
	"M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35\n"
	"; End of file"
	"\n"; /* ensure posix endlines, original doc doesn't have it */

static isc_result_t
in_rootns(dns_rdataset_t *rootns, dns_name_t *name) {
	dns_rdata_ns_t ns;

	if (!dns_rdataset_isassociated(rootns)) {
		return ISC_R_NOTFOUND;
	}

	DNS_RDATASET_FOREACH(rootns) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(rootns, &rdata);
		RETERR(dns_rdata_tostruct(&rdata, &ns, NULL));
		if (dns_name_compare(name, &ns.name) == 0) {
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

static isc_result_t
check_node(dns_rdataset_t *rootns, dns_name_t *name,
	   dns_rdatasetiter_t *rdsiter) {
	DNS_RDATASETITER_FOREACH(rdsiter) {
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
	CHECK(dns_db_createiterator(db, 0, &dbiter));
	DNS_DBITERATOR_FOREACH(dbiter) {
		CHECK(dns_dbiterator_current(dbiter, &node, name));
		CHECK(dns_db_allrdatasets(db, node, NULL, 0, now, &rdsiter));
		CHECK(check_node(&rootns, name, rdsiter));
		dns_rdatasetiter_destroy(&rdsiter);
		dns_db_detachnode(&node);
	}

cleanup:
	dns_rdataset_cleanup(&rootns);
	if (rdsiter != NULL) {
		dns_rdatasetiter_destroy(&rdsiter);
	}
	if (node != NULL) {
		dns_db_detachnode(&node);
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

	CHECK(dns_db_create(mctx, ZONEDB_DEFAULT, dns_rootname, dns_dbtype_zone,
			    rdclass, 0, NULL, &db));

	len = strlen(root_ns);
	isc_buffer_init(&source, root_ns, len);
	isc_buffer_add(&source, len);

	dns_rdatacallbacks_init(&callbacks);
	CHECK(dns_db_beginload(db, &callbacks));
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
	if (result != DNS_R_SEENINCLUDE) {
		CHECK(result);
	}
	if (check_hints(db) != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_WARNING, "extra data in root hints '%s'",
			      (filename != NULL) ? filename : "<BUILT-IN>");
	}
	*target = db;
	return ISC_R_SUCCESS;

cleanup:
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

const char *
dns_rootns_gethints(void) {
	return root_ns;
}
