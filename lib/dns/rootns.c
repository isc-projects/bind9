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
	";       last update:     July 22, 2026\n"
	";       related version of root zone:     2026072201\n"
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

isc_result_t
dns_rootns_filldelegdb(isc_mem_t *mctx, const char *filename,
		       dns_delegdb_t *db) {
	dns_rdatacallbacks_t callbacks;
	isc_result_t result;

	dns_rdatacallbacks_init(&callbacks);
	dns_delegdb_rootns_prepare(db, &callbacks);

	if (filename != NULL) {
		result = dns_master_loadfile(
			filename, (dns_name_t *)dns_rootname,
			(dns_name_t *)dns_rootname, dns_rdataclass_in,
			DNS_MASTER_HINT, 0, &callbacks, NULL, NULL, mctx,
			dns_masterformat_text, 0);
	} else {
		isc_buffer_t source;
		size_t len = strlen(root_ns);

		isc_buffer_init(&source, root_ns, len);
		isc_buffer_add(&source, len);
		result = dns_master_loadbuffer(
			&source, (dns_name_t *)dns_rootname,
			(dns_name_t *)dns_rootname, dns_rdataclass_in,
			DNS_MASTER_HINT, &callbacks, mctx);
	}

	/*
	 * DNS_R_SEENINCLUDE only signals the file used $INCLUDE; the load
	 * itself succeeded.
	 */
	if (result == DNS_R_SEENINCLUDE) {
		result = ISC_R_SUCCESS;
	}

	if (result == ISC_R_SUCCESS) {
		result = dns_delegdb_rootns_commit(&callbacks);
	}
	dns_delegdb_rootns_cleanup(&callbacks);

	if (result != ISC_R_SUCCESS) {
		const char *from = filename != NULL ? filename : "<builtin>";

		isc_log_write(NAMED_LOGCATEGORY_GENERAL, DNS_LOGMODULE_HINTS,
			      ISC_LOG_ERROR,
			      "could not configure root hints from '%s': %s",
			      from, isc_result_totext(result));
	}

	return result;
}

const char *
dns_rootns_gethints(void) {
	return root_ns;
}
