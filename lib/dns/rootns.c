/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: rootns.c,v 1.18 2001/01/09 21:51:30 bwelling Exp $ */

#include <config.h>

#include <isc/buffer.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/master.h>
#include <dns/result.h>
#include <dns/rootns.h>

static char root_ns[] =
";\n"
"; Internet Root Nameservers\n"
";\n"
"; Thu Sep 23 17:57:37 PDT 1999\n"
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
"B.ROOT-SERVERS.NET.     3600000 IN      A       128.9.0.107\n"
"C.ROOT-SERVERS.NET.     3600000 IN      A       192.33.4.12\n"
"D.ROOT-SERVERS.NET.     3600000 IN      A       128.8.10.90\n"
"E.ROOT-SERVERS.NET.     3600000 IN      A       192.203.230.10\n"
"F.ROOT-SERVERS.NET.     3600000 IN      A       192.5.5.241\n"
"G.ROOT-SERVERS.NET.     3600000 IN      A       192.112.36.4\n"
"H.ROOT-SERVERS.NET.     3600000 IN      A       128.63.2.53\n"
"I.ROOT-SERVERS.NET.     3600000 IN      A       192.36.148.17\n"
"J.ROOT-SERVERS.NET.     3600000 IN      A       198.41.0.10\n"
"K.ROOT-SERVERS.NET.     3600000 IN      A       193.0.14.129\n"
"L.ROOT-SERVERS.NET.     3600000 IN      A       198.32.64.12\n"
"M.ROOT-SERVERS.NET.     3600000 IN      A       202.12.27.33\n";

isc_result_t
dns_rootns_create(isc_mem_t *mctx, dns_rdataclass_t rdclass,
		  const char *filename, dns_db_t **target)
{
	isc_result_t result, eresult;
	isc_buffer_t source;
	size_t len;
	dns_rdatacallbacks_t callbacks;
	dns_db_t *db = NULL;

	REQUIRE(target != NULL && *target == NULL);

	result = dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			       rdclass, 0, NULL, &db);
	if (result != ISC_R_SUCCESS)
		return (result);

	dns_rdatacallbacks_init(&callbacks);

	len = strlen(root_ns);
	isc_buffer_init(&source, root_ns, len);
	isc_buffer_add(&source, len);

	result = dns_db_beginload(db, &callbacks.add,
				  &callbacks.add_private);
	if (result != ISC_R_SUCCESS)
		return (result);
	if (filename != NULL) {
		/*
		 * Load the hints from the specified filename.
		 */
		result = dns_master_loadfile(filename, &db->origin,
					     &db->origin, db->rdclass, 0,
					     &callbacks, db->mctx);
	} else if (rdclass == dns_rdataclass_in) {
		/*
		 * Default to using the Internet root servers.
		 */
		result = dns_master_loadbuffer(&source, &db->origin,
					       &db->origin, db->rdclass, 0,
					       &callbacks, db->mctx);
	} else
		result = ISC_R_NOTFOUND;
	eresult = dns_db_endload(db, &callbacks.add_private);
	if (result == ISC_R_SUCCESS || result == DNS_R_SEENINCLUDE)
		result = eresult;
	if (result != ISC_R_SUCCESS && result != DNS_R_SEENINCLUDE)
		goto db_detach;

	*target = db;
	return (ISC_R_SUCCESS);

 db_detach:
	dns_db_detach(&db);

	return (result);
}
