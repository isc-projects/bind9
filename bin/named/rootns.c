/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <config.h>

#include <stddef.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/types.h>

#include <dns/types.h>
#include <dns/db.h>
#include <dns/master.h>

#include <named/globals.h>
#include <named/rootns.h>

static char root_ns[] = "
;
; Internet Root Nameservers
;
; Thu Sep 23 17:57:37 PDT 1999
;
$TTL 518400
.                       518400  IN      NS      F.ROOT-SERVERS.NET.
.                       518400  IN      NS      B.ROOT-SERVERS.NET.
.                       518400  IN      NS      J.ROOT-SERVERS.NET.
.                       518400  IN      NS      K.ROOT-SERVERS.NET.
.                       518400  IN      NS      L.ROOT-SERVERS.NET.
.                       518400  IN      NS      M.ROOT-SERVERS.NET.
.                       518400  IN      NS      I.ROOT-SERVERS.NET.
.                       518400  IN      NS      E.ROOT-SERVERS.NET.
.                       518400  IN      NS      D.ROOT-SERVERS.NET.
.                       518400  IN      NS      A.ROOT-SERVERS.NET.
.                       518400  IN      NS      H.ROOT-SERVERS.NET.
.                       518400  IN      NS      C.ROOT-SERVERS.NET.
.                       518400  IN      NS      G.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.     3600000 IN      A       192.5.5.241
B.ROOT-SERVERS.NET.     3600000 IN      A       128.9.0.107
J.ROOT-SERVERS.NET.     3600000 IN      A       198.41.0.10
K.ROOT-SERVERS.NET.     3600000 IN      A       193.0.14.129
L.ROOT-SERVERS.NET.     3600000 IN      A       198.32.64.12
M.ROOT-SERVERS.NET.     3600000 IN      A       202.12.27.33
I.ROOT-SERVERS.NET.     3600000 IN      A       192.36.148.17
E.ROOT-SERVERS.NET.     3600000 IN      A       192.203.230.10
D.ROOT-SERVERS.NET.     3600000 IN      A       128.8.10.90
A.ROOT-SERVERS.NET.     3600000 IN      A       198.41.0.4
H.ROOT-SERVERS.NET.     3600000 IN      A       128.63.2.53
C.ROOT-SERVERS.NET.     3600000 IN      A       192.33.4.12
G.ROOT-SERVERS.NET.     3600000 IN      A       192.112.36.4
";

isc_result_t
ns_rootns_init(void) {
	dns_result_t result, eresult;
	isc_buffer_t source;
	size_t len;
	int soacount, nscount;
	dns_rdatacallbacks_t callbacks;

	REQUIRE(ns_g_rootns == NULL);

	result = dns_db_create(ns_g_mctx, "rbt", dns_rootname, ISC_FALSE,
			       dns_rdataclass_in, 0, NULL, &ns_g_rootns);
	if (result != ISC_R_SUCCESS)
		return (result);

	dns_rdatacallbacks_init(&callbacks);

	len = strlen(root_ns);
	isc_buffer_init(&source, root_ns, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);

	result = dns_db_beginload(ns_g_rootns, &callbacks.add,
				  &callbacks.add_private);
	if (result != ISC_R_SUCCESS)
		return (result);
	result = dns_master_loadbuffer(&source, &ns_g_rootns->origin,
				       &ns_g_rootns->origin,
				       ns_g_rootns->rdclass, ISC_FALSE,
				       &soacount, &nscount, &callbacks,
				       ns_g_rootns->mctx);
	eresult = dns_db_endload(ns_g_rootns, &callbacks.add_private);
	if (result == ISC_R_SUCCESS)
		result = eresult;
	if (result != ISC_R_SUCCESS)
		goto db_detach;

	return (DNS_R_SUCCESS);

 db_detach:
	dns_db_detach(&ns_g_rootns);

	return (result);
}

void
ns_rootns_destroy(void) {
	REQUIRE(ns_g_rootns != NULL);
	dns_db_detach(&ns_g_rootns);
}
