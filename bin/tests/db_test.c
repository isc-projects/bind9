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
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/compress.h>
#include <dns/db.h>

int
main(int argc, char *argv[]) {
	isc_mem_t *mctx = NULL;
	dns_db_t *db;
	dns_dbnode_t *node;
	dns_result_t result;
	dns_name_t name, *origin;
	dns_offsets_t offsets;
	isc_buffer_t source, target;
	size_t len;
	char s[1000];
	char b[256];

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	db = NULL;
	result = dns_db_create(mctx, "rbt", ISC_FALSE, 1, 0, NULL,
			       &db);
	RUNTIME_CHECK(result == DNS_R_SUCCESS);
	
	origin = dns_rootname;
	dns_name_init(&name, offsets);
	while (gets(s) != NULL) {
		len = strlen(s);
		isc_buffer_init(&source, s, len, ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&source, len);
		isc_buffer_init(&target, b, 255, ISC_BUFFERTYPE_BINARY);
		result = dns_name_fromtext(&name, &source, origin, ISC_FALSE,
					   &target);
		RUNTIME_CHECK(result == DNS_R_SUCCESS);
		node = NULL;
		result = dns_db_findnode(db, &name, ISC_TRUE, &node);
		RUNTIME_CHECK(result == DNS_R_SUCCESS);
		/* dns_db_detachnode(db, &node); */
	}

	dns_db_detach(&db);

	isc_mem_stats(mctx, stdout);

	return (0);
}
